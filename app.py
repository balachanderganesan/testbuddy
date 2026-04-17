#!/usr/bin/env python3
"""
VeloCloud Edge/Gateway Memory Monitor
======================================
Discovers VMs inside KVM hypervisors via iptables DNAT rules:
  port 2xxx → Edge   (process: edged)
  port 4xxx → Gateway (process: gwd)

VMs are accessed via:  ssh root@<hypervisor_ip> -p <console_port>
(The NAT rule on the hypervisor forwards console_port → VM:22)

Polls /proc/meminfo, CPU%, process uptime, core dumps, and HA peer
metrics from every discovered VM, stores in SQLite, and exposes a
REST API consumed by the dashboard frontend.
"""

import json
import re
import sqlite3
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from contextlib import contextmanager
from pathlib import Path

import paramiko
from flask import Flask, jsonify, render_template, request, Response

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent
SERVERS_JSON = BASE_DIR / "servers.json"
DB_PATH      = str(BASE_DIR / "vcmem.db")

POLL_INTERVAL        = 300    # seconds between polls (5 min)
REDISCOVER_INTERVAL  = 600    # seconds between iptables re-scans
SSH_TIMEOUT          = 15     # SSH connect + exec timeout (seconds)
HA_SSH_TIMEOUT       = 8      # timeout for each SSH hop to 169.254.2.2
DB_RETENTION_HOURS   = 168    # keep 7 days of samples
POLL_WORKERS         = 50     # max concurrent SSH sessions during a poll run

DEVICE_USER = "root"
DEVICE_PASS = "velocloud"

SC_SERVERS_JSON = BASE_DIR / "sc_servers.json"

TOPOLOGIES = {
    "chennai": {
        "label": "Chennai Solutions Topology",
        "servers_json": SERVERS_JSON,
        "server_names": None,           # None = use all servers in the file
    },
    "sc_tb1": {
        "label": "TB1",
        "servers_json": SC_SERVERS_JSON,
        "server_names": {"SRV1","SRV2","SRV3","SRV4","SRV5"},
    },
    "sc_tb2": {
        "label": "TB2",
        "servers_json": SC_SERVERS_JSON,
        "server_names": {"SRV6","SRV7","SRV8","SRV9","SRV10"},
    },
    "sc_tb3": {
        "label": "TB3",
        "servers_json": SC_SERVERS_JSON,
        "server_names": {"SRV14","SRV15","SRV16","SRV17","SRV18"},
    },
    "sc_tb4": {
        "label": "TB4",
        "servers_json": SC_SERVERS_JSON,
        "server_names": {"SRV19","SRV20","SRV21","SRV22","SRV23"},
    },
    "sc_tb5": {
        "label": "TB5",
        "servers_json": SC_SERVERS_JSON,
        "server_names": {"SRV24","SRV25","SRV26","SRV27","SRV28"},
    },
    "standard_testbeds": {
        "label": "Standard Testbeds",
        "servers_json": None,       # dynamic — bastion hosts added via /api/bastion/add
        "server_names": None,
    },
}

# Anomaly thresholds
WARN_FREE_PCT   = 15.0   # warn if free < 15%
CRIT_FREE_PCT   =  8.0   # critical if free < 8%
TREND_SAMPLES   = 20     # samples used for slope calculation
WARN_SLOPE_KB_H = -200   # warn  if trending down > 200 KB/h
CRIT_SLOPE_KB_H = -800   # crit  if trending down > 800 KB/h

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)
logging.getLogger("paramiko.transport").setLevel(logging.WARNING)  # suppress non-SSH banner noise

# Prevents poll and rediscover from running concurrently (they write the same rows).
_op_lock = threading.Lock()
_op_name = ""   # human-readable name of whoever holds the lock

app = Flask(__name__)

# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hypervisors (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                name      TEXT    NOT NULL,
                ip        TEXT    NOT NULL UNIQUE,
                port      INTEGER DEFAULT 22,
                username  TEXT,
                password  TEXT,
                last_seen TEXT,
                reachable INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS devices (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                hypervisor_id  INTEGER NOT NULL,
                device_type    TEXT    NOT NULL,
                ip             TEXT    NOT NULL,
                console_port   INTEGER,
                vm_name        TEXT,
                last_seen      TEXT,
                reachable      INTEGER DEFAULT 0,
                UNIQUE(ip, hypervisor_id),
                FOREIGN KEY(hypervisor_id) REFERENCES hypervisors(id)
            );

            CREATE TABLE IF NOT EXISTS memory_samples (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id             INTEGER NOT NULL,
                ts                    TEXT    NOT NULL,
                pid                   INTEGER,
                mem_total_kb          INTEGER,
                mem_free_kb           INTEGER,
                mem_available_kb      INTEGER,
                mem_buffers_kb        INTEGER,
                mem_cached_kb         INTEGER,
                cpu_pct               REAL,
                process_uptime_sec    INTEGER,
                core_count            INTEGER,
                ha_reachable          INTEGER DEFAULT 0,
                ha_pid                INTEGER,
                ha_mem_total_kb       INTEGER,
                ha_mem_free_kb        INTEGER,
                ha_mem_available_kb   INTEGER,
                ha_cpu_pct            REAL,
                ha_process_uptime_sec INTEGER,
                ha_core_count         INTEGER,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            CREATE INDEX IF NOT EXISTS idx_ms_dev_ts
                ON memory_samples(device_id, ts DESC);

            CREATE TABLE IF NOT EXISTS recording_sessions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                topology_id  TEXT    NOT NULL,
                label        TEXT    NOT NULL DEFAULT '',
                started_at   TEXT    NOT NULL,
                stopped_at   TEXT,
                status       TEXT    NOT NULL DEFAULT 'recording',
                sample_count INTEGER DEFAULT 0,
                device_count INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_rs_topology
                ON recording_sessions(topology_id, started_at DESC);

            CREATE TABLE IF NOT EXISTS device_checks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id    INTEGER NOT NULL,
                ts           TEXT    NOT NULL,
                check_type   TEXT    NOT NULL,
                result_json  TEXT    NOT NULL,
                alert_level  TEXT    DEFAULT 'ok',
                alert_detail TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            CREATE INDEX IF NOT EXISTS idx_dc_dev_type_ts
                ON device_checks(device_id, check_type, ts DESC);
        """)
        # Migrate existing DB: add new columns if absent
        _add_col_if_missing(conn, "recording_sessions", "poll_interval_sec INTEGER DEFAULT 300")
        _add_col_if_missing(conn, "recording_sessions", "last_polled_at TEXT")
        _add_col_if_missing(conn, "recording_sessions", "hypervisor_id INTEGER")
        _add_col_if_missing(conn, "devices", "vm_name TEXT")
        _add_col_if_missing(conn, "devices", "core_files TEXT")
        _add_col_if_missing(conn, "devices", "ha_core_files TEXT")
        _add_col_if_missing(conn, "devices", "vm_port INTEGER DEFAULT 22")
        _add_col_if_missing(conn, "devices", "prev_route_total INTEGER")
        _add_col_if_missing(conn, "devices", "prev_peer_count INTEGER")
        _add_col_if_missing(conn, "devices", "prev_total_paths INTEGER")
        _add_col_if_missing(conn, "devices", "prev_stale_pi_count INTEGER")
        _add_col_if_missing(conn, "devices", "prev_stale_td_count INTEGER")
        _add_col_if_missing(conn, "hypervisors", "topology_id TEXT DEFAULT 'chennai'")
        _add_col_if_missing(conn, "device_checks", "dismissed INTEGER DEFAULT 0")
        _add_col_if_missing(conn, "memory_samples", "core_files_json TEXT")
        _add_col_if_missing(conn, "memory_samples", "ha_core_files_json TEXT")
        for col in [
            "cpu_pct REAL", "process_uptime_sec INTEGER", "core_count INTEGER",
            "ha_reachable INTEGER", "ha_pid INTEGER",
            "ha_mem_total_kb INTEGER", "ha_mem_free_kb INTEGER",
            "ha_mem_available_kb INTEGER", "ha_cpu_pct REAL",
            "ha_process_uptime_sec INTEGER", "ha_core_count INTEGER",
        ]:
            _add_col_if_missing(conn, "memory_samples", col)


def _add_col_if_missing(conn, table, col_def):
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
    except sqlite3.OperationalError:
        pass  # column already exists


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


CHECKS_RETENTION_HOURS = 120  # 5 days for diagnostic check alerts


def purge_old_samples():
    cutoff = (datetime.utcnow() - timedelta(hours=DB_RETENTION_HOURS)).isoformat()
    checks_cutoff = (datetime.utcnow() - timedelta(hours=CHECKS_RETENTION_HOURS)).isoformat()
    with get_db() as conn:
        conn.execute("DELETE FROM memory_samples WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM device_checks WHERE ts < ?", (checks_cutoff,))
    log.info("Old samples purged")


# ── SSH helpers ───────────────────────────────────────────────────────────────

def ssh_connect(host, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            hostname=host, port=int(port),
            username=username, password=password,
            timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False,
            banner_timeout=SSH_TIMEOUT,
        )
        return ssh
    except paramiko.AuthenticationException:
        pass
    # Fallback: keyboard-interactive auth (Ubuntu/PAM servers often reject the
    # 'password' SSH method but accept 'keyboard-interactive' with the same password).
    t = paramiko.Transport((host, int(port)))
    t.start_client(timeout=SSH_TIMEOUT)
    t.auth_interactive_dumb(
        username,
        lambda title, instructions, prompts: [password] * len(prompts),
    )
    ssh._transport = t
    return ssh


def ssh_run(ssh, cmd, timeout=None):
    t = timeout or SSH_TIMEOUT
    _, stdout, _ = ssh.exec_command(cmd, timeout=t)
    return stdout.read().decode("utf-8", errors="replace").strip()


# ── Discovery ─────────────────────────────────────────────────────────────────

_DNAT_RE = re.compile(
    r"-A CONSOLE\b.*?--dport\s+(\d+).*?--to-destination\s+([\d.]+):(\d+)"
)


def _detect_vm_type(hv_ip, console_port):
    """
    SSH into a VM via the hypervisor NAT and detect its type by checking
    which VeloCloud process is running (edged → edge, gwd → gateway).
    Returns 'edge', 'gateway', or None if neither process is found.
    """
    try:
        ssh = ssh_connect(hv_ip, console_port, DEVICE_USER, DEVICE_PASS)
        out = ssh_run(
            ssh,
            "pgrep -o edged >/dev/null 2>&1 && echo edge; "
            "pgrep -o gwd   >/dev/null 2>&1 && echo gateway",
            timeout=SSH_TIMEOUT,
        )
        ssh.close()
        lines = out.splitlines()
        if "edge"    in lines: return "edge"
        if "gateway" in lines: return "gateway"
    except Exception:
        pass
    return None


def discover_on_hypervisor(hv, known_types):
    """
    Discover VeloCloud VMs on a hypervisor.

    known_types: dict of {vm_ip: device_type} already stored in the DB for
                 this hypervisor.  VMs in this dict skip the SSH type-probe —
                 their type is stable (an edge stays an edge).  Only genuinely
                 new VM IPs are probed via SSH to detect edge vs gateway.
    """
    found, ok = [], False
    try:
        ssh = ssh_connect(hv["ip"], hv["port"], hv["username"], hv["password"])
        out = ssh_run(ssh, "iptables -t nat -S 2>/dev/null")
        ssh.close()

        all_rules = [
            (int(m.group(1)), m.group(2), int(m.group(3)))
            for m in _DNAT_RE.finditer(out)
        ]

        lock    = threading.Lock()
        vm_seen = set()

        def _probe(hv_port, vm_ip, vm_port):
            with lock:
                if vm_ip in vm_seen:
                    return
                # Already known — reuse stored type, no SSH needed.
                if vm_ip in known_types:
                    vm_seen.add(vm_ip)
                    found.append({
                        "device_type":  known_types[vm_ip],
                        "ip":           vm_ip,
                        "console_port": hv_port,
                        "vm_port":      vm_port,
                    })
                    return
                # Claim this IP before releasing the lock so other threads
                # for the same VM (multiple DNAT rules) don't launch
                # redundant SSH probes.
                vm_seen.add(vm_ip)
            # New VM — probe via SSH to detect type.
            dtype = _detect_vm_type(hv["ip"], hv_port)
            if dtype:
                with lock:
                    found.append({
                        "device_type":  dtype,
                        "ip":           vm_ip,
                        "console_port": hv_port,
                        "vm_port":      vm_port,
                    })

        probe_threads = [
            threading.Thread(target=_probe, args=rule, daemon=True)
            for rule in all_rules
        ]
        for t in probe_threads: t.start()
        for t in probe_threads: t.join(timeout=SSH_TIMEOUT + 5)

        new_count = sum(1 for ip in vm_seen if ip not in known_types)
        log.info(f"  [{hv['name']}] {len(found)} VMs ({new_count} new)")
        ok = True
    except Exception as exc:
        log.warning(f"  [{hv['name']}] discovery failed: {exc}")
    return found, ok


def run_discovery(topology_id="chennai"):
    global _op_name
    if not _op_lock.acquire(blocking=False):
        log.info(f"Discovery [{topology_id}] skipped — {_op_name} already running")
        return
    _op_name = f"discovery[{topology_id}]"
    try:
        _run_discovery(topology_id)
    finally:
        _op_lock.release()
        _op_name = ""


def _run_discovery(topology_id):
    topo = TOPOLOGIES.get(topology_id)
    if not topo:
        log.error(f"Unknown topology: {topology_id}")
        return
    log.info(f"=== Discovery starting [{topology_id}] ===")

    # For topologies with a servers_json, sync hypervisor list from file.
    # For dynamic topologies (servers_json=None), use whatever is already in DB.
    if topo["servers_json"] is not None:
        try:
            servers = json.loads(topo["servers_json"].read_text())
        except Exception as exc:
            log.error(f"Cannot read servers.json for {topology_id}: {exc}")
            return

        if topo["server_names"]:
            servers = [s for s in servers if s["name"] in topo["server_names"]]

        with get_db() as conn:
            for srv in servers:
                ip   = srv["connections"]["ip"]
                name = srv["name"]
                port = srv["connections"].get("port", 22)
                user = srv["credentials"]["username"]
                pw   = srv["credentials"]["password"]
                conn.execute(
                    "INSERT OR IGNORE INTO hypervisors(name,ip,port,username,password,topology_id) VALUES(?,?,?,?,?,?)",
                    (name, ip, port, user, pw, topology_id))
                conn.execute(
                    "UPDATE hypervisors SET name=?,port=?,username=?,password=?,topology_id=? WHERE ip=?",
                    (name, port, user, pw, topology_id, ip))

    with get_db() as conn:
        hvs = [dict(r) for r in conn.execute(
            "SELECT * FROM hypervisors WHERE topology_id=?", (topology_id,)
        ).fetchall()]
        # Load already-known VM types keyed by hypervisor_id so probing is
        # skipped for existing VMs (type is stable — edge stays edge).
        known = {}
        for row in conn.execute(
            "SELECT hypervisor_id, ip, device_type FROM devices "
            "WHERE hypervisor_id IN (SELECT id FROM hypervisors WHERE topology_id=?)",
            (topology_id,)
        ).fetchall():
            known.setdefault(row["hypervisor_id"], {})[row["ip"]] = row["device_type"]

    results, lock = {}, threading.Lock()

    def _disc(hv):
        devs, ok = discover_on_hypervisor(hv, known.get(hv["id"], {}))
        with lock:
            results[hv["id"]] = (hv, devs, ok)

    threads = [threading.Thread(target=_disc, args=(hv,), daemon=True) for hv in hvs]
    for t in threads: t.start()
    for t in threads: t.join(timeout=SSH_TIMEOUT + 5)

    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        for hv_id, (hv, devs, ok) in results.items():
            conn.execute(
                "UPDATE hypervisors SET last_seen=?,reachable=? WHERE id=?",
                (now, 1 if ok else 0, hv_id))
            if not ok:
                continue
            found_ips = {d["ip"] for d in devs}
            for d in devs:
                vm_port = d.get("vm_port", 22)
                conn.execute(
                    "INSERT OR IGNORE INTO devices"
                    "(hypervisor_id,device_type,ip,console_port,vm_port,last_seen) VALUES(?,?,?,?,?,?)",
                    (hv_id, d["device_type"], d["ip"], d["console_port"], vm_port, now))
                conn.execute(
                    "UPDATE devices SET device_type=?,console_port=?,vm_port=?,last_seen=? WHERE ip=? AND hypervisor_id=?",
                    (d["device_type"], d["console_port"], vm_port, now, d["ip"], hv_id))
            # Remove devices that disappeared from this hypervisor.
            # Skip deletion when found_ips is empty: iptables may be
            # transiently flushed or all SSH probes may have timed out,
            # which would incorrectly wipe all known devices.
            if found_ips:
                placeholders = ",".join("?" * len(found_ips))
                conn.execute(
                    f"DELETE FROM devices WHERE hypervisor_id=? AND ip NOT IN ({placeholders})",
                    (hv_id, *found_ips))
            else:
                log.warning(f"  [{hv['name']}] reachable but no VMs found — skipping stale cleanup")

    log.info(f"=== Discovery complete [{topology_id}] ===")


# ── Metric collection ─────────────────────────────────────────────────────────

_MEMINFO_RE = re.compile(r"^(\w+):\s+(\d+)", re.MULTILINE)


def _collect_cmd(proc):
    """
    Shell command that collects all metrics in one exec_command round-trip.
    Output uses VCMEM_ prefixed markers for unambiguous parsing.
    CPU% via ps; process uptime via /proc/pid/stat (works on BusyBox too).
    Core files: outputs VCMEM_COREFILE:name|mtime per file, then VCMEM_CORES:count.
    """
    return (
        f"PID=$(pgrep -o {proc} 2>/dev/null); "
        "_EN=$(python -c \"import json; d=json.load(open('/opt/vc/.edge.info')); print(d.get('edgeInfo',{}).get('name',''))\" 2>/dev/null); "
        "[ -z \"$_EN\" ] && _EN=$(hostname 2>/dev/null); "
        "printf 'VCMEM_HOST:%s\\n' \"$_EN\"; "
        "printf 'VCMEM_PID:%s\\n' \"$PID\"; "
        "cat /proc/meminfo 2>/dev/null; "
        "if [ -n \"$PID\" ]; then "
        "  BOOT=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0); "
        "  CLK=$(getconf CLK_TCK 2>/dev/null || echo 100); "
        "  ST=$(cut -d' ' -f22 /proc/$PID/stat 2>/dev/null || echo 0); "
        "  EL=$(( BOOT - ST / CLK )); "
        "  CPU=$(ps -p $PID -o pcpu --no-headers 2>/dev/null | tr -d ' ' | head -1); "
        "  [ -z \"$CPU\" ] && CPU=0; "
        "  printf 'VCMEM_PS:%s,%d\\n' \"$CPU\" \"$EL\"; "
        "else printf 'VCMEM_PS:0,0\\n'; fi; "
        "_CF=$(find /velocloud/core /velocloud/kcore -maxdepth 2 -type f"
        " \\( -name '*.tgz' -o -name '*.gz' \\) 2>/dev/null); "
        "_CNT=0; "
        "for _f in $_CF; do "
        "  _CNT=$((_CNT+1)); "
        "  _TS=$(stat -c %Y $_f 2>/dev/null || echo 0); "
        "  printf 'VCMEM_COREFILE:%s|%s\\n' $(basename $_f) $_TS; "
        "  _UNIQ=$(basename $_f | tr '.' '\\n' | grep '^[0-9]\\{8,10\\}$' | head -1); "
        "  if [ -n \"$_UNIQ\" ]; then "
        "    _DIAGF=/velocloud/${_UNIQ}_core.zip; "
        "    if [ ! -f \"$_DIAGF\" ]; then "
        "      (cd /velocloud && /opt/vc/bin/gendiag.py -o ${_UNIQ}_core.zip > /dev/null 2>&1 &); "
        "    fi; "
        "  fi; "
        "done; "
        "printf 'VCMEM_CORES:%d\\n' $_CNT"
    )


def _parse_metrics(raw):
    """Parse output from _collect_cmd."""
    r = dict(hostname="", pid=None, cpu_pct=None, process_uptime_sec=None, core_count=0,
             core_files=[], mem_total=0, mem_free=0, mem_available=0, mem_buffers=0, mem_cached=0)
    for line in raw.splitlines():
        if line.startswith("VCMEM_HOST:"):
            r["hostname"] = line[11:].strip()
        elif line.startswith("VCMEM_PID:"):
            s = line[10:].strip()
            if s.isdigit():
                r["pid"] = int(s)
        elif line.startswith("VCMEM_PS:"):
            parts = line[9:].strip().split(",")
            try: r["cpu_pct"] = float(parts[0])
            except: pass
            try: r["process_uptime_sec"] = int(parts[1])
            except: pass
        elif line.startswith("VCMEM_CORES:"):
            try: r["core_count"] = int(line[12:].strip())
            except: pass
        elif line.startswith("VCMEM_COREFILE:"):
            parts = line[15:].strip().split("|", 1)
            name = parts[0] if parts else ""
            ts = 0
            if len(parts) > 1:
                try: ts = int(parts[1])
                except: pass
            if name:
                r["core_files"].append({"name": name, "ts": ts})
    mem = dict(_MEMINFO_RE.findall(raw))
    r["mem_total"]     = int(mem.get("MemTotal",    0))
    r["mem_free"]      = int(mem.get("MemFree",      0))
    r["mem_available"] = int(mem.get("MemAvailable", 0))
    r["mem_buffers"]   = int(mem.get("Buffers",      0))
    r["mem_cached"]    = int(mem.get("Cached",       0))
    return r


def _collect_ha_metrics(ssh):
    """
    From an active edge's SSH session, try to reach the HA standby at 169.254.2.2.
    Returns parsed metrics dict or None if standby is unreachable.
    """
    HA_IP  = "169.254.2.2"
    SSH_OPT = "-o StrictHostKeyChecking=no -o LogLevel=ERROR"

    # Combined command to run on the standby - uses same VCMEM_ markers.
    # IMPORTANT: inner must contain NO single quotes because it is wrapped in
    # single quotes when passed to ssh on the active edge:  ssh ... '{inner}'
    # All printf format strings use double quotes instead.
    inner = (
        "PID=$(pgrep -o edged 2>/dev/null); "
        "printf \"VCMEM_HOST:%s\\n\" \"$(hostname)\"; "
        "printf \"VCMEM_PID:%s\\n\" \"$PID\"; "
        "cat /proc/meminfo; "
        "if [ -n \"$PID\" ]; then "
        "  BOOT=$(cut -d. -f1 /proc/uptime || echo 0); "
        "  CLK=$(getconf CLK_TCK 2>/dev/null || echo 100); "
        "  ST=$(cut -d\" \" -f22 /proc/$PID/stat 2>/dev/null || echo 0); "
        "  EL=$(( BOOT - ST / CLK )); "
        "  CPU=$(ps -p $PID -o pcpu --no-headers 2>/dev/null | tr -d \" \" | head -1); "
        "  [ -z \"$CPU\" ] && CPU=0; "
        "  printf \"VCMEM_PS:%s,%d\\n\" \"$CPU\" \"$EL\"; "
        "else printf \"VCMEM_PS:0,0\\n\"; fi; "
        "_CF=$(find /velocloud/core /velocloud/kcore -maxdepth 2 -type f"
        " \\( -name *.tgz -o -name *.gz \\) 2>/dev/null); "
        "_CNT=0; "
        "for _f in $_CF; do "
        "  _CNT=$((_CNT+1)); "
        "  _TS=$(stat -c %Y $_f 2>/dev/null || echo 0); "
        "  printf \"VCMEM_COREFILE:%s|%s\\n\" $(basename $_f) $_TS; "
        "  _UNIQ=$(basename $_f | tr . \"\\n\" | grep \"^[0-9]\\{8,10\\}$\" | head -1); "
        "  if [ -n \"$_UNIQ\" ]; then "
        "    _DIAGF=/velocloud/${_UNIQ}_core.zip; "
        "    if [ ! -f \"$_DIAGF\" ]; then "
        "      (cd /velocloud && /opt/vc/bin/gendiag.py -o ${_UNIQ}_core.zip > /dev/null 2>&1 &); "
        "    fi; "
        "  fi; "
        "done; "
        "printf \"VCMEM_CORES:%d\\n\" $_CNT"
    )

    # Try key-based auth first (HA peers often have mutual trust)
    raw = ssh_run(
        ssh,
        f"ssh {SSH_OPT} -o BatchMode=yes -o ConnectTimeout={HA_SSH_TIMEOUT} "
        f"root@{HA_IP} '{inner}' 2>/dev/null",
        timeout=HA_SSH_TIMEOUT + 3,
    )
    if not raw or "MemTotal" not in raw:
        # Fall back: try sshpass with the standard device password
        raw = ssh_run(
            ssh,
            f"sshpass -p {DEVICE_PASS} ssh {SSH_OPT} -o ConnectTimeout={HA_SSH_TIMEOUT} "
            f"root@{HA_IP} '{inner}' 2>/dev/null",
            timeout=HA_SSH_TIMEOUT + 3,
        )

    if not raw or "MemTotal" not in raw:
        return None

    m = _parse_metrics(raw)
    return m if m["mem_total"] else None


# ── Diagnostic checks ────────────────────────────────────────────────────────

CHECKS_SSH_TIMEOUT = 120  # headroom for debug.py --timeout 60 commands


def _checks_cmd():
    """
    Shell command that runs all diagnostic checks in a single SSH exec.
    Each section is delimited by VCCHECK_<TYPE>_BEGIN / VCCHECK_<TYPE>_END.
    The --psummary output is shared by tunnel and path checks (run once).
    """
    return (
        "printf 'VCCHECK_PSUMMARY_BEGIN\\n'; "
        "/opt/vc/bin/debug.py -v --psummary 2>/dev/null || echo '[]'; "
        "printf '\\nVCCHECK_PSUMMARY_END\\n'; "

        "printf 'VCCHECK_ROUTE_BEGIN\\n'; "
        "/opt/vc/bin/debug.py --timeout 60 --rsummary 2>/dev/null || echo '[]'; "
        "printf '\\nVCCHECK_ROUTE_END\\n'; "

        "printf 'VCCHECK_STALE_PI_BEGIN\\n'; "
        "/opt/vc/bin/debug.py --timeout 60 -v --stale_pi_dump 2>/dev/null || echo '[]'; "
        "printf '\\nVCCHECK_STALE_PI_END\\n'; "

        "printf 'VCCHECK_STALE_TD_BEGIN\\n'; "
        "/opt/vc/bin/debug.py --timeout 60 -v --stale_td_dump 2>/dev/null || echo '[]'; "
        "printf '\\nVCCHECK_STALE_TD_END\\n'; "

        "printf 'VCCHECK_HEALTH_BEGIN\\n'; "
        "/opt/vc/bin/debug.py -v --health_report 2>/dev/null || echo '{}'; "
        "printf '\\nVCCHECK_HEALTH_END\\n'; "

        "printf 'VCCHECK_MEMTOP_BEGIN\\n'; "
        "/opt/vc/bin/debug.py -v --memory_dump 2>/dev/null || echo '[]'; "
        "printf '\\nVCCHECK_MEMTOP_END\\n'; "

        "printf 'VCCHECK_DPDK_BEGIN\\n'; "
        "/opt/vc/bin/vcdbgdump -r dpdk-leak-dump 2>/dev/null || echo ''; "
        "printf '\\nVCCHECK_DPDK_END\\n'"
    )


def _extract_check_block(raw, name):
    """Extract text between VCCHECK_<name>_BEGIN and VCCHECK_<name>_END."""
    begin = f"VCCHECK_{name}_BEGIN"
    end = f"VCCHECK_{name}_END"
    start = raw.find(begin)
    if start < 0:
        return None
    start += len(begin)
    stop = raw.find(end, start)
    if stop < 0:
        return None
    return raw[start:stop].strip()


def _safe_json(text, fallback=None):
    """Parse JSON, returning fallback on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return fallback


def _parse_tunnel_check(block, device):
    """Check tunnel stability from --psummary output."""
    data = _safe_json(block, [])
    if not data:
        return None
    total_unstable = 0
    total_dead = 0
    details = []
    for entry in data:
        unstable = entry.get("unstable", 0) or 0
        dead = entry.get("dead", 0) or 0
        total_unstable += unstable
        total_dead += dead
        if unstable or dead:
            pt = entry.get("peer_type", "?")
            parts = []
            if dead:
                parts.append(f"{dead} dead")
            if unstable:
                parts.append(f"{unstable} unstable")
            details.append(f"{pt}: {', '.join(parts)}")

    if total_dead > 0:
        level = "critical"
    elif total_unstable > 0:
        level = "warning"
    else:
        level = "ok"

    return {
        "check_type": "tunnel",
        "result": data,
        "alert_level": level,
        "alert_detail": "; ".join(details) if details else None,
    }


def _parse_route_check(block, device):
    """Check route summary for >2% change from previous poll."""
    data = _safe_json(block, [])
    if not data:
        return None
    total_routes = 0
    for seg in data:
        rs = seg.get("rsummary", {})
        if isinstance(rs, dict):
            total_routes += rs.get("total_routes", 0) or 0
        elif isinstance(rs, list):
            total_routes += sum(r.get("total", 0) or 0 for r in rs)

    prev = device.get("prev_route_total")
    level = "ok"
    detail = None
    if prev is not None and prev > 0:
        change_pct = abs(total_routes - prev) / prev * 100
        if change_pct > 2.0:
            level = "warning"
            direction = "increased" if total_routes > prev else "decreased"
            detail = f"Routes {direction} from {prev} to {total_routes} ({change_pct:.1f}%)"

    result = {"segments": data, "_total_routes": total_routes, "_prev_total": prev}
    return {
        "check_type": "route",
        "result": result,
        "alert_level": level,
        "alert_detail": detail,
    }


def _parse_path_check(block, device):
    """Check path summary for peer/path count changes."""
    data = _safe_json(block, [])
    if not data:
        return None
    total_peers = sum(e.get("peer_count", 0) or 0 for e in data)
    total_paths = sum(e.get("total_paths", 0) or 0 for e in data)

    prev_peers = device.get("prev_peer_count")
    prev_paths = device.get("prev_total_paths")
    level = "ok"
    details = []
    if prev_peers is not None and total_peers != prev_peers:
        level = "warning"
        details.append(f"peer_count {prev_peers} -> {total_peers}")
    if prev_paths is not None and total_paths != prev_paths:
        level = "warning"
        details.append(f"total_paths {prev_paths} -> {total_paths}")

    result = {"peers": data, "_total_peer_count": total_peers, "_total_paths": total_paths}
    return {
        "check_type": "path",
        "result": result,
        "alert_level": level,
        "alert_detail": "; ".join(details) if details else None,
    }


def _parse_stale_check(block, device, kind):
    """Check stale PI or TD flow count for increases."""
    data = _safe_json(block, [])
    count = len(data) if isinstance(data, list) else 0
    prev_key = f"prev_{kind}_count"
    prev = device.get(prev_key)
    level = "ok"
    detail = None
    if prev is not None and count > prev:
        level = "warning"
        detail = f"{kind} increased from {prev} to {count}"

    truncated = data[:20] if isinstance(data, list) else []
    return {
        "check_type": kind,
        "result": {"count": count, "entries": truncated},
        "alert_level": level,
        "alert_detail": detail,
    }


_ALERT_RANK = {"ok": 0, "warning": 1, "critical": 2}


def _escalate_level(current, new):
    """Return whichever alert level is more severe."""
    return new if _ALERT_RANK.get(new, 0) > _ALERT_RANK.get(current, 0) else current


def _parse_health_check(block, device):
    """Parse health report and alert on CPU/mem/handoff thresholds."""
    data = _safe_json(block, {})
    if not data:
        return None

    # Normalize: health_report may return a list with one dict or a plain dict
    if isinstance(data, list):
        data = data[0] if data else {}

    level = "ok"
    details = []

    cpu_300 = data.get("cpu_300s_avg_pct")
    if cpu_300 is not None:
        try:
            cpu_300 = float(cpu_300)
        except (TypeError, ValueError):
            cpu_300 = None
    if cpu_300 is not None:
        if cpu_300 > 95:
            level = _escalate_level(level, "critical")
            details.append(f"CPU 300s avg {cpu_300:.1f}%")
        elif cpu_300 > 80:
            level = _escalate_level(level, "warning")
            details.append(f"CPU 300s avg {cpu_300:.1f}%")

    mem_pct = data.get("edged_mem_usage_pct") or data.get("gatewayd_mem_usage_pct")
    if mem_pct is not None:
        try:
            mem_pct = float(mem_pct)
        except (TypeError, ValueError):
            mem_pct = None
    if mem_pct is not None and mem_pct > 85:
        level = _escalate_level(level, "warning")
        details.append(f"mem usage {mem_pct:.1f}%")

    drops = data.get("handoffq_drops")
    if drops is not None:
        try:
            drops = int(drops)
        except (TypeError, ValueError):
            drops = 0
    if drops and drops > 0:
        level = _escalate_level(level, "warning")
        details.append(f"handoff drops {drops}")

    return {
        "check_type": "health",
        "result": data,
        "alert_level": level,
        "alert_detail": "; ".join(details) if details else None,
    }


def _parse_memtop_check(block, device):
    """Parse memory dump, return top 10 allocators by bytes."""
    data = _safe_json(block, [])
    if not isinstance(data, list):
        return None
    sorted_data = sorted(data, key=lambda x: x.get("bytes", 0), reverse=True)[:10]
    return {
        "check_type": "memory_top10",
        "result": sorted_data,
        "alert_level": "ok",
        "alert_detail": None,
    }


def _parse_dpdk_check(block, device):
    """Count dpdk_mbuf_leak occurrences in vcdbgdump output."""
    leak_count = block.count("dpdk_mbuf_leak") if block else 0
    if leak_count > 10:
        level = "critical"
    elif leak_count > 0:
        level = "warning"
    else:
        level = "ok"

    return {
        "check_type": "dpdk_leak",
        "result": {"leak_count": leak_count, "raw_snippet": (block or "")[:500]},
        "alert_level": level,
        "alert_detail": f"{leak_count} DPDK mbuf leaks detected" if leak_count > 0 else None,
    }


def _parse_checks(raw, device):
    """
    Parse all diagnostic check blocks from the combined SSH output.
    Each parser is independent — if one fails, the others still succeed.
    """
    if not raw:
        return []

    psummary_block = _extract_check_block(raw, "PSUMMARY")

    results = []
    checks = [
        ("tunnel",      lambda: _parse_tunnel_check(psummary_block, device)),
        ("path",        lambda: _parse_path_check(psummary_block, device)),
        ("route",       lambda: _parse_route_check(_extract_check_block(raw, "ROUTE"), device)),
        ("stale_pi",    lambda: _parse_stale_check(_extract_check_block(raw, "STALE_PI"), device, "stale_pi")),
        ("stale_td",    lambda: _parse_stale_check(_extract_check_block(raw, "STALE_TD"), device, "stale_td")),
        ("health",      lambda: _parse_health_check(_extract_check_block(raw, "HEALTH"), device)),
        ("memory_top10", lambda: _parse_memtop_check(_extract_check_block(raw, "MEMTOP"), device)),
        ("dpdk_leak",   lambda: _parse_dpdk_check(_extract_check_block(raw, "DPDK"), device)),
    ]
    for name, parse_fn in checks:
        try:
            result = parse_fn()
            if result:
                results.append(result)
        except Exception as exc:
            log.debug(f"  check parse error [{name}]: {exc}")
    return results


# ── Polling ───────────────────────────────────────────────────────────────────

def poll_device(device):
    """
    SSH into a VM via its hypervisor's NAT (hypervisor_ip:console_port),
    collect memory/CPU/core metrics, optionally collect HA peer metrics.
    """
    try:
        # Always connect via hypervisor NAT (hypervisor_ip:console_port).
        # The DNAT rule forwards the connection to the VM — whether its SSH
        # is on port 22 or a non-standard port like 2041.
        ssh = ssh_connect(
            device["hypervisor_ip"], device["console_port"],
            DEVICE_USER, DEVICE_PASS,
        )

        proc = "edged" if device["device_type"] == "edge" else "gwd"
        raw  = ssh_run(ssh, _collect_cmd(proc))
        m    = _parse_metrics(raw)

        # HA check (edges only)
        ha = None
        if device["device_type"] == "edge":
            try:
                ha = _collect_ha_metrics(ssh)
            except Exception as exc:
                log.debug(f"  HA probe {device['ip']}: {exc}")

        # Diagnostic checks (tunnel, route, path, stale flows, health, mem top10, dpdk)
        checks = []
        try:
            checks_raw = ssh_run(ssh, _checks_cmd(), timeout=CHECKS_SSH_TIMEOUT)
            checks = _parse_checks(checks_raw, device)
        except Exception as exc:
            log.debug(f"  checks {device['ip']}: {exc}")

        ssh.close()

        now = datetime.utcnow().isoformat()
        with get_db() as conn:
            # Update VM name and core file list
            conn.execute(
                "UPDATE devices SET vm_name=COALESCE(?,vm_name), core_files=? WHERE id=?",
                (m["hostname"] or None, json.dumps(m["core_files"]), device["id"]))
            if ha:
                conn.execute(
                    "UPDATE devices SET ha_core_files=? WHERE id=?",
                    (json.dumps(ha.get("core_files", [])), device["id"]))

            conn.execute("""
                INSERT INTO memory_samples(
                    device_id, ts, pid,
                    mem_total_kb, mem_free_kb, mem_available_kb,
                    mem_buffers_kb, mem_cached_kb,
                    cpu_pct, process_uptime_sec, core_count,
                    core_files_json, ha_core_files_json,
                    ha_reachable, ha_pid,
                    ha_mem_total_kb, ha_mem_free_kb, ha_mem_available_kb,
                    ha_cpu_pct, ha_process_uptime_sec, ha_core_count
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                device["id"], now, m["pid"],
                m["mem_total"], m["mem_free"], m["mem_available"],
                m["mem_buffers"], m["mem_cached"],
                m["cpu_pct"], m["process_uptime_sec"], m["core_count"],
                json.dumps(m["core_files"]) if m["core_files"] else None,
                json.dumps(ha.get("core_files", [])) if ha and ha.get("core_files") else None,
                1 if ha else 0,
                ha["pid"]                 if ha else None,
                ha["mem_total"]           if ha else None,
                ha["mem_free"]            if ha else None,
                ha["mem_available"]       if ha else None,
                ha["cpu_pct"]             if ha else None,
                ha["process_uptime_sec"]  if ha else None,
                ha["core_count"]          if ha else None,
            ))
            conn.execute(
                "UPDATE devices SET reachable=1, last_seen=? WHERE id=?",
                (now, device["id"]))

            # Store diagnostic check results
            for chk in checks:
                conn.execute("""
                    INSERT INTO device_checks(device_id, ts, check_type, result_json, alert_level, alert_detail)
                    VALUES(?,?,?,?,?,?)
                """, (device["id"], now, chk["check_type"],
                      json.dumps(chk["result"]), chk["alert_level"], chk.get("alert_detail")))

            # Update prev_* columns for next-poll change detection
            for chk in checks:
                ct = chk["check_type"]
                r = chk["result"]
                if ct == "route" and isinstance(r, dict):
                    conn.execute("UPDATE devices SET prev_route_total=? WHERE id=?",
                                 (r.get("_total_routes"), device["id"]))
                elif ct == "path" and isinstance(r, dict):
                    conn.execute("UPDATE devices SET prev_peer_count=?, prev_total_paths=? WHERE id=?",
                                 (r.get("_total_peer_count"), r.get("_total_paths"), device["id"]))
                elif ct == "stale_pi" and isinstance(r, dict):
                    conn.execute("UPDATE devices SET prev_stale_pi_count=? WHERE id=?",
                                 (r.get("count"), device["id"]))
                elif ct == "stale_td" and isinstance(r, dict):
                    conn.execute("UPDATE devices SET prev_stale_td_count=? WHERE id=?",
                                 (r.get("count"), device["id"]))

    except Exception as exc:
        log.debug(f"  poll {device['ip']}:{device['console_port']} — {exc}")
        with get_db() as conn:
            conn.execute("UPDATE devices SET reachable=0 WHERE id=?", (device["id"],))


def run_poll():
    global _op_name
    if not _op_lock.acquire(blocking=False):
        log.info(f"Poll skipped — {_op_name} already running")
        return
    _op_name = "poll"
    try:
        _run_poll()
    finally:
        _op_lock.release()
        _op_name = ""


def _run_poll():
    with get_db() as conn:
        # Join hypervisors so poll_device gets hypervisor_ip
        devices = [dict(r) for r in conn.execute("""
            SELECT d.*, h.ip AS hypervisor_ip
            FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE NOT (d.console_port >= 2200 AND d.console_port <= 2299)
        """).fetchall()]

    if not devices:
        log.info("No devices in DB yet — waiting for discovery")
        return

    log.info(f"Polling {len(devices)} devices (max {POLL_WORKERS} concurrent)...")
    with ThreadPoolExecutor(max_workers=POLL_WORKERS) as pool:
        for d in devices:
            pool.submit(poll_device, d)
    # pool.__exit__ calls shutdown(wait=True) — blocks until all tasks finish.
    # poll_device handles its own DB writes, SSH timeouts, and errors.
    log.info("Poll complete")


# ── Anomaly detection ─────────────────────────────────────────────────────────

def _parse_ts(ts):
    """Parse ISO timestamp string — compatible with Python 3.6."""
    return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")


def _slope_kb_per_hour(timestamps, free_values):
    n = len(timestamps)
    if n < 3:
        return 0.0
    t0 = _parse_ts(timestamps[0])
    xs = [(_parse_ts(t) - t0).total_seconds() for t in timestamps]
    ys = list(free_values)
    x_mean = sum(xs) / n
    y_mean = sum(ys) / n
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    den = sum((x - x_mean) ** 2 for x in xs)
    return (num / den * 3600) if den else 0.0


def get_device_status(device_id):
    with get_db() as conn:
        # Check device's last_seen timestamp to determine if it's newly discovered
        device_row = conn.execute(
            "SELECT last_seen, reachable FROM devices WHERE id=?", (device_id,)
        ).fetchone()

        latest = conn.execute("""
            SELECT pid, mem_total_kb, mem_free_kb, mem_available_kb,
                   cpu_pct, process_uptime_sec, core_count,
                   ha_reachable, ha_pid, ha_mem_total_kb, ha_mem_free_kb,
                   ha_mem_available_kb, ha_cpu_pct, ha_process_uptime_sec, ha_core_count, ts
            FROM memory_samples WHERE device_id=? ORDER BY ts DESC LIMIT 1
        """, (device_id,)).fetchone()

        if not latest:
            # No samples yet - check if this is a newly discovered device
            if device_row and device_row["last_seen"]:
                try:
                    last_seen = _parse_ts(device_row["last_seen"])
                    time_since_seen = (datetime.utcnow() - last_seen).total_seconds()
                    # If discovered within last 2 poll cycles and never polled, it's "discovering"
                    if time_since_seen < (POLL_INTERVAL * 2):
                        return {"alert": "discovering", "current": None, "slope_kb_h": 0}
                except Exception:
                    pass
            return {"alert": "no_data", "current": None, "slope_kb_h": 0}

        pid       = latest["pid"]
        total     = latest["mem_total_kb"] or 1
        free      = latest["mem_free_kb"] or 0
        free_pct  = free / total * 100

        rows = conn.execute("""
            SELECT ts, mem_free_kb FROM memory_samples
            WHERE device_id=? AND pid=?
            ORDER BY ts DESC LIMIT ?
        """, (device_id, pid, TREND_SAMPLES)).fetchall()

    rows = list(reversed(rows))
    slope = _slope_kb_per_hour([r["ts"] for r in rows], [r["mem_free_kb"] for r in rows])

    if free_pct < CRIT_FREE_PCT or slope < CRIT_SLOPE_KB_H:
        alert = "critical"
    elif free_pct < WARN_FREE_PCT or slope < WARN_SLOPE_KB_H:
        alert = "warning"
    else:
        alert = "ok"

    ha_info = None
    if latest["ha_reachable"]:
        ha_total = latest["ha_mem_total_kb"] or 1
        ha_free  = latest["ha_mem_free_kb"] or 0
        ha_info  = {
            "pid":              latest["ha_pid"],
            "mem_total_kb":     latest["ha_mem_total_kb"],
            "mem_free_kb":      ha_free,
            "mem_available_kb": latest["ha_mem_available_kb"],
            "cpu_pct":          latest["ha_cpu_pct"],
            "process_uptime_sec": latest["ha_process_uptime_sec"],
            "core_count":       latest["ha_core_count"],
            "free_pct":         round(ha_free / ha_total * 100, 1),
        }

    return {
        "alert":      alert,
        "slope_kb_h": round(slope, 1),
        "current": {
            "ts":                 latest["ts"],
            "pid":                pid,
            "mem_total_kb":       total,
            "mem_free_kb":        free,
            "mem_available_kb":   latest["mem_available_kb"],
            "mem_used_kb":        total - free,
            "free_pct":           round(free_pct, 1),
            "cpu_pct":            latest["cpu_pct"],
            "process_uptime_sec": latest["process_uptime_sec"],
            "core_count":         latest["core_count"],
        },
        "ha": ha_info,
    }


# Max chart data points per device embedded in reports. Beyond this, samples are
# downsampled evenly so the HTML file stays a manageable size.
MAX_CHART_SAMPLES = 500

# ── Report data builder ───────────────────────────────────────────────────────

def _build_report_data(session_id):
    """Aggregate memory_samples for all devices in a recording window.
    Works for both completed and active (still-recording) sessions.
    """
    with get_db() as conn:
        session = conn.execute(
            "SELECT * FROM recording_sessions WHERE id=?", (session_id,)
        ).fetchone()
        if not session:
            return None
        session = dict(session)
        tid    = session["topology_id"]
        start  = session["started_at"]
        # For active sessions, use current time as the window end
        stop   = session["stopped_at"] or datetime.utcnow().isoformat()
        hv_id  = session.get("hypervisor_id")

        # Device filter: specific hypervisor (per-bastion) or whole topology
        if hv_id:
            where_clause = "d.hypervisor_id=?"
            where_args   = (hv_id, start, stop)
            hv_row = conn.execute(
                "SELECT name FROM hypervisors WHERE id=?", (hv_id,)
            ).fetchone()
            topo_label = hv_row["name"] if hv_row else str(hv_id)
        else:
            where_clause = "h.topology_id=?"
            where_args   = (tid, start, stop)
            topo_label   = TOPOLOGIES.get(tid, {}).get("label", tid)

        devices = [dict(r) for r in conn.execute(f"""
            SELECT DISTINCT d.id, d.device_type, d.ip, d.vm_name, h.name AS hypervisor_name
            FROM memory_samples ms
            JOIN devices d ON ms.device_id = d.id
            JOIN hypervisors h ON d.hypervisor_id = h.id
            WHERE {where_clause} AND ms.ts>=? AND ms.ts<=?
            ORDER BY d.device_type, h.name, d.ip
        """, where_args).fetchall()]

        result_devices = []
        for dev in devices:
            samples = [dict(r) for r in conn.execute("""
                SELECT ts, mem_total_kb, mem_free_kb, mem_available_kb, cpu_pct,
                       ha_reachable, ha_mem_free_kb, ha_mem_total_kb, ha_cpu_pct,
                       core_count, core_files_json, ha_core_files_json
                FROM memory_samples
                WHERE device_id=? AND ts>=? AND ts<=?
                ORDER BY ts ASC
            """, (dev["id"], start, stop)).fetchall()]
            if not samples:
                continue

            frees  = [s["mem_free_kb"] for s in samples if s["mem_free_kb"] is not None]
            cpus   = [s["cpu_pct"]     for s in samples if s["cpu_pct"]     is not None]
            ha_pct = sum(1 for s in samples if s.get("ha_reachable")) / len(samples) * 100

            dev["summary"] = {
                "mem_total_kb":     samples[-1]["mem_total_kb"],
                "mem_free_min_kb":  min(frees) if frees else None,
                "mem_free_max_kb":  max(frees) if frees else None,
                "mem_free_avg_kb":  int(sum(frees) / len(frees)) if frees else None,
                "cpu_pct_avg":      round(sum(cpus) / len(cpus), 1) if cpus else None,
                "cpu_pct_max":      round(max(cpus), 1) if cpus else None,
                "ha_reachable_pct": round(ha_pct, 1),
                "core_count_max":   max((s["core_count"] or 0) for s in samples),
                "sample_count":     len(samples),
                "first_ts":         samples[0]["ts"],
                "last_ts":          samples[-1]["ts"],
            }
            # Keep full samples for core file extraction before downsampling
            dev["_all_samples"] = samples

            # Downsample for chart rendering to cap HTML size; summary uses all samples
            if len(samples) > MAX_CHART_SAMPLES:
                step = max(1, len(samples) // MAX_CHART_SAMPLES)
                chart_samples = samples[::step]
                if chart_samples[-1] is not samples[-1]:
                    chart_samples.append(samples[-1])
                dev["samples"] = chart_samples
            else:
                dev["samples"] = samples
            result_devices.append(dev)

    # Compute coredump alerts from full (non-downsampled) sample data
    core_alerts = []
    for dev in result_devices:
        all_samples = dev.pop("_all_samples")
        if dev["summary"]["core_count_max"] > 0:
            first_core_ts = next(
                (s["ts"] for s in all_samples if (s["core_count"] or 0) > 0), None
            )
            # Collect unique core file names seen across all samples
            seen_files = {}
            for s in all_samples:
                raw = s.get("core_files_json")
                if not raw:
                    continue
                try:
                    files = json.loads(raw) if isinstance(raw, str) else raw
                except (json.JSONDecodeError, TypeError):
                    continue
                for f in (files if isinstance(files, list) else []):
                    fname = f.get("name", "")
                    if fname and fname not in seen_files:
                        ts_val = f.get("ts", 0)
                        seen_files[fname] = {
                            "name": fname,
                            "file_ts": ts_val,
                            "file_ts_str": datetime.utcfromtimestamp(int(ts_val)).strftime("%Y-%m-%d %H:%M:%S") if ts_val else "",
                            "first_poll": s["ts"],
                        }
            # Same for HA core files
            ha_seen_files = {}
            for s in all_samples:
                raw = s.get("ha_core_files_json")
                if not raw:
                    continue
                try:
                    files = json.loads(raw) if isinstance(raw, str) else raw
                except (json.JSONDecodeError, TypeError):
                    continue
                for f in (files if isinstance(files, list) else []):
                    fname = f.get("name", "")
                    if fname and fname not in ha_seen_files:
                        ts_val = f.get("ts", 0)
                        ha_seen_files[fname] = {
                            "name": fname,
                            "file_ts": ts_val,
                            "file_ts_str": datetime.utcfromtimestamp(int(ts_val)).strftime("%Y-%m-%d %H:%M:%S") if ts_val else "",
                            "first_poll": s["ts"],
                        }

            core_alerts.append({
                "device_name":   dev.get("vm_name") or dev["ip"],
                "ip":            dev["ip"],
                "core_count":    dev["summary"]["core_count_max"],
                "first_seen":    first_core_ts,
                "core_files":    list(seen_files.values()),
                "ha_core_files": list(ha_seen_files.values()),
            })

    # Strip core_files_json from chart samples to reduce payload size
    for dev in result_devices:
        for s in dev["samples"]:
            s.pop("core_files_json", None)
            s.pop("ha_core_files_json", None)

    # Gather check alerts that occurred during the recording window
    with get_db() as conn:
        device_ids = [d["id"] for d in result_devices]
        check_alerts_data = []
        if device_ids:
            ph = ",".join("?" * len(device_ids))
            # Deduplicate: for each (device, check_type, alert_detail) group
            # keep only one row with first_seen/last_seen and occurrence count.
            check_rows = [dict(r) for r in conn.execute(f"""
                SELECT dc.device_id, dc.check_type, dc.alert_level,
                       dc.alert_detail,
                       MIN(dc.ts) AS first_seen,
                       MAX(dc.ts) AS last_seen,
                       COUNT(*)   AS occurrences,
                       d.device_type, d.ip, d.vm_name,
                       h.name AS hypervisor_name
                FROM device_checks dc
                JOIN devices d ON dc.device_id = d.id
                JOIN hypervisors h ON d.hypervisor_id = h.id
                WHERE dc.device_id IN ({ph})
                  AND dc.ts >= ? AND dc.ts <= ?
                  AND dc.alert_level != 'ok'
                GROUP BY dc.device_id, dc.check_type, dc.alert_level, dc.alert_detail
                ORDER BY
                  CASE dc.alert_level WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                  MAX(dc.ts) DESC
            """, (*device_ids, start, stop)).fetchall()]

            for cr in check_rows:
                cr["ts"] = cr["last_seen"]
                check_alerts_data.append(cr)

        # Build per-device check summary and trend data
        # Query full (non-deduplicated) check history for trend charts
        check_trend_rows = {}
        if device_ids:
            for row in conn.execute(f"""
                SELECT device_id, ts, check_type, result_json, alert_level
                FROM device_checks
                WHERE device_id IN ({ph})
                  AND ts >= ? AND ts <= ?
                  AND check_type != 'memory_top10'
                ORDER BY ts ASC
            """, (*device_ids, start, stop)).fetchall():
                check_trend_rows.setdefault(row["device_id"], []).append(row)

        for dev in result_devices:
            dev_checks = [c for c in check_alerts_data if c["device_id"] == dev["id"]]
            # Unique check types with alert for this device
            seen_types = set()
            dev["check_alerts"] = []
            for c in dev_checks:
                key = (c["check_type"], c["alert_level"])
                if key not in seen_types:
                    seen_types.add(key)
                    dev["check_alerts"].append({
                        "check_type":  c["check_type"],
                        "alert_level": c["alert_level"],
                        "alert_detail": c["alert_detail"],
                        "ts":          c["ts"],
                    })

            # Extract numeric trend data per check type for charts
            dev["check_trends"] = {}
            for row in check_trend_rows.get(dev["id"], []):
                ct = row["check_type"]
                extractor = _TREND_EXTRACTORS.get(ct)
                if not extractor:
                    continue
                try:
                    result = json.loads(row["result_json"])
                    metrics = extractor(result)
                except Exception:
                    continue
                metrics["ts"] = row["ts"]
                metrics["alert_level"] = row["alert_level"]
                dev["check_trends"].setdefault(ct, []).append(metrics)

    # Summarize check alerts by category for the report header
    check_alert_summary = {}
    for ca in check_alerts_data:
        ct = ca["check_type"]
        if ct not in check_alert_summary:
            check_alert_summary[ct] = {"total": 0, "critical": 0, "warning": 0}
        check_alert_summary[ct]["total"] += 1
        if ca["alert_level"] == "critical":
            check_alert_summary[ct]["critical"] += 1
        elif ca["alert_level"] == "warning":
            check_alert_summary[ct]["warning"] += 1

    dc = session.get("device_count") or 0
    if dc > 0:
        session["sample_count"] = session["sample_count"] // dc
    return {
        "session":              session,
        "topology_label":       topo_label,
        "is_live":              session["status"] == "recording",
        "window_end":           stop,
        "devices":              result_devices,
        "core_alerts":          core_alerts,
        "check_alerts":         check_alerts_data,
        "check_alert_summary":  check_alert_summary,
    }


# ── Recording poll manager ────────────────────────────────────────────────────
# Tracks the unix timestamp of the last poll per recording session id.
_rec_last_polled: dict = {}


def _poll_recording_devices(session: dict):
    """Poll devices for one active recording at its custom rate."""
    tid   = session["topology_id"]
    hv_id = session.get("hypervisor_id")
    sid   = session["id"]

    with get_db() as conn:
        if hv_id:
            devices = [dict(r) for r in conn.execute("""
                SELECT d.*, h.ip AS hypervisor_ip
                FROM devices d JOIN hypervisors h ON d.hypervisor_id = h.id
                WHERE d.hypervisor_id=?
                  AND NOT (d.console_port >= 2200 AND d.console_port <= 2299)
            """, (hv_id,)).fetchall()]
        else:
            devices = [dict(r) for r in conn.execute("""
                SELECT d.*, h.ip AS hypervisor_ip
                FROM devices d JOIN hypervisors h ON d.hypervisor_id = h.id
                WHERE h.topology_id=?
                  AND NOT (d.console_port >= 2200 AND d.console_port <= 2299)
            """, (tid,)).fetchall()]

    if not devices:
        return

    log.info(f"[REC {sid}] Polling {len(devices)} devices (interval={session['poll_interval_sec']}s)")
    with ThreadPoolExecutor(max_workers=min(len(devices), POLL_WORKERS)) as pool:
        for d in devices:
            pool.submit(poll_device, d)

    # Update last_polled_at timestamp in DB
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE recording_sessions SET last_polled_at=? WHERE id=?",
            (now, sid)
        )


def recording_poll_manager():
    """Background thread: drives custom-rate polling for all active recordings."""
    while True:
        try:
            with get_db() as conn:
                active = [dict(r) for r in conn.execute(
                    "SELECT * FROM recording_sessions WHERE status='recording'"
                ).fetchall()]

            now = time.time()
            for session in active:
                sid      = session["id"]
                interval = session.get("poll_interval_sec") or POLL_INTERVAL
                last     = _rec_last_polled.get(sid, 0)

                if now - last >= interval:
                    _rec_last_polled[sid] = now
                    threading.Thread(
                        target=_poll_recording_devices,
                        args=(session,),
                        daemon=True,
                    ).start()
        except Exception as exc:
            log.error(f"Recording poll manager error: {exc}")

        time.sleep(10)   # wake up every 10 s to check due recordings


# ── Background scheduler ──────────────────────────────────────────────────────

def background_loop():
    last_discovery = {tid: 0 for tid in TOPOLOGIES}
    last_purge = 0
    while True:
        now = time.time()
        for tid in TOPOLOGIES:
            if now - last_discovery[tid] >= REDISCOVER_INTERVAL:
                try:
                    run_discovery(tid)
                except Exception as exc:
                    log.error(f"Discovery error [{tid}]: {exc}")
                last_discovery[tid] = time.time()
        try:
            run_poll()
        except Exception as exc:
            log.error(f"Poll error: {exc}")
        if now - last_purge >= 3600:
            try:
                purge_old_samples()
            except Exception as exc:
                log.error(f"Purge error: {exc}")
            last_purge = time.time()
        time.sleep(POLL_INTERVAL)


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           poll_interval=POLL_INTERVAL,
                           warn_free_pct=WARN_FREE_PCT,
                           crit_free_pct=CRIT_FREE_PCT)


@app.route("/api/summary")
def api_summary():
    tid   = request.args.get("topology", "chennai")
    hv_id = request.args.get("hypervisor_id", type=int)
    with get_db() as conn:
        if hv_id:
            hv_where  = "id=? AND topology_id=?"
            hv_args   = (hv_id, tid)
            dev_where = "d.hypervisor_id=? AND h.topology_id=?"
            dev_args  = (hv_id, tid)
        else:
            hv_where  = "topology_id=?"
            hv_args   = (tid,)
            dev_where = "h.topology_id=?"
            dev_args  = (tid,)
        hv_total = conn.execute(
            f"SELECT COUNT(*) FROM hypervisors WHERE {hv_where}", hv_args).fetchone()[0]
        hv_up    = conn.execute(
            f"SELECT COUNT(*) FROM hypervisors WHERE {hv_where} AND reachable=1", hv_args).fetchone()[0]
        e_total  = conn.execute(f"""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where} AND d.device_type='edge'""", dev_args).fetchone()[0]
        e_up     = conn.execute(f"""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where} AND d.device_type='edge' AND d.reachable=1""", dev_args).fetchone()[0]
        g_total  = conn.execute(f"""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where} AND d.device_type='gateway'""", dev_args).fetchone()[0]
        g_up     = conn.execute(f"""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where} AND d.device_type='gateway' AND d.reachable=1""", dev_args).fetchone()[0]
        samples  = conn.execute(f"""
            SELECT COUNT(*) FROM memory_samples ms
            JOIN devices d ON ms.device_id=d.id
            JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where}""", dev_args).fetchone()[0]
    return jsonify({
        "hypervisors":   {"total": hv_total,  "reachable": hv_up},
        "edges":         {"total": e_total,   "reachable": e_up},
        "gateways":      {"total": g_total,   "reachable": g_up},
        "total_samples": samples,
        "server_time":   datetime.utcnow().isoformat() + "Z",
    })


@app.route("/api/devices")
def api_devices():
    tid   = request.args.get("topology", "chennai")
    dtype = request.args.get("type", "")
    hv_id = request.args.get("hypervisor_id", type=int)
    with get_db() as conn:
        if hv_id:
            dev_where = "d.hypervisor_id=? AND h.topology_id=?"
            params = [hv_id, tid]
        else:
            dev_where = "h.topology_id=?"
            params = [tid]
        q = f"""
            SELECT d.id, d.device_type, d.ip, d.console_port, d.vm_name,
                   d.core_files, d.ha_core_files,
                   d.last_seen, d.reachable,
                   h.name AS hypervisor_name, h.ip AS hypervisor_ip
            FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where}
              AND NOT (d.console_port >= 2200 AND d.console_port <= 2299)
        """
        if dtype in ("edge", "gateway"):
            q += " AND d.device_type=?"
            params.append(dtype)
        q += " ORDER BY d.device_type, h.name, d.ip"
        rows = [dict(r) for r in conn.execute(q, params).fetchall()]

    for dev in rows:
        dev["core_files"]    = json.loads(dev.get("core_files")    or "[]")
        dev["ha_core_files"] = json.loads(dev.get("ha_core_files") or "[]")
        dev["memory"] = get_device_status(dev["id"])

    # Batch-fetch latest check_type → alert_level for all devices in one query
    if rows:
        device_ids = [d["id"] for d in rows]
        ph = ",".join("?" * len(device_ids))
        with get_db() as conn:
            chk_rows = conn.execute(f"""
                SELECT dc.device_id, dc.check_type, dc.alert_level
                FROM device_checks dc
                WHERE dc.device_id IN ({ph})
                  AND dc.ts = (
                      SELECT MAX(dc2.ts) FROM device_checks dc2
                      WHERE dc2.device_id = dc.device_id AND dc2.check_type = dc.check_type
                  )
            """, device_ids).fetchall()
        checks_by_device = {}
        for r in chk_rows:
            checks_by_device.setdefault(r["device_id"], {})[r["check_type"]] = r["alert_level"]
        for dev in rows:
            dev["checks_summary"] = checks_by_device.get(dev["id"], {})
    else:
        for dev in rows:
            dev["checks_summary"] = {}

    return jsonify(rows)


@app.route("/api/device/<int:device_id>/history")
def api_device_history(device_id):
    hours = max(1, min(int(request.args.get("hours", 6)), 168))
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

    with get_db() as conn:
        dev = conn.execute("""
            SELECT d.*, h.name AS hypervisor_name, h.ip AS hypervisor_ip
            FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id WHERE d.id=?
        """, (device_id,)).fetchone()
        if not dev:
            return jsonify({"error": "not found"}), 404

        pid_row = conn.execute(
            "SELECT pid FROM memory_samples WHERE device_id=? ORDER BY ts DESC LIMIT 1",
            (device_id,)).fetchone()
        current_pid = pid_row["pid"] if pid_row else None

        samples = conn.execute("""
            SELECT ts, pid, mem_total_kb, mem_free_kb, mem_available_kb,
                   cpu_pct, process_uptime_sec, core_count,
                   ha_reachable, ha_mem_free_kb, ha_mem_total_kb,
                   ha_cpu_pct, ha_process_uptime_sec, ha_core_count
            FROM memory_samples
            WHERE device_id=? AND ts >= ?
            ORDER BY ts ASC
        """, (device_id, since)).fetchall()

    return jsonify({
        "device":      dict(dev),
        "current_pid": current_pid,
        "samples":     [dict(s) for s in samples],
    })


@app.route("/api/alerts")
def api_alerts():
    tid   = request.args.get("topology", "chennai")
    hv_id = request.args.get("hypervisor_id", type=int)
    if hv_id:
        dev_where = "d.hypervisor_id=? AND h.topology_id=?"
        dev_args  = (hv_id, tid)
    else:
        dev_where = "h.topology_id=?"
        dev_args  = (tid,)
    with get_db() as conn:
        devices = [dict(r) for r in conn.execute(f"""
            SELECT d.id, d.device_type, d.ip, d.vm_name, d.reachable,
                   h.name AS hypervisor_name
            FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE {dev_where}
              AND d.reachable=1
              AND NOT (d.console_port >= 2200 AND d.console_port <= 2299)
        """, dev_args).fetchall()]

    alerts = []
    for dev in devices:
        st = get_device_status(dev["id"])
        if st["alert"] in ("warning", "critical"):
            alerts.append({
                "device_id":   dev["id"],
                "device_type": dev["device_type"],
                "ip":          dev["ip"],
                "vm_name":     dev.get("vm_name") or dev["ip"],
                "hypervisor":  dev["hypervisor_name"],
                "alert":       st["alert"],
                "alert_source": "memory",
                "slope_kb_h":  st["slope_kb_h"],
                "current":     st["current"],
                "ha":          st["ha"],
            })

    # Check-based alerts
    with get_db() as conn:
        check_alerts = [dict(r) for r in conn.execute("""
            SELECT dc.device_id, dc.check_type, dc.alert_level, dc.alert_detail, dc.ts,
                   d.device_type, d.ip, d.vm_name, h.name AS hypervisor_name
            FROM device_checks dc
            JOIN devices d ON dc.device_id = d.id
            JOIN hypervisors h ON d.hypervisor_id = h.id
            WHERE h.topology_id = ?
              AND dc.alert_level != 'ok'
              AND COALESCE(dc.dismissed, 0) = 0
              AND dc.ts = (
                  SELECT MAX(dc2.ts) FROM device_checks dc2
                  WHERE dc2.device_id = dc.device_id
                    AND dc2.check_type = dc.check_type
              )
        """, (tid,)).fetchall()]
    for ca in check_alerts:
        alerts.append({
            "device_id":    ca["device_id"],
            "device_type":  ca["device_type"],
            "ip":           ca["ip"],
            "vm_name":      ca.get("vm_name") or ca["ip"],
            "hypervisor":   ca["hypervisor_name"],
            "alert":        ca["alert_level"],
            "alert_source": ca["check_type"],
            "alert_detail": ca["alert_detail"],
            "ts":           ca["ts"],
            "slope_kb_h":   None,
            "current":      None,
            "ha":           None,
        })

    alerts.sort(key=lambda x: (x["alert"] != "critical", x.get("slope_kb_h") or 0))
    return jsonify(alerts)


@app.route("/api/checks")
def api_checks():
    """Return latest check results with non-ok alerts for a topology."""
    tid = request.args.get("topology", "chennai")
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT dc.id, dc.device_id, dc.ts, dc.check_type,
                   dc.alert_level, dc.alert_detail,
                   d.device_type, d.ip, d.vm_name,
                   h.name AS hypervisor_name
            FROM device_checks dc
            JOIN devices d ON dc.device_id = d.id
            JOIN hypervisors h ON d.hypervisor_id = h.id
            WHERE h.topology_id = ?
              AND dc.alert_level != 'ok'
              AND COALESCE(dc.dismissed, 0) = 0
              AND dc.ts = (
                  SELECT MAX(dc2.ts) FROM device_checks dc2
                  WHERE dc2.device_id = dc.device_id
                    AND dc2.check_type = dc.check_type
              )
            ORDER BY
              CASE dc.alert_level WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
              dc.ts DESC
        """, (tid,)).fetchall()]
    return jsonify(rows)


@app.route("/api/checks/dismiss", methods=["POST"])
def api_checks_dismiss():
    """Dismiss specific check alerts by ID list, or all for a topology."""
    data = request.get_json(force=True) or {}
    ids = data.get("ids")  # list of check IDs to dismiss
    tid = data.get("topology")  # dismiss all for this topology

    with get_db() as conn:
        if ids and isinstance(ids, list):
            placeholders = ",".join("?" * len(ids))
            conn.execute(
                f"UPDATE device_checks SET dismissed=1 WHERE id IN ({placeholders})",
                ids)
            return jsonify({"status": "dismissed", "count": len(ids)})
        elif tid:
            result = conn.execute("""
                UPDATE device_checks SET dismissed=1
                WHERE alert_level != 'ok' AND dismissed = 0
                  AND device_id IN (
                      SELECT d.id FROM devices d
                      JOIN hypervisors h ON d.hypervisor_id = h.id
                      WHERE h.topology_id = ?
                  )
            """, (tid,))
            return jsonify({"status": "dismissed_all", "topology": tid, "count": result.rowcount})
        else:
            return jsonify({"error": "provide 'ids' array or 'topology'"}), 400


@app.route("/api/device/<int:device_id>/checks")
def api_device_checks(device_id):
    """Return latest check result per check_type for a device."""
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT dc.*
            FROM device_checks dc
            WHERE dc.device_id = ?
              AND dc.ts = (
                  SELECT MAX(dc2.ts) FROM device_checks dc2
                  WHERE dc2.device_id = dc.device_id
                    AND dc2.check_type = dc.check_type
              )
            ORDER BY dc.check_type
        """, (device_id,)).fetchall()]
    for r in rows:
        try:
            r["result"] = json.loads(r["result_json"])
        except (json.JSONDecodeError, TypeError):
            r["result"] = None
        del r["result_json"]
    return jsonify(rows)


@app.route("/api/device/<int:device_id>/checks/history")
def api_device_checks_history(device_id):
    """Return check history for a device and check_type over a time window."""
    check_type = request.args.get("type", "tunnel")
    hours = max(1, min(int(request.args.get("hours", 6)), 168))
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT ts, result_json, alert_level, alert_detail
            FROM device_checks
            WHERE device_id = ? AND check_type = ? AND ts >= ?
            ORDER BY ts ASC
        """, (device_id, check_type, since)).fetchall()]
    for r in rows:
        try:
            r["result"] = json.loads(r["result_json"])
        except (json.JSONDecodeError, TypeError):
            r["result"] = None
        del r["result_json"]
    return jsonify({"check_type": check_type, "samples": rows})


_TREND_EXTRACTORS = {
    "tunnel": lambda r: {
        "stable":   sum(e.get("stable", 0) or 0 for e in r) if isinstance(r, list) else 0,
        "unstable": sum(e.get("unstable", 0) or 0 for e in r) if isinstance(r, list) else 0,
        "dead":     sum(e.get("dead", 0) or 0 for e in r) if isinstance(r, list) else 0,
    },
    "route": lambda r: {
        "total_routes": r.get("_total_routes", 0) if isinstance(r, dict) else 0,
    },
    "path": lambda r: {
        "peer_count":  r.get("_total_peer_count", 0) if isinstance(r, dict) else 0,
        "total_paths": r.get("_total_paths", 0) if isinstance(r, dict) else 0,
    },
    "stale_pi": lambda r: {
        "count": r.get("count", 0) if isinstance(r, dict) else (len(r) if isinstance(r, list) else 0),
    },
    "stale_td": lambda r: {
        "count": r.get("count", 0) if isinstance(r, dict) else (len(r) if isinstance(r, list) else 0),
    },
    "health": lambda r: {
        "cpu_pct":      float(r.get("cpu_300s_avg_pct") or r.get("cpu_60s_avg_pct") or 0) if isinstance(r, dict) else 0,
        "mem_pct":      float(r.get("edged_mem_usage_pct") or r.get("gatewayd_mem_usage_pct") or 0) if isinstance(r, dict) else 0,
        "flow_count":   int(r.get("flow_count") or 0) if isinstance(r, dict) else 0,
        "handoffq_drops": int(r.get("handoffq_drops") or 0) if isinstance(r, dict) else 0,
    },
    "dpdk_leak": lambda r: {
        "leak_count": r.get("leak_count", 0) if isinstance(r, dict) else 0,
    },
}


@app.route("/api/device/<int:device_id>/checks/trends")
def api_device_checks_trends(device_id):
    """Return pre-extracted numeric time-series for all chartable check types."""
    hours = max(1, min(int(request.args.get("hours", 6)), 168))
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    with get_db() as conn:
        rows = conn.execute("""
            SELECT ts, check_type, result_json, alert_level
            FROM device_checks
            WHERE device_id = ? AND ts >= ? AND check_type != 'memory_top10'
            ORDER BY ts ASC
        """, (device_id, since)).fetchall()

    trends = {}
    for row in rows:
        ct = row["check_type"]
        extractor = _TREND_EXTRACTORS.get(ct)
        if not extractor:
            continue
        try:
            result = json.loads(row["result_json"])
            metrics = extractor(result)
        except Exception:
            continue
        metrics["ts"] = row["ts"]
        metrics["alert_level"] = row["alert_level"]
        trends.setdefault(ct, []).append(metrics)

    return jsonify(trends)


@app.route("/api/rediscover", methods=["POST"])
def api_rediscover():
    tid = request.args.get("topology", "chennai")
    if tid not in TOPOLOGIES:
        tid = "chennai"
    if _op_lock.locked():
        return jsonify({"status": "busy", "reason": _op_name + " already running"}), 409
    threading.Thread(target=run_discovery, args=(tid,), daemon=True).start()
    return jsonify({"status": "discovery started", "topology": tid})


@app.route("/api/topologies")
def api_topologies():
    return jsonify({
        tid: {"label": t["label"]}
        for tid, t in TOPOLOGIES.items()
    })


@app.route("/api/poll_now", methods=["POST"])
def api_poll_now():
    if _op_lock.locked():
        return jsonify({"status": "busy", "reason": _op_name + " already running"}), 409
    threading.Thread(target=run_poll, daemon=True).start()
    return jsonify({"status": "poll started"})


@app.route("/api/bastion/list")
def api_bastion_list():
    with get_db() as conn:
        hvs = [dict(r) for r in conn.execute("""
            SELECT h.id, h.name, h.ip, h.reachable, h.last_seen,
                   COUNT(d.id) AS device_count
            FROM hypervisors h
            LEFT JOIN devices d ON d.hypervisor_id = h.id
            WHERE h.topology_id = 'standard_testbeds'
            GROUP BY h.id
        """).fetchall()]
    return jsonify(hvs)


@app.route("/api/bastion/add", methods=["POST"])
def api_bastion_add():
    """Add a dynamic bastion host to the Standard Testbeds topology and start discovery."""
    data     = request.get_json(force=True) or {}
    ip       = (data.get("ip")       or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    name     = (data.get("name")     or "").strip() or ip
    port     = int(data.get("port", 22))
    if not ip or not username or not password:
        return jsonify({"error": "ip, username, and password are required"}), 400
    topology_id = "standard_testbeds"
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO hypervisors(name,ip,port,username,password,topology_id) VALUES(?,?,?,?,?,?)",
            (name, ip, port, username, password, topology_id))
        conn.execute(
            "UPDATE hypervisors SET name=?,port=?,username=?,password=?,topology_id=? WHERE ip=?",
            (name, port, username, password, topology_id, ip))
    threading.Thread(target=run_discovery, args=(topology_id,), daemon=True).start()
    return jsonify({"status": "bastion added, discovery started", "ip": ip})


@app.route("/api/bastion/<int:hv_id>", methods=["DELETE"])
def api_bastion_delete(hv_id):
    """Delete a bastion host and all its devices from the Standard Testbeds topology."""
    with get_db() as conn:
        conn.execute("""
            DELETE FROM memory_samples WHERE device_id IN (
                SELECT id FROM devices WHERE hypervisor_id = ?
            )
        """, (hv_id,))
        conn.execute("DELETE FROM devices WHERE hypervisor_id = ?", (hv_id,))
        conn.execute(
            "DELETE FROM hypervisors WHERE id = ? AND topology_id = 'standard_testbeds'",
            (hv_id,))
    return jsonify({"status": "deleted", "id": hv_id})


# ── Recording API ─────────────────────────────────────────────────────────────

@app.route("/api/recording/options")
def api_recording_options():
    """Return all recordable targets: topologies + individual bastion hosts."""
    options = []
    for tid, t in TOPOLOGIES.items():
        if tid == "standard_testbeds":
            continue  # expanded as individual bastions below
        options.append({"value": tid, "label": t["label"], "group": "Topology", "hypervisor_id": None})

    with get_db() as conn:
        bastions = [dict(r) for r in conn.execute("""
            SELECT h.id, h.name, h.ip, h.reachable,
                   COUNT(d.id) AS device_count
            FROM hypervisors h
            LEFT JOIN devices d ON d.hypervisor_id = h.id
            WHERE h.topology_id = 'standard_testbeds'
            GROUP BY h.id
            ORDER BY h.name
        """).fetchall()]
    for b in bastions:
        display = b["name"] if b["name"] != b["ip"] else b["ip"]
        options.append({
            "value":        f"bastion_{b['id']}",
            "label":        display,
            "group":        "Standard Testbeds",
            "hypervisor_id": b["id"],
            "ip":           b["ip"],
            "device_count": b["device_count"],
            "reachable":    bool(b["reachable"]),
        })
    return jsonify(options)


@app.route("/api/recording/start", methods=["POST"])
def api_recording_start():
    data             = request.get_json(force=True) or {}
    raw_topology     = data.get("topology", "chennai")
    label            = (data.get("label") or "").strip()
    poll_interval    = int(data.get("poll_interval_sec", POLL_INTERVAL))
    poll_interval    = max(30, min(poll_interval, 3600))   # clamp 30s–1h

    # Support bastion_<id> synthetic topology values
    hv_id = None
    if raw_topology.startswith("bastion_"):
        try:
            hv_id = int(raw_topology.split("_", 1)[1])
            tid   = "standard_testbeds"
        except (IndexError, ValueError):
            return jsonify({"error": "invalid topology"}), 400
    else:
        tid = raw_topology
        if tid not in TOPOLOGIES:
            return jsonify({"error": "unknown topology"}), 400

    with get_db() as conn:
        # One active recording per (topology, hypervisor_id)
        if hv_id:
            existing = conn.execute(
                "SELECT id FROM recording_sessions WHERE hypervisor_id=? AND status='recording'",
                (hv_id,)
            ).fetchone()
        else:
            existing = conn.execute(
                "SELECT id FROM recording_sessions WHERE topology_id=? AND hypervisor_id IS NULL AND status='recording'",
                (tid,)
            ).fetchone()
        if existing:
            return jsonify({"error": "already_recording", "session_id": existing["id"]}), 409

        now = datetime.utcnow().isoformat()
        cur = conn.execute(
            """INSERT INTO recording_sessions
               (topology_id, hypervisor_id, label, started_at, status, poll_interval_sec, last_polled_at)
               VALUES(?,?,?,?,?,?,?)""",
            (tid, hv_id, label, now, "recording", poll_interval, now)
        )
        session_id = cur.lastrowid
    return jsonify({
        "id": session_id, "topology": tid, "hypervisor_id": hv_id,
        "started_at": now, "status": "recording", "poll_interval_sec": poll_interval,
    })


@app.route("/api/recording/stop", methods=["POST"])
def api_recording_stop():
    data         = request.get_json(force=True) or {}
    raw_topology = data.get("topology", "chennai")

    hv_id = None
    if raw_topology.startswith("bastion_"):
        try:
            hv_id = int(raw_topology.split("_", 1)[1])
            tid   = "standard_testbeds"
        except (IndexError, ValueError):
            return jsonify({"error": "invalid topology"}), 400
    else:
        tid = raw_topology

    with get_db() as conn:
        if hv_id:
            session = conn.execute(
                "SELECT * FROM recording_sessions WHERE hypervisor_id=? AND status='recording'",
                (hv_id,)
            ).fetchone()
        else:
            session = conn.execute(
                "SELECT * FROM recording_sessions WHERE topology_id=? AND hypervisor_id IS NULL AND status='recording'",
                (tid,)
            ).fetchone()
        if not session:
            return jsonify({"error": "no_active_recording"}), 404

        now     = datetime.utcnow().isoformat()
        sid     = session["id"]
        started = session["started_at"]

        if hv_id:
            counts = conn.execute("""
                SELECT COUNT(ms.id) AS sample_count,
                       COUNT(DISTINCT ms.device_id) AS device_count
                FROM memory_samples ms
                JOIN devices d ON ms.device_id = d.id
                WHERE d.hypervisor_id=? AND ms.ts>=? AND ms.ts<=?
            """, (hv_id, started, now)).fetchone()
        else:
            counts = conn.execute("""
                SELECT COUNT(ms.id) AS sample_count,
                       COUNT(DISTINCT ms.device_id) AS device_count
                FROM memory_samples ms
                JOIN devices d ON ms.device_id = d.id
                JOIN hypervisors h ON d.hypervisor_id = h.id
                WHERE h.topology_id=? AND ms.ts>=? AND ms.ts<=?
            """, (tid, started, now)).fetchone()

        sc     = counts["sample_count"] if counts else 0
        dc     = counts["device_count"] if counts else 0
        status = "complete" if sc > 0 else "empty"
        conn.execute(
            "UPDATE recording_sessions SET stopped_at=?, status=?, sample_count=?, device_count=? WHERE id=?",
            (now, status, sc, dc, sid)
        )
    # Remove from in-memory poll tracker so the manager ignores it immediately
    _rec_last_polled.pop(sid, None)
    display_sc = sc // dc if dc > 0 else sc
    return jsonify({
        "id": sid, "topology": tid, "hypervisor_id": hv_id,
        "started_at": started, "stopped_at": now,
        "sample_count": display_sc, "device_count": dc, "status": status,
    })


@app.route("/api/recording/status")
def api_recording_status():
    raw = request.args.get("topology", "chennai")
    hv_id = None
    if raw.startswith("bastion_"):
        try:
            hv_id = int(raw.split("_", 1)[1])
        except (IndexError, ValueError):
            return jsonify({"recording": False, "session": None})
    with get_db() as conn:
        if hv_id:
            row = conn.execute(
                "SELECT id, started_at, label, poll_interval_sec FROM recording_sessions WHERE hypervisor_id=? AND status='recording'",
                (hv_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, started_at, label, poll_interval_sec FROM recording_sessions WHERE topology_id=? AND hypervisor_id IS NULL AND status='recording'",
                (raw,)
            ).fetchone()
    if row:
        return jsonify({"recording": True, "session": dict(row)})
    return jsonify({"recording": False, "session": None})


@app.route("/api/recording/active")
def api_recording_active():
    """Return all currently active recording sessions (across all topologies)."""
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT rs.id, rs.topology_id, rs.hypervisor_id, rs.label,
                   rs.started_at, rs.poll_interval_sec,
                   h.name AS hypervisor_name, h.ip AS hypervisor_ip
            FROM recording_sessions rs
            LEFT JOIN hypervisors h ON rs.hypervisor_id = h.id
            WHERE rs.status='recording'
            ORDER BY rs.started_at DESC
        """).fetchall()]
    for r in rows:
        topo = TOPOLOGIES.get(r["topology_id"], {})
        if r["hypervisor_id"]:
            r["display_label"] = r["hypervisor_name"] or r["hypervisor_ip"] or str(r["hypervisor_id"])
        else:
            r["display_label"] = topo.get("label", r["topology_id"])
    return jsonify(rows)


@app.route("/api/reports/<int:report_id>/live")
def api_report_live(report_id):
    """Live data for an active recording — same as /data but works while status='recording'."""
    data = _build_report_data(report_id)
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


# ── Reports API ───────────────────────────────────────────────────────────────

@app.route("/api/reports")
def api_reports():
    tid = request.args.get("topology", "")
    with get_db() as conn:
        base = """
            SELECT rs.*, h.name AS hypervisor_name, h.ip AS hypervisor_ip
            FROM recording_sessions rs
            LEFT JOIN hypervisors h ON rs.hypervisor_id = h.id
            WHERE rs.status != 'recording'
        """
        if tid.startswith("bastion_"):
            # Per-bastion topology value — filter by hypervisor_id
            hid = int(tid[len("bastion_"):])
            rows = [dict(r) for r in conn.execute(
                base + " AND rs.hypervisor_id=? ORDER BY rs.started_at DESC", (hid,)
            ).fetchall()]
        elif tid:
            rows = [dict(r) for r in conn.execute(
                base + " AND rs.topology_id=? ORDER BY rs.started_at DESC", (tid,)
            ).fetchall()]
        else:
            rows = [dict(r) for r in conn.execute(
                base + " ORDER BY rs.started_at DESC"
            ).fetchall()]
    for r in rows:
        if r.get("started_at") and r.get("stopped_at"):
            try:
                t0 = datetime.strptime(r["started_at"][:19], "%Y-%m-%dT%H:%M:%S")
                t1 = datetime.strptime(r["stopped_at"][:19], "%Y-%m-%dT%H:%M:%S")
                r["duration_sec"] = int((t1 - t0).total_seconds())
            except ValueError:
                r["duration_sec"] = 0
        else:
            r["duration_sec"] = 0
        if r.get("hypervisor_id"):
            r["topology_label"] = r.get("hypervisor_name") or r.get("hypervisor_ip") or "Bastion"
        else:
            r["topology_label"] = TOPOLOGIES.get(r["topology_id"], {}).get("label", r["topology_id"])
        dc = r.get("device_count") or 0
        r["sample_count"] = r["sample_count"] // dc if dc > 0 else r["sample_count"]
    return jsonify(rows)


@app.route("/api/reports/<int:report_id>/data")
def api_report_data(report_id):
    data = _build_report_data(report_id)
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/api/reports/<int:report_id>/download")
def api_report_download(report_id):
    data = _build_report_data(report_id)
    if not data:
        return "Report not found", 404
    html = render_template(
        "report.html",
        report_data=data,
        warn_free_pct=WARN_FREE_PCT,
        crit_free_pct=CRIT_FREE_PCT,
    )
    s   = data["session"]
    tid = s["topology_id"]
    fname = f"report_{report_id}_{tid}_{s['started_at'][:10]}.html"
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.route("/api/reports/<int:report_id>/rename", methods=["POST"])
def api_report_rename(report_id):
    label = (request.json or {}).get("label", "").strip()
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE recording_sessions SET label=? WHERE id=? AND status != 'recording'",
            (label, report_id),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found or still recording"}), 404
        conn.commit()
    return jsonify({"ok": True, "label": label})


@app.route("/api/reports/<int:report_id>", methods=["DELETE"])
def api_report_delete(report_id):
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM recording_sessions WHERE id=? AND status != 'recording'",
            (report_id,),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "not found or still recording"}), 404
        conn.commit()
    return jsonify({"ok": True})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Initialising database...")
    init_db()
    log.info("Starting background collector...")
    threading.Thread(target=background_loop, daemon=True).start()
    threading.Thread(target=recording_poll_manager, daemon=True).start()
    log.info("Starting web server on http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)

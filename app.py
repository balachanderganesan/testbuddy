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
        """)
        # Migrate existing DB: add new columns if absent
        _add_col_if_missing(conn, "recording_sessions", "poll_interval_sec INTEGER DEFAULT 300")
        _add_col_if_missing(conn, "recording_sessions", "last_polled_at TEXT")
        _add_col_if_missing(conn, "recording_sessions", "hypervisor_id INTEGER")
        _add_col_if_missing(conn, "devices", "vm_name TEXT")
        _add_col_if_missing(conn, "devices", "core_files TEXT")
        _add_col_if_missing(conn, "devices", "ha_core_files TEXT")
        _add_col_if_missing(conn, "devices", "vm_port INTEGER DEFAULT 22")
        _add_col_if_missing(conn, "hypervisors", "topology_id TEXT DEFAULT 'chennai'")
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
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def purge_old_samples():
    cutoff = (datetime.utcnow() - timedelta(hours=DB_RETENTION_HOURS)).isoformat()
    with get_db() as conn:
        conn.execute("DELETE FROM memory_samples WHERE ts < ?", (cutoff,))
    log.info("Old samples purged")


# ── SSH helpers ───────────────────────────────────────────────────────────────

def ssh_connect(host, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host, port=int(port),
        username=username, password=password,
        timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False,
        banner_timeout=SSH_TIMEOUT,
    )
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
                    ha_reachable, ha_pid,
                    ha_mem_total_kb, ha_mem_free_kb, ha_mem_available_kb,
                    ha_cpu_pct, ha_process_uptime_sec, ha_core_count
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                device["id"], now, m["pid"],
                m["mem_total"], m["mem_free"], m["mem_available"],
                m["mem_buffers"], m["mem_cached"],
                m["cpu_pct"], m["process_uptime_sec"], m["core_count"],
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

    except Exception as exc:
        log.debug(f"  poll {device['ip']}:{device['console_port']} — {exc}")
        with get_db() as conn:
            conn.execute("UPDATE devices SET reachable=0 WHERE id=?", (device["id"],))


def run_poll():
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
        latest = conn.execute("""
            SELECT pid, mem_total_kb, mem_free_kb, mem_available_kb,
                   cpu_pct, process_uptime_sec, core_count,
                   ha_reachable, ha_pid, ha_mem_total_kb, ha_mem_free_kb,
                   ha_mem_available_kb, ha_cpu_pct, ha_process_uptime_sec, ha_core_count, ts
            FROM memory_samples WHERE device_id=? ORDER BY ts DESC LIMIT 1
        """, (device_id,)).fetchone()

        if not latest:
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
                       ha_reachable, ha_mem_free_kb, ha_mem_total_kb, ha_cpu_pct, core_count
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

    # Compute coredump alerts from sample data (no extra DB column needed)
    core_alerts = []
    for dev in result_devices:
        if dev["summary"]["core_count_max"] > 0:
            # Find first sample where cores appeared
            first_core_ts = next(
                (s["ts"] for s in dev["samples"] if (s["core_count"] or 0) > 0), None
            )
            core_alerts.append({
                "device_name": dev.get("vm_name") or dev["ip"],
                "ip":          dev["ip"],
                "core_count":  dev["summary"]["core_count_max"],
                "first_seen":  first_core_ts,
            })

    return {
        "session":        session,
        "topology_label": topo_label,
        "is_live":        session["status"] == "recording",
        "window_end":     stop,
        "devices":        result_devices,
        "core_alerts":    core_alerts,
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
    tid = request.args.get("topology", "chennai")
    with get_db() as conn:
        hv_total = conn.execute(
            "SELECT COUNT(*) FROM hypervisors WHERE topology_id=?", (tid,)).fetchone()[0]
        hv_up = conn.execute(
            "SELECT COUNT(*) FROM hypervisors WHERE topology_id=? AND reachable=1", (tid,)).fetchone()[0]
        e_total = conn.execute("""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=? AND d.device_type='edge'""", (tid,)).fetchone()[0]
        e_up = conn.execute("""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=? AND d.device_type='edge' AND d.reachable=1""", (tid,)).fetchone()[0]
        g_total = conn.execute("""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=? AND d.device_type='gateway'""", (tid,)).fetchone()[0]
        g_up = conn.execute("""
            SELECT COUNT(*) FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=? AND d.device_type='gateway' AND d.reachable=1""", (tid,)).fetchone()[0]
        samples = conn.execute("""
            SELECT COUNT(*) FROM memory_samples ms
            JOIN devices d ON ms.device_id=d.id
            JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=?""", (tid,)).fetchone()[0]
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
    with get_db() as conn:
        q = """
            SELECT d.id, d.device_type, d.ip, d.console_port, d.vm_name,
                   d.core_files, d.ha_core_files,
                   d.last_seen, d.reachable,
                   h.name AS hypervisor_name, h.ip AS hypervisor_ip
            FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=?
              AND NOT (d.console_port >= 2200 AND d.console_port <= 2299)
        """
        params = [tid]
        if dtype in ("edge", "gateway"):
            q += " AND d.device_type=?"
            params.append(dtype)
        q += " ORDER BY d.device_type, h.name, d.ip"
        rows = [dict(r) for r in conn.execute(q, params).fetchall()]

    for dev in rows:
        dev["core_files"]    = json.loads(dev.get("core_files")    or "[]")
        dev["ha_core_files"] = json.loads(dev.get("ha_core_files") or "[]")
        dev["memory"] = get_device_status(dev["id"])
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
    tid = request.args.get("topology", "chennai")
    with get_db() as conn:
        devices = [dict(r) for r in conn.execute("""
            SELECT d.id, d.device_type, d.ip, d.vm_name, d.reachable,
                   h.name AS hypervisor_name
            FROM devices d JOIN hypervisors h ON d.hypervisor_id=h.id
            WHERE h.topology_id=?
              AND d.reachable=1
              AND NOT (d.console_port >= 2200 AND d.console_port <= 2299)
        """, (tid,)).fetchall()]

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
                "slope_kb_h":  st["slope_kb_h"],
                "current":     st["current"],
                "ha":          st["ha"],
            })
    alerts.sort(key=lambda x: (x["alert"] != "critical", x["slope_kb_h"]))
    return jsonify(alerts)


@app.route("/api/rediscover", methods=["POST"])
def api_rediscover():
    tid = request.args.get("topology", "chennai")
    if tid not in TOPOLOGIES:
        tid = "chennai"
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
    return jsonify({
        "id": sid, "topology": tid, "hypervisor_id": hv_id,
        "started_at": started, "stopped_at": now,
        "sample_count": sc, "device_count": dc, "status": status,
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
        if tid:
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


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Initialising database...")
    init_db()
    log.info("Starting background collector...")
    threading.Thread(target=background_loop, daemon=True).start()
    threading.Thread(target=recording_poll_manager, daemon=True).start()
    log.info("Starting web server on http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)

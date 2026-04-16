# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**testbuddy** is a Flask web dashboard ("Solution Topology Watcher") that monitors VeloCloud Edges and Gateways running as VMs on KVM hypervisors. It discovers VMs via iptables DNAT rules, polls memory/CPU/core-dump metrics over SSH, stores samples in SQLite, and serves a REST API consumed by a single-page frontend.

## Running the App

```bash
./setup_venv.sh               # create .venv and install deps (one-time)
source .venv/bin/activate
python app.py                 # starts on http://0.0.0.0:5001
```

No build step, no migrations — `init_db()` runs automatically on startup and handles schema migrations via `_add_col_if_missing`.

## File Layout

- [app.py](app.py) — the entire backend: DB schema, SSH helpers, discovery, polling, anomaly detection, REST API, and Flask entry point (~930 lines)
- [templates/index.html](templates/index.html) — single-page dashboard (Bootstrap 5 dark theme + Chart.js)
- [servers.json](servers.json) — KVM hypervisor list for the Chennai topology (SRV1–SRV29)
- [sc_servers.json](sc_servers.json) — KVM hypervisor list for the SC testbed topologies
- [vcmem.db](vcmem.db) — SQLite database (auto-created, not committed)

## Architecture

### Discovery → Polling → Anomaly pipeline

1. **Background thread** (`background_loop`) runs every `POLL_INTERVAL` (300 s). It calls `run_discovery` per topology every `REDISCOVER_INTERVAL` (600 s), then `run_poll` on every device.

2. **Discovery** (`run_discovery` → `discover_on_hypervisor`): SSH to each hypervisor, run `iptables -t nat -S`, parse DNAT rules via `_DNAT_RE`. New VMs are probed via SSH (`pgrep edged` / `pgrep gwd`) to detect their type; known VMs reuse the stored type from DB. Results are upserted into `hypervisors` and `devices` tables.

3. **Polling** (`run_poll` → `poll_device`): SSH into each VM **through the hypervisor NAT** (`hypervisor_ip:console_port`). Runs `_collect_cmd(proc)` — a single shell one-liner that emits `VCMEM_`-prefixed markers alongside `/proc/meminfo`. Parsed by `_parse_metrics`. Edges also probe their HA standby at `169.254.2.2` via `_collect_ha_metrics`.

4. **Anomaly detection** (`get_device_status`): Computes a linear-regression slope over the last `TREND_SAMPLES` (20) `mem_free_kb` values. Alert levels: ok / warning / critical based on `WARN_FREE_PCT`/`CRIT_FREE_PCT` thresholds and `WARN_SLOPE_KB_H`/`CRIT_SLOPE_KB_H` trend thresholds.

### Topologies

Topologies are defined in the `TOPOLOGIES` dict in `app.py`. Each entry maps to:
- A `servers_json` file (or `None` for dynamic "standard_testbeds")
- An optional `server_names` set to filter servers from the JSON

VM type (edge vs gateway) is determined dynamically via SSH process detection (`pgrep edged` / `pgrep gwd`) on first discovery; no static port-range rules are used.

The `standard_testbeds` topology is dynamic — hypervisors are added/removed via `/api/bastion/add` and `/api/bastion/delete/<id>` REST endpoints rather than from a JSON file.

### Database schema

Three tables in `vcmem.db`:
- `hypervisors` — one row per KVM host, tagged with `topology_id`
- `devices` — one row per discovered VM (edge or gateway), linked to its hypervisor; stores `core_files` and `ha_core_files` as JSON blobs
- `memory_samples` — time-series rows written every poll, indexed on `(device_id, ts DESC)`; HA metrics stored inline with `ha_` prefix columns

Old samples are purged hourly; retention is `DB_RETENTION_HOURS` (168 h = 7 days).

### REST API surface

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/summary?topology=` | Hypervisor/edge/gateway up counts |
| GET | `/api/devices?topology=&type=` | All devices with latest memory status |
| GET | `/api/device/<id>/history?hours=` | Time-series samples for one device |
| GET | `/api/alerts?topology=` | Devices in warning/critical state |
| GET | `/api/topologies` | Topology labels |
| POST | `/api/rediscover?topology=` | Trigger immediate re-discovery |
| POST | `/api/poll_now` | Trigger immediate poll |
| GET | `/api/bastion/list` | Standard-testbeds hypervisors |
| POST | `/api/bastion/add` | Add dynamic hypervisor |
| DELETE | `/api/bastion/<id>` | Remove dynamic hypervisor |

### servers.json format

```json
[{
  "name": "SRV1",
  "connections": { "ip": "10.x.x.x", "port": 22 },
  "credentials": { "username": "root", "password": "..." }
}]
```

The `custom_params`, `interfaces`, and `storage_disk` fields in the JSON are **not used by testbuddy** — they belong to a wider lab automation context.

## Key constants to tune

All in the top of `app.py`:

```python
POLL_INTERVAL        = 300   # seconds between polls
REDISCOVER_INTERVAL  = 600   # seconds between iptables scans
SSH_TIMEOUT          = 15    # SSH connect+exec timeout
HA_SSH_TIMEOUT       = 8     # timeout for HA peer SSH hop
DB_RETENTION_HOURS   = 168   # 7-day sample retention
POLL_WORKERS         = 50    # max concurrent SSH sessions during a poll run
WARN_FREE_PCT        = 15.0  # memory warning threshold
CRIT_FREE_PCT        =  8.0  # memory critical threshold
WARN_SLOPE_KB_H      = -200  # warn if trending down > 200 KB/h
CRIT_SLOPE_KB_H      = -800  # critical if trending down > 800 KB/h
```

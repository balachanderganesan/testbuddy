# Test Buddy

A real-time testbed verification dashboard for VeloCloud SD-WAN infrastructure. Discovers VMs running on KVM hypervisors, polls health metrics over SSH, runs diagnostic checks, and surfaces alerts — all from a single-page dark-themed web UI.

## Features

- **Auto-Discovery** — Scans hypervisor `iptables` DNAT rules to find Edge and Gateway VMs automatically
- **Memory & CPU Monitoring** — Polls `/proc/meminfo`, CPU%, process PID/uptime from every VM via SSH
- **Anomaly Detection** — Linear regression over recent samples detects memory leaks (slope-based) and low-memory conditions (threshold-based)
- **8 Diagnostic Checks** per poll interval:
  - Tunnel stability (stable/unstable/dead)
  - Route summary (alerts on >2% change)
  - Path summary (alerts on peer/path additions or removals)
  - Stale PI/TD flows (alerts on count increase)
  - Health report (CPU, mem usage, handoff drops)
  - Top 10 memory allocators
  - DPDK packet leak detection
  - HA Active/Active panic log analysis
- **HA Peer Monitoring** — Probes standby edge at `169.254.2.2` for memory, CPU, core dumps
- **Core Dump Tracking** — Detects and lists core dump files with timestamps
- **Recording & Reports** — Record polling sessions at custom intervals, generate downloadable HTML reports with trend charts
- **Pause/Resume Polling** — Toggle auto-polling on/off when the testbed is under heavy load
- **Multi-Topology Support** — Chennai, SC testbeds (TB1–TB5), and dynamic Standard Testbeds with bastion host management
- **Alert Management** — Dismiss individual, selected, or all check alerts; auto-purge after 5 days

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python3 app.py
```

Open **http://localhost:5001** in your browser.

## Requirements

- Python 3.8+
- Flask >= 3.0.0
- Paramiko >= 3.4.0
- SSH access to hypervisors listed in `servers.json` / `sc_servers.json`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Flask Web Server                      │
│                    (port 5001)                           │
├────────────┬──────────────┬─────────────────────────────┤
│  REST API  │  Dashboard   │  Downloadable Reports       │
│  (32 endpoints) │ (index.html) │ (report.html)          │
├────────────┴──────────────┴─────────────────────────────┤
│                 Background Threads                       │
│  ┌──────────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │  Discovery    │  │  Polling  │  │ Recording Poll   │  │
│  │  (iptables)   │  │  (SSH)    │  │ Manager          │  │
│  └──────────────┘  └───────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────┤
│                 SQLite (vcmem.db)                        │
│  hypervisors │ devices │ memory_samples │ device_checks  │
│  recording_sessions                                      │
└─────────────────────────────────────────────────────────┘
```

**Single-process Flask app** with background daemon threads:

1. **Discovery** — SSHes into hypervisors, parses `iptables -t nat` rules, detects VM type by checking for `edged` or `gwd` processes
2. **Polling** — SSHes into each VM via hypervisor NAT, collects memory/CPU/core metrics + 8 diagnostic checks in a single round-trip
3. **Anomaly Detection** — Computed at query time using linear regression over recent samples

**Frontend** — Vanilla JS + Bootstrap 5 + Chart.js. No build toolchain. Auto-refreshes every poll interval.

## Configuration

| Constant | Default | Purpose |
|---|---|---|
| `POLL_INTERVAL` | 300s | Background poll cadence + frontend refresh |
| `REDISCOVER_INTERVAL` | 600s | How often iptables is re-scanned |
| `SSH_TIMEOUT` | 15s | SSH connect/exec timeout |
| `POLL_WORKERS` | 50 | Max concurrent SSH sessions |
| `WARN_FREE_PCT` / `CRIT_FREE_PCT` | 15% / 8% | Memory health thresholds |
| `WARN_SLOPE_KB_H` / `CRIT_SLOPE_KB_H` | -200 / -800 | Memory leak rate thresholds |
| `DB_RETENTION_HOURS` | 168 (7d) | Memory sample retention |
| `CHECKS_RETENTION_HOURS` | 120 (5d) | Diagnostic check alert retention |

## API Reference

### Core
| Endpoint | Method | Description |
|---|---|---|
| `/api/summary` | GET | Hypervisor/device/sample counts |
| `/api/devices` | GET | All devices with memory status and check summary |
| `/api/device/<id>/history` | GET | Time-series memory data |
| `/api/alerts` | GET | Devices in warning/critical state |
| `/api/topologies` | GET | Available topology labels |
| `/api/rediscover` | POST | Trigger topology re-discovery |
| `/api/poll_now` | POST | Trigger immediate poll |
| `/api/polling/status` | GET | Auto-polling state (paused/live) |
| `/api/polling/toggle` | POST | Pause or resume auto-polling |

### Diagnostic Checks
| Endpoint | Method | Description |
|---|---|---|
| `/api/checks` | GET | Active check alerts by topology |
| `/api/checks/dismiss` | POST | Dismiss alerts by IDs or topology |
| `/api/device/<id>/checks` | GET | Latest check results per device |
| `/api/device/<id>/checks/history` | GET | Check history by type |
| `/api/device/<id>/checks/trends` | GET | Numeric trends for all check types |

### Recording & Reports
| Endpoint | Method | Description |
|---|---|---|
| `/api/recording/start` | POST | Start recording session |
| `/api/recording/stop` | POST | Stop recording session |
| `/api/recording/status` | GET | Current recording state |
| `/api/reports` | GET | List completed reports |
| `/api/reports/<id>/data` | GET | Report data with check trends |
| `/api/reports/<id>/download` | GET | Downloadable HTML report |

### Bastion Hosts (Standard Testbeds)
| Endpoint | Method | Description |
|---|---|---|
| `/api/bastion/list` | GET | List dynamic hypervisors |
| `/api/bastion/add` | POST | Add a bastion host |
| `/api/bastion/<id>` | DELETE | Remove a bastion host |

## Database

SQLite with WAL mode. Schema auto-migrates via `_add_col_if_missing()`.

| Table | Purpose |
|---|---|
| `hypervisors` | KVM host inventory per topology |
| `devices` | Discovered VMs (edges/gateways) |
| `memory_samples` | Per-poll memory/CPU/core metrics |
| `device_checks` | Diagnostic check results and alerts |
| `recording_sessions` | Recording session metadata |

## Project Structure

```
testbuddy/
├── app.py                 # Flask app, SSH polling, all backend logic
├── templates/
│   ├── index.html         # Dashboard SPA (Bootstrap 5 + Chart.js)
│   └── report.html        # Downloadable report template
├── servers.json           # Chennai topology hypervisor list
├── sc_servers.json        # SC testbed hypervisor list
├── requirements.txt       # Python dependencies
├── vcmem.db               # SQLite database (auto-created)
└── CLAUDE.md              # AI assistant context
```

## Screenshots

The dashboard provides:
- Summary cards (hypervisors, edges, gateways, alerts, samples, check alerts)
- Core dump and HA panic alert banners
- Grouped diagnostic check alerts with dismiss controls
- Device table with memory bars, CPU, trend arrows, HA status, and check indicators
- Per-device modal with memory chart, HA panel, diagnostic check cards with trend charts
- Recording controls and report viewer with embedded charts

## License

Internal tool — not licensed for external distribution.

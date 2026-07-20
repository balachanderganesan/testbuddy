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
- **Google Chat Notifications** — Sends webhook messages for new or escalated memory, diagnostic-check, and core-dump alerts
- **Recording & Reports** — Record polling sessions at custom intervals, generate downloadable HTML reports with trend charts
- **Shared Recording Support** — Multiple users can record different testbeds or bastions at the same time, with one active recording per target
- **Pause/Resume Polling** — Toggle auto-polling on/off when the testbed is under heavy load
- **Multi-Topology Support** — Chennai, SC testbeds (TB1–TB5), and dynamic Standard Testbeds with bastion host management
- **Alert Management** — Dismiss individual, selected, or all check alerts; auto-purge after 5 days

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Optional: copy the sample environment file and edit it
cp .env.example .env

# Run the server
python3 app.py
```

Open **http://localhost:5001** in your browser.

## Production Deploy

Use the included deployment helper on the production host after the repo has been copied or checked out there:

```bash
cd /path/to/testbuddy
chmod +x deploy_prod.sh
cp .env.example .env
# edit .env as needed
APP_USER=testbuddy APP_GROUP=testbuddy ./deploy_prod.sh
```

What it does:
- Creates or reuses `.venv`
- Installs Python dependencies from `requirements.txt`
- Creates `/etc/systemd/system/testbuddy.service`
- Enables and restarts the service
- Points the service at `.env` so config changes are picked up on restart

Useful overrides:
- `SERVICE_NAME` to change the systemd unit name
- `APP_USER` / `APP_GROUP` to run the service as a specific account
- `PYTHON_BIN` to choose a specific Python interpreter
- `ENV_FILE` to use a dotenv file other than `.env`
- `TESTBUDDY_GOOGLE_CHAT_WEBHOOK_URL` or `TESTBUDDY_GOOGLE_CHAT_WEBHOOK_URLS` to enable Google Chat alerts

Example with Google Chat enabled:

```bash
cat > .env <<'EOF'
TESTBUDDY_HOST=0.0.0.0
TESTBUDDY_PORT=5001
TESTBUDDY_GOOGLE_CHAT_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=...
EOF

APP_USER=testbuddy APP_GROUP=testbuddy ./deploy_prod.sh
```

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

### Dotenv support

`app.py` automatically loads `.env` from the repo root before reading `TESTBUDDY_*` variables. Existing shell or systemd environment variables still win over values in `.env`.

For production installs, `deploy_prod.sh` sets `TESTBUDDY_DOTENV_PATH` in the systemd unit, so editing `.env` and restarting the service is enough:

```bash
sudo systemctl restart testbuddy
```

### Google Chat alerting

Set these in `.env` or in the process environment before starting `app.py`:

- `TESTBUDDY_GOOGLE_CHAT_WEBHOOK_URL` — single incoming-webhook URL
- `TESTBUDDY_GOOGLE_CHAT_WEBHOOK_URLS` — comma or whitespace separated webhook URLs
- `TESTBUDDY_GOOGLE_CHAT_TIMEOUT` — webhook POST timeout in seconds, default `10`
- `TESTBUDDY_GOOGLE_CHAT_NOTIFY_RECOVERIES` — set to `1` to also post recovery messages when an alert clears

Behavior:

- Sends messages after each completed poll, not on every page load or API call
- Posts only for new alerts, severity escalations, and core-dump file-list changes
- Covers memory alerts, active diagnostic check alerts, and core-dump alerts

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
| `/api/recording/status` | GET | Current recording state for one target |
| `/api/recording/active` | GET | All active recordings across targets |
| `/api/reports` | GET | List completed reports |
| `/api/reports/<id>/data` | GET | Report data with check trends |
| `/api/reports/<id>/download` | GET | Downloadable HTML report |

Recording rules:
- Different testbeds and bastions can be recorded concurrently.
- The same testbed or bastion can have only one active recording at a time.
- Recordings are anonymous and tied to the target, so any user can stop an active target recording.

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

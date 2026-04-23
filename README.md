# AegisEDR

**Standalone Endpoint Detection & Response lab** - A comprehensive mini-stack for learning, portfolio demonstration, and technical interviews.

## Overview

AegisEDR is a self-contained EDR laboratory that demonstrates:
- Endpoint agent simulation with process telemetry
- YAML-driven detection rules mapped to MITRE ATT&CK
- Detection engine with 12 matching operators
- 30 ATT&CK techniques covered
- Response automation (isolate, kill, ban)
- Full REST API with CRUD operations
- Web dashboard with real-time streaming
- Incident management lifecycle
- SIEM connectors (Splunk/Elastic/syslog)
- Alerting webhooks (Slack/PagerDuty/Teams)
- Threat intelligence integration (MISP/OTX)
- Network telemetry monitoring

## Project Structure

```
aegis-edr/
├── agent/                 # Telemetry collection (4 modules)
│   ├── endpoint_agent.py
│   ├── telemetry_collector.py
│   ├── process_tree.py
│   └── network_telemetry.py
├── api/main.py           # Full REST API (FastAPI)
├── automations/          # Response automation (2 modules)
├── controller/main.py    # Typer CLI
├── dashboard/main.py    # Web dashboard
├── detections/         # Detection engine (6 modules)
│   ├── matcher.py       # 12 operators
│   ├── rules.yaml      # 30 ATT&CK rules
│   ├── storage.py      # SQLite
│   ├── ioc_db.py      # IOC database
│   ├── yara_scanner.py
│   └── sigma_converter.py
├── incident/management.py  # Full lifecycle
├── integrations/       # Enterprise (3 modules)
│   ├── siem_connectors.py
│   ├── alerting.py
│   └── threat_intel.py
└── tests/             # 12 pytest tests
```

## Quick Start

```bash
cd projects/aegis-edr
uv sync

# List detection rules
uv run python controller/main.py ruleset

# Analyze sample telemetry
uv run python controller/main.py analyze samples/telemetry_sample.json
```

## Components

### CLI Controller
- `controller/main.py` - Typer CLI with Rich output
- Commands: `analyze`, `ruleset`

### REST API
```bash
uv run python api/main.py --port 8080
# Swagger UI: http://localhost:8080/docs
```

### Web Dashboard
```bash
uv run python dashboard/main.py --port 8000
# Access: http://localhost:8000
```

### Testing
```bash
PYTHONPATH=. uv run pytest tests/ -v
```

## Detection Rules

30 rules covering all MITRE ATT&CK tactics:
- **Execution**: PowerShell, WScript, Downloads
- **Persistence**: Registry Run, Scheduled Tasks, Services
- **Privilege Escalation**: Process Injection
- **Defense Evasion**: DLL Hijacking, disable AV
- **Credential Access**: Mimikatz, LSASS, Password Spraying
- **Discovery**: User/System enumeration
- **Lateral Movement**: RDP, SMB, Scheduled Tasks
- **Collection**: Email, Clipboard, Screen capture
- **Exfiltration**: HTTP, DNS
- **Impact**: Ransomware, Process termination

## Features

| Feature | Implementation |
|---------|---------------|
| Detection Engine | 12 operators (regex, gt/lt, contains, etc.) |
| ATT&CK Coverage | 30 techniques across 11 tactics |
| Data Storage | SQLite with deduplication |
| IOC Database | Hash reputation storage |
| YARA Scanner | 8 built-in rules |
| REST API | 14+ endpoints |
| WebSocket | Real-time streaming |
| SIEM | Splunk HEC, Elasticsearch, Syslog |
| Alerting | Slack, PagerDuty, Teams, Email |
| Threat Intel | MISP, AlienVault OTX, STIX |
| Incident Mgmt | Full lifecycle (Open→Closed) |
| Network Telemetry | DNS/HTTP monitoring |

## Usage Examples

### Analyze Telemetry
```bash
uv run python controller/main.py analyze samples/telemetry_sample.json --no-respond
```

### Live Monitoring
```bash
# File system monitoring
uv run python controller/main.py monitor --path ~/Downloads --duration 60

# Process monitoring (detects suspicious processes)
uv run python controller/main.py watch-process --duration 30

# Network connection monitoring
uv run python controller/main.py watch-network --duration 30
```

### List Incidents via API
```bash
curl http://localhost:8080/api/incidents?severity=Critical
```

### Check IOC
```bash
curl http://localhost:8080/api/iocs/sha256/aaaabbbbcccc1111222233334444555566667777888899990000aaaabbbb
```

## Documentation

- [dev_notes.md](dev_notes.md) - Complete architecture and roadmap
- [docs/workflow.md](docs/workflow.md) - Visual workflow

## Extending

1. **Add detection rules** - Edit `detections/rules.yaml`
2. **SIEM integration** - Configure in `integrations/siem_connectors.py`
3. **Alerting** - Add webhooks in `integrations/alerting.py`
4. **Threat intel** - Connect MISP/OTX in `integrations/threat_intel.py`

## Portfolio Value

This project demonstrates:
- MITRE ATT&CK mapping knowledge
- Detection engineering skills
- REST API design
- Real-time streaming (WebSocket)
- Database design (SQLite)
- Incident response automation
- SIEM integration concepts
- Threat intelligence integration

## License

MIT

---

## Portfolio Description

**Custom detection rule engine for hands-on security learning**

During my security journey, I built this detection rule engine to understand how alerts are created and how attackers behave. It became a practical way to study the MITRE ATT&CK framework while building real, working detection logic.

**What it demonstrates:**
- **Detection engineering fundamentals** - I know how SIEM rules work, not just how to read alerts
- **MITRE ATT&CK knowledge** - 50+ detection rules mapped to real attack techniques
- **Cloud security awareness** - AWS CloudTrail rules for IAM abuse, suspicious API activity
- **Self-directed learning** - I took initiative to build tools that help me understand the "why" behind alerts

**Conversation starter for interviews:**
> "I built AegisEDR to deepen my understanding of how detection works. Rather than just responding to alerts, I wanted to understand the logic behind them. This project shows I don't just consume alerts—I understand how they're created. The AWS CloudTrail rules demonstrate cloud security monitoring capability, which is in high demand."

**Technical details I can discuss:**
- Why certain rules use regex vs. exact matching
- How I handled false positive tuning
- The difference between event-based and behavioral detection
- Mapping detection rules to attacker kill chains
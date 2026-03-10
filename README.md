# 🛡️ CipherSecOps

> **Cross-Platform Autonomous Security Monitoring & Response Platform**
> A production-grade mini EDR/XDR system for real-time threat detection, automated response, and security visualization.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95-green?logo=fastapi)
![React](https://img.shields.io/badge/React-18-blue?logo=react)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Overview

CipherSecOps is a comprehensive security monitoring platform that deploys lightweight agents across your infrastructure to collect telemetry, detect threats in real-time, and automate incident response.

**Supported Platforms:** 🪟 Windows | 🐧 Linux | 🍎 macOS | ☁️ Cloud VMs | 📡 IoT Devices

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CipherSecOps Platform                    │
│                                                                 │
│  ┌──────────────┐     ┌───────────────┐     ┌───────────────┐  │
│  │   Agents     │────▶│  FastAPI      │────▶│  React        │  │
│  │  (Edge)      │     │  Server       │     │  Dashboard    │  │
│  │              │     │               │     │               │  │
│  │ • Processes  │     │ • Threat Eng. │     │ • Threat List │  │
│  │ • Network    │     │ • MITRE Map   │     │ • Network Map │  │
│  │ • Files      │     │ • Risk Score  │     │ • Timeline    │  │
│  │ • Logs       │     │ • Playbooks   │     │ • Agent Stats │  │
│  └──────────────┘     └───────┬───────┘     └───────────────┘  │
│                               │                                 │
│                    ┌──────────▼──────────┐                      │
│                    │  PostgreSQL + Redis │                      │
│                    └─────────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Features

- 🔍 **Process Monitoring** — Detect suspicious process spawning (python→powershell, encoded commands)
- 🌐 **Network Anomaly Detection** — Reverse shells, DNS tunneling, unusual ports
- 📁 **File Integrity Monitoring** — SHA-256 baseline tracking of critical OS files
- 📋 **Log Analysis** — Parse auth.log, syslog, Windows Event Log
- 🤖 **AI Decision Engine** — Correlate signals, calculate risk scores, recommend actions
- 🎯 **MITRE ATT&CK Mapping** — Map detections to TTPs
- 🛡️ **Threat Intelligence** — AlienVault OTX, AbuseIPDB, VirusTotal integration
- 📋 **Automated Playbooks** — YAML-based response playbooks for common attack patterns
- 📊 **React Dashboard** — Real-time dark-themed security dashboard
- 🐳 **Container Ready** — Full Docker Compose and Kubernetes support

## 🚀 Quick Start (Docker Compose)

```bash
# Clone the repository
git clone https://github.com/Cipher7788/CipherSecOps.git
cd CipherSecOps

# Copy environment variables
cp .env.example .env
# Edit .env with your API keys and secrets

# Start the full stack
docker-compose up -d

# Access the dashboard
open http://localhost:3000

# View API docs
open http://localhost:8000/docs
```

## 🛠️ Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL (or use Docker)

### Server Setup

```bash
cd server
pip install -r requirements.txt
uvicorn server.main:app --reload
```

### Agent Setup

```bash
cd agent
pip install -r requirements.txt
python -m agent.main
```

### Dashboard Setup

```bash
cd dashboard
npm install
npm start
```

## 🧪 Testing

```bash
# All tests
pytest tests/ -v

# Agent tests only
pytest tests/test_agent/ -v

# Server tests only
pytest tests/test_server/ -v

# With coverage
pytest tests/ -v --cov=agent --cov=server --cov-report=term-missing
```

## 📁 Project Structure

```
CipherSecOps/
├── agent/                    # Lightweight monitoring agent
│   ├── system_monitor.py     # Process heuristics (psutil)
│   ├── network_monitor.py    # Connection & C2 detection
│   ├── integrity_checker.py  # SHA-256 file baseline
│   ├── log_collector.py      # Auth/syslog parsing
│   ├── telemetry_sender.py   # Batched telemetry dispatch
│   ├── config.py             # Environment-driven config
│   └── main.py               # Agent orchestrator
├── server/                   # FastAPI backend
│   ├── api/                  # REST routers
│   │   ├── agents.py
│   │   ├── dashboard.py
│   │   ├── incidents.py
│   │   ├── playbooks.py
│   │   ├── telemetry.py
│   │   └── threats.py
│   ├── threat_engine/        # Detection & scoring
│   │   ├── rules.py          # 7 detection rules
│   │   ├── mitre_mapping.py  # ATT&CK technique map
│   │   ├── risk_scorer.py    # 0-100 risk scoring
│   │   └── analyzer.py       # Rule orchestration
│   ├── ai_engine/            # Decision engine
│   ├── playbooks/            # YAML response templates
│   ├── threat_intel/         # VirusTotal, OTX, AbuseIPDB
│   ├── models.py             # SQLAlchemy ORM models
│   ├── database.py           # Async DB session
│   └── main.py               # FastAPI app entry point
├── dashboard/                # React 18 frontend
│   └── src/
│       ├── components/       # Dashboard, Threats, NetworkMap, etc.
│       └── services/api.js   # REST client
├── k8s/                      # Kubernetes manifests
├── tests/                    # Pytest test suite
│   ├── conftest.py           # Shared fixtures
│   ├── test_agent/           # Agent unit tests
│   └── test_server/          # Server unit tests
├── docker-compose.yml
└── pytest.ini
```

## 🎯 MITRE ATT&CK Coverage

| Technique | ID | Detection |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Python/bash spawning shells, office macros |
| Application Layer Protocol (C2) | T1071 | Reverse shell connections, DNS tunneling |
| Obfuscated Files or Information | T1027 | Base64 encoded PowerShell commands |
| Brute Force | T1110 | Auth log failure thresholds |
| Scheduled Task / Job | T1053 | Cron / Task Scheduler anomalies |
| Process Injection | T1055 | Unusual process parent-child pairs |
| Network Service Scanning | T1046 | Port scan patterns |
| Resource Hijacking | T1496 | Crypto miner pool connections |
| Valid Accounts | T1078 | Credential misuse patterns |
| Exploit Public-Facing Application | T1190 | Web shell indicators |

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_SECRET_KEY` | *(required)* | Secret for signing JWT tokens |
| `ALIENVAULT_OTX_API_KEY` | — | AlienVault OTX API key |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB API key |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key |
| `SLACK_WEBHOOK_URL` | — | Slack alert webhook |

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License — see [LICENSE](LICENSE)
"Cross-Platform Autonomous Security Monitoring &amp; Response Platform (EDR/XDR)"

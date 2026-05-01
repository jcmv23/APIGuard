<p align="center">
  <img src="https://img.shields.io/badge/version-4.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.10+-green?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Next.js-16-black?style=for-the-badge&logo=next.js" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-blue?style=for-the-badge&logo=postgresql" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker" />
  <img src="https://img.shields.io/badge/license-BSL%201.1-purple?style=for-the-badge" />
</p>

<h1 align="center">🛡️ APIGuard Enterprise v4.0</h1>
<p align="center"><b>Enterprise API Security Platform</b></p>
<p align="center">
  Automated offensive security auditing for REST, GraphQL & WebSocket APIs.<br/>
  15 scanner modules · AI-powered explanations · Real-time telemetry · OWASP Top 10 compliance.<br/>
  Executive reports · Ticket management (Jira/GitHub) · API key authentication · PostgreSQL ready.
</p>

---

## 📋 Table of Contents

- [What is APIGuard?](#-what-is-apiguard)
- [Features at a Glance](#-features-at-a-glance)
- [Quick Start (5 minutes)](#-quick-start-5-minutes)
- [Architecture](#-architecture)
- [Scanner Modules](#-scanner-modules-15)
- [Using the Dashboard](#-using-the-dashboard)
- [CLI Usage](#-cli-usage)
- [API Reference](#-api-reference)
- [Docker Deployment](#-docker-deployment)
- [Configuration](#-configuration)
- [FAQ](#-faq)

---

## 🔍 What is APIGuard?

APIGuard is a **professional-grade API security scanner** that automatically discovers vulnerabilities in your APIs. Think of it as having a dedicated security team that works 24/7 — scanning, analyzing, and explaining every risk it finds.

**Who is it for?**
- 🏢 **CTOs & CISOs** — Get an executive dashboard with a security score, risk trends, and OWASP compliance at a glance.
- 🔐 **Security Engineers** — Run deep audits with 15 specialized modules covering injection, auth bypass, JWT cracking, secret detection, and more.
- 👨‍💻 **Developers** — Integrate scans into your CI/CD pipeline and catch vulnerabilities before they reach production.

---

## ✨ Features at a Glance

| Category | Features |
|----------|----------|
| **Scanning** | 15 security modules, OWASP API Top 10 coverage, auto-discovery of endpoints |
| **Intelligence** | AI-powered vulnerability explanations with fix code, Shannon entropy analysis |
| **Dashboard** | Real-time telemetry, animated security gauge, attack surface heatmap |
| **Reporting** | PDF/HTML/Markdown reports, SARIF export for CI/CD, scan comparison (diff) |
| **Executive Report** | C-level security overview, KPIs, risk gauge, severity trends 🆕 |
| **Ticket System** | Create tickets for Jira/Slack/GitHub with AI suggestions, local history 🆕 |
| **API Keys** | SHA-256 hashed keys with scopes, expiration, and revocation 🆕 |
| **Webhooks** | Notifications to Slack, Discord, Teams, Email, Jira, and GitHub Issues 🆕 |
| **Enterprise** | Multi-tenancy (RBAC), scan scheduling (date/time + interval), custom rules |
| **Database** | SQLite (dev) → PostgreSQL (prod), auto-migration 🆕 |
| **Deployment** | Docker Compose with PostgreSQL 16 + API + Frontend 🆕 |
| **UX** | Dark/Light theme, Command Palette (Ctrl+K), sound notifications, onboarding tour |

---

## 🚀 Quick Start (5 minutes)

### Prerequisites

- Python 3.10+
- Node.js 18+
- Git

### 1. Clone & Setup Backend

```bash
git clone https://github.com/your-repo/apiguard.git
cd apiguard

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Backend

```bash
python -m uvicorn api_server:app --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 3. Start the Frontend

```bash
cd apiguard-frontend
npm install
npm run dev
```

### 4. Open in Browser

Navigate to **http://localhost:3000** and you're ready to go!

**First time?** Create an account on the login page, then start scanning.

---

## 🏗 Architecture

```
APIGuard Enterprise v4.0
├── api_server.py            # FastAPI backend (REST + WebSocket)
├── main.py                  # CLI scanner entry point
├── user_management.py       # Auth & multi-tenancy (RBAC)
├── terminal_handler.py      # Interactive terminal engine (50+ commands)
│
├── core/
│   ├── ai_explainer.py      # AI vulnerability explanations
│   ├── api_keys.py          # API key management (SHA-256) 🆕
│   ├── scan_manager.py      # Real-time scan orchestration
│   ├── scheduler.py         # Date/time scheduler with background execution 🆕
│   ├── remediation.py       # Finding status tracking
│   ├── rules_engine.py      # Custom security rules
│   ├── api_discovery.py     # Auto-discover API specs & endpoints
│   ├── rate_limiter.py      # Persistent rate limiting
│   ├── database.py          # SQLite/PostgreSQL dual-backend 🆕
│   └── ci_integration.py    # SARIF export for CI/CD
│
├── integrations/
│   └── webhooks.py          # Slack, Discord, Teams, Email, Jira, GitHub 🆕
│
├── module_1_parser/         # OpenAPI/Swagger parser
├── module_2_bola/           # Broken Object Level Authorization
├── module_3_bfla/           # Broken Function Level Authorization
├── module_4_auth/           # Authentication & JWT testing
├── module_5_ratelimit/      # Rate limiting detection
├── module_6_injection/      # SQL/XSS/CORS injection
├── module_7_dashboard/      # Report generator (PDF/HTML)
├── module_8_ssl/            # SSL/TLS certificate auditing
├── module_9_graphql/        # GraphQL introspection & DoS
├── module_10_data_exposure/  # Sensitive data leak detection
├── module_11_fuzzer/        # Advanced mutational fuzzer (100+ payloads)
├── module_12_jwt/           # JWT cracker & algorithm analysis
├── module_13_secrets/       # Secret scanner (100+ regex patterns)
├── module_14_waf/           # WAF detection & fingerprinting
├── module_15_spec/          # Spec vs Reality validator
│
├── scripts/
│   └── init_postgres.sql    # PostgreSQL schema auto-init 🆕
│
├── apiguard-frontend/       # Next.js 16 dashboard (React)
├── tests/                   # Pytest suite (60+ tests) 🆕
├── Dockerfile               # Production container (multi-stage)
└── docker-compose.yml       # Full stack: API + Frontend + PostgreSQL 🆕
```

---

## 🔬 Scanner Modules (15)

### Core Modules (1-10)

| # | Module | What it does |
|---|--------|-------------|
| 1 | **OpenAPI Parser** | Parses Swagger/OpenAPI specs and discovers all endpoints automatically |
| 2 | **BOLA Scanner** | Tests for Broken Object Level Authorization (IDOR) by swapping object IDs |
| 3 | **BFLA Scanner** | Tests privilege escalation by using low-privilege tokens on admin endpoints |
| 4 | **Auth Analyzer** | Tests JWT validation, token manipulation, and authentication bypass |
| 5 | **Rate Limit Tester** | Sends burst requests to detect missing rate limiting |
| 6 | **Injection Scanner** | Tests for SQL injection, XSS, CORS misconfig, and header injection |
| 7 | **Report Generator** | Generates PDF, HTML, and Markdown vulnerability reports |
| 8 | **SSL/TLS Auditor** | Checks certificate validity, weak ciphers, and protocol versions |
| 9 | **GraphQL Scanner** | Tests introspection exposure, query depth attacks, and batch abuse |
| 10 | **Data Exposure** | Detects sensitive data in responses (emails, SSNs, credit cards) |

### Advanced Modules v4.0 (11-15) 🆕

| # | Module | What it does |
|---|--------|-------------|
| 11 | **Advanced Fuzzer** | Mutational fuzzing with 100+ payloads (SQLi, XSS, SSTI, CRLF, Path Traversal) with evasion engine |
| 12 | **JWT Cracker** | Cracks weak JWT secrets (80+ dictionary), detects `alg:none`, `kid` injection, claim analysis |
| 13 | **Secret Scanner** | Detects exposed secrets (AWS keys, Stripe tokens, GitHub PATs) with Shannon entropy analysis |
| 14 | **WAF Detector** | Fingerprints 15+ WAF vendors (Cloudflare, AWS WAF, Akamai) with active bypass probing |
| 15 | **Spec Validator** | Compares API spec vs reality, discovers shadow/undocumented endpoints, tests auth bypass |

---

## 🖥 Using the Dashboard

### Navigation

The dashboard has a **sidebar** on the left with these sections:

| Section | What you'll find |
|---------|-----------------|
| **Executive Analytics** | Security score gauge, KPI cards, risk trend chart, vulnerability donut, attack heatmap |
| **Active Scanner** | Launch quick or advanced scans, configure modules, enter target URL |
| **Telemetry Console** | Real-time terminal with live scan output, supports 50+ commands |
| **Risk Database** | Scan history, reports, scan comparison (diff), click → Executive Report 🆕 |
| **OWASP Compliance** | Mapping of your findings against the OWASP API Security Top 10 (2023) |
| **Scan Scheduler** | Pick date + time + repeat interval (15min to weekly) + max runs 🆕 |
| **Remediation** | Track finding status (open → in progress → fixed) |
| **Custom Rules** | Create custom detection rules with regex patterns |
| **Trend Metrics** | MTTR, risk exposure score, severity breakdown over time |
| **API Discovery** | Auto-discover OpenAPI specs, GraphQL endpoints, and admin panels |
| **Executive Report** | `/report/executive` — C-level overview, KPIs, create tickets 🆕 |

### Running Your First Scan

1. Click **Active Scanner** in the sidebar
2. Enter your target API URL (e.g., `https://api.yourcompany.com`)
3. Click **▶ Launch Audit**
4. Watch the scan progress in real-time on the **Telemetry Console**
5. Once complete, check **Executive Analytics** for your security score

### Quick Scan vs Advanced

- **Quick Scan**: Enter a URL and go. All 15 modules run with default settings.
- **Advanced Configuration**: Toggle individual modules on/off, set auth tokens, configure rate limit thresholds, timeouts, and more.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + K` | Open Command Palette (fast navigation) |
| `Theme toggle` | Switch Dark ↔ Light mode (button in sidebar header) |

### Understanding the Security Score

| Score | Rating | Color |
|-------|--------|-------|
| 80-100 | Excellent | 🟢 Green |
| 60-79 | Good | 🔵 Blue |
| 40-59 | Fair | 🟡 Yellow |
| 20-39 | Poor | 🟠 Orange |
| 0-19 | Critical | 🔴 Red |

### AI Explain & Fix

Every finding has an **"Explain & Fix"** button. Click it to get:
- A plain-English explanation of the vulnerability
- Real risk impact assessment
- Code examples showing how to fix it
- A severity rating

---

## ⌨ CLI Usage

You can also run scans from the command line:

```bash
# Full scan
python main.py --url https://api.example.com

# Scan with authentication
python main.py --url https://api.example.com --token "Bearer eyJ..."

# Skip specific modules
python main.py --url https://api.example.com --skip-graphql --skip-waf

# Quick scan (core modules only)
python main.py --url https://api.example.com --skip-fuzzer --skip-jwt --skip-secrets --skip-waf --skip-spec
```

### Terminal Commands (inside the dashboard console)

The Telemetry Console supports 50+ commands. Some highlights:

```bash
help                    # Show all commands
scan <url>              # Launch a scan
status                  # Current scan status
history                 # List past scans
clear                   # Clear terminal
whoami                  # Current user info
modules                 # List all scanner modules
neofetch                # System info (hacker style)
matrix                  # Matrix rain animation
```

---

## 📡 API Reference

The backend exposes a full REST API at `http://localhost:8000`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Start a new scan (async) |
| `POST` | `/api/v1/scan/sync` | Start a scan (wait for result) |
| `GET` | `/api/v1/scan/{id}` | Get scan status/results |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/report/{id}/pdf` | Download PDF report |
| `GET` | `/api/v1/report/{id}/html` | Download HTML report |
| `POST` | `/api/v1/compare` | Compare two scans (diff) |
| `POST` | `/api/v1/explain` | AI explanation for a finding |
| `POST` | `/api/v1/keys` | Create API key (shown once) 🆕 |
| `GET` | `/api/v1/keys` | List API keys (masked) 🆕 |
| `DELETE` | `/api/v1/keys/{id}` | Revoke an API key 🆕 |
| `GET` | `/api/v1/keys/validate` | Validate an API key 🆕 |
| `POST` | `/api/v1/schedules` | Create scheduled scan 🆕 |
| `GET` | `/api/v1/schedules` | List scheduled scans 🆕 |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/docs` | Interactive API documentation (Swagger UI) |

### Example: Start a scan via curl

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.example.com",
    "modules": ["bola", "auth", "injection", "fuzzer", "jwt", "secrets"],
    "timeout": 15
  }'
```

---

## 🐳 Docker Deployment

### Full Stack with PostgreSQL (Recommended)

```bash
docker compose up -d
```

This starts **3 services**:
- 🐘 **PostgreSQL 16** (port 5432) — production database
- ⚡ **Backend API** (port 8000) — connected to PostgreSQL
- 🎨 **Frontend** (port 3000) — Next.js dashboard

### Environment Variables for Docker

```env
APIGUARD_PG_PASSWORD=your_secure_password
APIGUARD_JWT_SECRET=your_jwt_secret
APIGUARD_CORS_ORIGINS=http://localhost:3000
APIGUARD_WEBHOOK_SLACK=https://hooks.slack.com/services/...
APIGUARD_JIRA_URL=https://yourcompany.atlassian.net
APIGUARD_JIRA_EMAIL=your@email.com
APIGUARD_JIRA_TOKEN=your_api_token
APIGUARD_GITHUB_REPO=owner/repo
APIGUARD_GITHUB_TOKEN=ghp_...
```

### Backend Only (SQLite)

```bash
docker build -t apiguard .
docker run -p 8000:8000 apiguard
```

---

## ⚙ Configuration

### Environment Variables

Create a `.env` file in the root directory (see `.env.example`):

```env
# Server
APP_VERSION=4.0.0
SECRET_KEY=your-secret-key-here

# Scan defaults
DEFAULT_TIMEOUT=10
DEFAULT_DELAY=0.1
MAX_RATE_REQUESTS=200

# Notifications (optional)
WEBHOOK_URL=https://hooks.slack.com/services/...
```

### Authentication

APIGuard uses JWT-based authentication with role-based access control (RBAC):

| Role | Permissions |
|------|-------------|
| **Admin** | Full access, manage users, configure system |
| **Analyst** | Run scans, view reports, manage findings |
| **Viewer** | Read-only access to dashboards and reports |

---

## ❓ FAQ

**Q: Is APIGuard safe to run on production APIs?**
> APIGuard sends HTTP requests to your API endpoints. While it's designed to be non-destructive, we recommend running scans against **staging/test environments** first. Some modules (like the fuzzer and rate limit tester) send high volumes of requests.

**Q: Do I need an OpenAPI spec?**
> No. If you provide just a base URL, APIGuard will attempt to auto-discover the spec. For best results, provide the spec URL (e.g., `https://api.example.com/swagger.json`).

**Q: Can I scan internal APIs?**
> Yes! As long as the machine running APIGuard has network access to the target API.

**Q: How are scans stored?**
> All scan results are persisted in local SQLite databases. No data is sent to external servers.

**Q: Can I integrate with CI/CD?**
> Yes. Use the `/api/v1/ci/scan` endpoint which returns SARIF format, compatible with GitHub Security, GitLab SAST, and most CI tools.

**Q: What APIs can I test?**
> REST APIs (JSON), GraphQL endpoints, and any HTTP-based service. WebSocket support is experimental.

---

## 📊 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.10+, FastAPI, Uvicorn, Pydantic |
| **Frontend** | Next.js 16, React 19, TypeScript, Tailwind CSS |
| **Charts** | Recharts |
| **Database** | SQLite (dev) / PostgreSQL 16 (prod) |
| **Auth** | JWT + bcrypt, RBAC, API Keys (SHA-256) |
| **Integrations** | Slack, Discord, Teams, Email, Jira Cloud, GitHub Issues |
| **Deployment** | Docker, Docker Compose, multi-stage builds |
| **Testing** | Pytest (60+ tests) |

---

## 📄 License

**Business Source License (BSL) 1.1**

Este software está licenciado bajo la **BSL 1.1**. Es libre para usar en entornos de pruebas (testing) y no comerciales. **Cualquier uso comercial o en entornos de producción requiere permiso explícito y una licencia comercial.** 

Para más detalles, consulta el archivo `LICENSE` en este repositorio.

---

<p align="center">
  <br/>
  <b>Creado por Jean Carlos Martinez con mucho amor y café. ☕❤️</b>
  <br/>
  <br/>
  <i>"La seguridad no es un producto, es un proceso."</i> — Bruce Schneier
</p>

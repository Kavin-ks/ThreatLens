# ThreatLens

**Evidence-driven application security assessment platform**

Built for Smart India Hackathon 2026 — NTRO problem statement: security assessment of the World Monitor application.

ThreatLens automates vulnerability detection across injection, cryptography, authentication, authorization, dependency, configuration, and SSRF/proxy attack surfaces. Every finding goes through a structured lifecycle — Detected → Confirmed → Remediated → Retested → Resolved — with machine-collected evidence attached at each step. Reports are generated as audit-ready PDFs.

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| Node.js | 20+ |
| Docker | optional (Postgres + Redis) |

### 1. Clone

```bash
git clone https://github.com/Kavin-ks/ThreatLens.git
cd ThreatLens
```

### 2. Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # edit DATABASE_URL and optional settings
uvicorn app.main:app --reload   # or: python -m app.main
```

- API: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

- App: `http://localhost:5173`

### 4. With Docker (Postgres + Redis)

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis
# Then run backend and frontend as above, pointing DATABASE_URL at Postgres
```

---

## Using ThreatLens

### Creating an assessment

1. Click **New Assessment** on the Dashboard.
2. Enter a project name and the **target path** (local source directory of the app you are assessing).
3. Optionally add a target URL for dynamic scanners.

### Running a scan

Open a project and click **Run Scan**. The scanner orchestrator auto-discovers all registered scanners, filters those whose `can_scan()` returns `true` for the target, and runs them in parallel. Results appear as findings in real time.

### Managing findings

Each finding has:

| Field | Description |
|-------|-------------|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Confidence** | CONFIRMED / LIKELY / POSSIBLE / FALSE_POSITIVE |
| **Status** | Full lifecycle from DETECTED to RESOLVED |
| **CVSS** | v3.1 vector and score (editable) |
| **Evidence** | File path, line number, code snippet, tool output |
| **History** | Every status transition with timestamp and actor |

**Finding lifecycle:**

```
DETECTED → VALIDATING → CONFIRMED → REMEDIATION → RETESTING → RESOLVED
                      ↘ REJECTED (false positive)
```

### Remediation and retest

1. On a confirmed finding, click **Add Remediation** — supply a description and optional patch diff.
2. Apply the fix to the target codebase.
3. Click **Run Retest** to re-scan and automatically resolve the finding if the vulnerability is gone.
4. For manually discovered findings (`scanner_id = "manual"`), pass `manual_resolve: true` in the retest request with notes documenting how you verified the fix — the finding resolves to RESOLVED and the evidence is preserved.

### Reports

Open a scan run and click **Generate Report** to produce a PDF that includes:
- Executive summary with severity counts
- Severity distribution chart
- Per-finding detail: CVSS breakdown, evidence, attack path, remediation, retest result
- False-positive appendix with rationale

### Settings

Visit **Settings** (`/settings`) to:
- Toggle between **dark and light themes** (preference saved in browser)
- Configure the backend API URL
- Check live backend connection status

---

## Architecture

```
ThreatLens/
├── backend/
│   ├── app/
│   │   ├── api/v1/           FastAPI routers
│   │   ├── models/           SQLAlchemy 2.0 models
│   │   ├── schemas/          Pydantic v2 request/response schemas
│   │   └── services/         Business logic, PDF generation, retest
│   └── scanners/             Modular scanner engine
│       ├── base.py           BaseScanner interface
│       ├── registry.py       Auto-discovery and registration
│       ├── orchestrator.py   Parallel scan coordination
│       ├── injection/        SQL, command, SSTI, path traversal
│       ├── crypto/           Weak ciphers, key sizes, hash algorithms
│       ├── authentication/   Missing auth, insecure sessions, rate limiting
│       ├── authorization/    Broken access control, IDOR
│       ├── dependencies/     CVE audit via lockfile analysis
│       ├── configuration/    Debug mode, CI secrets, insecure defaults
│       ├── headers/          HTTP security headers (dynamic)
│       └── api_security/     Unauthenticated endpoints, mass assignment
├── frontend/
│   ├── src/
│   │   ├── context/          ThemeContext (dark/light toggle)
│   │   ├── pages/            Dashboard, Projects, Findings, Settings, Help…
│   │   ├── components/       Shared UI: badges, layout, TopBar, Sidebar
│   │   └── api/              Typed API client (Axios + React Query)
│   └── tailwind.config.js
└── assessments/
    └── worldmonitor_security_report.pdf   Phase 11 assessment output
```

### Stack

| Layer | Technology |
|-------|-----------|
| Backend framework | FastAPI |
| ORM | SQLAlchemy 2.0 |
| Validation | Pydantic v2 |
| Database | SQLite (dev) / PostgreSQL (prod) |
| PDF generation | fpdf2 |
| Frontend | React 18 + TypeScript + Vite |
| Styling | Tailwind CSS v3 |
| State / data | React Query (@tanstack/react-query) |
| Icons | lucide-react |

---

## Scanner Framework

Add a scanner without touching core platform code:

```python
# backend/scanners/my_category/my_scanner.py
from scanners.base import BaseScanner, RawFinding
from scanners.registry import scanner_registry

@scanner_registry.register
class MyScanner(BaseScanner):
    scanner_id   = "my_scanner"
    name         = "My Custom Scanner"
    description  = "Detects XYZ vulnerability pattern."
    cwe_ids      = ["CWE-XXX"]
    category     = "my_category"
    severity     = "HIGH"

    def can_scan(self, target_path: str) -> bool:
        return True  # or check for specific files / frameworks

    def scan(self, target_path: str) -> list[RawFinding]:
        findings = []
        # ... analyse target_path ...
        findings.append(RawFinding(
            title="XYZ found",
            description="...",
            affected_file="src/foo.py",
            affected_line=42,
            evidence="...",
        ))
        return findings
```

Restart the backend — auto-discovery registers it automatically.

---

## Development

### Run tests

```bash
cd backend
source .venv/bin/activate
python -m pytest backend/tests/ -x -q
# Expected: 276 passed
```

### Type-check frontend

```bash
cd frontend
npm run type-check
```

### Alembic migrations

```bash
cd backend
alembic upgrade head          # apply migrations
alembic revision --autogenerate -m "description"   # generate new migration
```

---

## Development Status

| Phase | Status | Description |
|-------|--------|-------------|
| 1  | ✅ Complete | Architecture planning |
| 2  | ✅ Complete | Project foundation, scanner framework, UI shell |
| 3  | ✅ Complete | Scanner engine — injection, crypto, auth, authz |
| 4  | ✅ Complete | Dependency, configuration, headers, API scanners |
| 5  | ✅ Complete | Full frontend dashboard with React Query |
| 6  | ✅ Complete | World Monitor application assessment |
| 7  | ✅ Complete | PDF report generation |
| 8  | ✅ Complete | AI-assisted triage (opt-in, Anthropic API) |
| 9  | ✅ Complete | Verification pass — all 5 findings triaged |
| 10 | ✅ Complete | Final finding validation with PoC evidence |
| 11 | ✅ Complete | Remediation workflow, IP-pinning fix, retest |

**276 tests passing.** World Monitor assessment: 1 RESOLVED (MCP TOCTOU SSRF), 4 FALSE_POSITIVE (image-size, stream-json, uuid, CI postgres).

---

## Security Notice

ThreatLens performs **authorized security assessments only**. All dynamic testing targets local, controlled instances of the authorized application. Dynamic scanners will not contact any external host not listed in the project's authorized targets. Never use ThreatLens against production systems or infrastructure outside an explicitly authorized assessment scope.

AI-assisted triage is opt-in per finding. Source code and sensitive data are never sent to an external AI service without explicit configuration.

---

## License

Developed for SIH 2026. All rights reserved.

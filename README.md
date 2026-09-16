# ThreatLens

**Automated Application Security Assessment Platform**

Built for Smart India Hackathon 2026 — NTRO Problem Statement: Security Assessment of the World Monitor Application.

ThreatLens is an evidence-driven security assessment platform. Every finding goes through a structured lifecycle (Detected → Confirmed → Remediated → Retested → Resolved) with machine-collected evidence attached before a vulnerability is classified as confirmed.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- (Optional) Docker + Docker Compose for PostgreSQL and Redis

### 1. Clone and set up

```bash
git clone https://github.com/Kavin-ks/ThreatLens.git
cd ThreatLens
```

### 2. Backend setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # Edit .env as needed
python -m app.main              # OR: uvicorn app.main:app --reload
```

Backend runs at: http://localhost:8000  
API docs: http://localhost:8000/docs

### 3. Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at: http://localhost:5173

### 4. Run with Docker (PostgreSQL + Redis)

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis
# Then run backend and frontend as above, with DATABASE_URL pointing to Postgres
```

---

## Architecture

```
ThreatLens/
├── backend/              FastAPI + SQLAlchemy + Celery
│   ├── app/              Application core (API, models, services)
│   └── scanners/         Modular scanner engine
│       ├── base.py       BaseScanner interface
│       ├── registry.py   Scanner discovery and registration
│       └── [category]/   One directory per vulnerability category
├── frontend/             React 18 + TypeScript + Vite + Tailwind CSS
└── docker-compose.yml    Production services
```

See [docs/architecture.md](docs/architecture.md) for the full system design.

---

## Development Status

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Architecture planning |
| Phase 2 | ✅ Complete | Project foundation, scanner framework, UI shell |
| Phase 3 | 🔲 Pending | Scanner engine + first scanners |
| Phase 4 | 🔲 Pending | Additional scanners + validation |
| Phase 5 | 🔲 Pending | Full frontend dashboard |
| Phase 6 | 🔲 Pending | World Monitor assessment |
| Phase 7 | 🔲 Pending | Report generation |

---

## Scanner Framework

New vulnerability scanners are added by:
1. Creating a Python file in `backend/scanners/<category>/`
2. Subclassing `BaseScanner`
3. Implementing `can_scan()`, `scan()`, and optionally `validate()` and `collect_evidence()`
4. Decorating with `@scanner_registry.register`

No changes to core platform code required. See `backend/scanners/base.py` for the interface.

---

## Security Notice

ThreatLens performs authorized security assessments only. All dynamic testing must target local, controlled instances of the authorized application. Never use ThreatLens against production systems or infrastructure outside an explicitly authorized assessment scope.

---

## License

Developed for SIH 2026. All rights reserved.

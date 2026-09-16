.PHONY: help backend frontend install test lint clean docker-up docker-down migrate

help:
	@echo "ThreatLens Development Commands"
	@echo ""
	@echo "  setup         Install all dependencies (backend + frontend)"
	@echo "  backend       Start the FastAPI backend (dev mode)"
	@echo "  frontend      Start the React frontend (dev mode)"
	@echo "  test          Run all tests"
	@echo "  test-backend  Run backend tests only"
	@echo "  migrate       Run database migrations"
	@echo "  docker-up     Start Docker services (Postgres + Redis)"
	@echo "  docker-down   Stop Docker services"
	@echo "  clean         Remove build artifacts and caches"

setup:
	cd backend && python -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
	cd frontend && npm install

backend:
	cd backend && .venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd frontend && npm run dev

test: test-backend

test-backend:
	cd backend && .venv/bin/pytest tests/ -v --tb=short

migrate:
	cd backend && .venv/bin/alembic upgrade head

migrate-create:
	cd backend && .venv/bin/alembic revision --autogenerate -m "$(msg)"

docker-up:
	docker compose -f docker-compose.dev.yml up -d postgres redis

docker-down:
	docker compose -f docker-compose.dev.yml down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	cd frontend && rm -rf dist node_modules/.vite 2>/dev/null || true

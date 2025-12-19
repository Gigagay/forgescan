# ForgeScan

Short description
- ForgeScan is a web-based security scanning platform that runs vulnerability scans, aggregates findings, and provides dashboards, CI integration, and background workers for asynchronous processing.

Primary capabilities
- Run vulnerability scans against targets (HTTP repos/services).
- Store scan results and findings in PostgreSQL.
- Provide REST API (FastAPI) and WebSocket endpoints.
- Background processing via Celery and Redis.
- CI/CD integration (e.g. GitHub) to run scans and post results.
- Frontend SPA (Vite/React) for dashboards and reports.
- Exportable reports (CSV/other formats).

Architecture overview
- Backend: FastAPI + SQLAlchemy (async), Celery workers for async tasks.
- Database: PostgreSQL (alpine image in docker-compose).
- Broker & cache: Redis.
- Frontend: Vite + React served in dev mode (3000).
- Deployment: Docker / docker-compose for local development.

Key files / folders
- backend/app — FastAPI application and services.
- backend/app/main.py — application entry (lifespan, middleware).
- backend/app/db — database models and migrations (alembic).
- backend/app/api — REST API endpoints and integrations.
- backend/app/workers — Celery tasks.
- backend/requirements.txt — pinned Python deps.
- frontend — React frontend (Vite).
- docker-compose.yml — local dev stack (Postgres, Redis, backend, worker, frontend).

Quick start (local dev, Windows / PowerShell)
1) Prereqs
   - Docker Desktop (for docker-compose) OR Python 3.11+ + virtualenv.
   - Git, Node.js (for frontend), PostgreSQL client (optional).

2) Using docker-compose (recommended for local dev)
   - From repo root:
     powershell
     docker-compose -f forgescan/docker-compose.yml up --build
   - Tail logs:
     powershell
     docker-compose -f forgescan/docker-compose.yml logs -f backend

3) Running backend locally (without Docker)
   - Create venv and install:
     powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     pip install -r backend/requirements.txt
   - Set environment (example .env in backend/):
     - POSTGRES_DSN, REDIS_URL, SECRET_KEY, other settings per backend/app/core/config.py
   - DB migrations:
     powershell
     cd backend
     alembic upgrade head
   - Start dev server:
     powershell
     uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

4) Running tests
   - From backend folder inside venv:
     powershell
     pytest -q

Common troubleshooting & debugging notes
- FastAPI import/middleware collisions
  - Avoid importing middleware objects that shadow names used by FastAPI (e.g. audit_log_middleware).
  - If you see "object is not awaitable" when starting requests, check whether an async function is actually sync. In main.py we detect sync vs async for AuditLogger.log_event and run sync calls in a threadpool.

- AuditLogger sync vs async
  - If AuditLogger.log_event is synchronous, awaiting it will raise. Prefer making AuditLogger async or adapt call site:
    - Use inspect.iscoroutinefunction(...) and run synchronous call via asyncio.get_running_loop().run_in_executor(...). See backend/app/main.py for pattern implemented.

- Database connection failures
  - Ensure POSTGRES_* env vars match docker-compose or your local Postgres.
  - Use pg_isready or psql to confirm connectivity.
  - For migrations, ensure alembic.ini and SQLALCHEMY_DATABASE_URL point to the same DB.

- Mutable JSON defaults in models/migrations
  - Avoid Python literal mutable defaults (e.g. default={}/default=[]) in models and migrations; use callables (default=list/default=dict) or server_default to prevent shared state.

- Celery worker issues
  - Confirm Redis is reachable and CELERY_BROKER_URL/RESULT_BACKEND are set.
  - Worker logs helpful: docker-compose logs -f worker

- Docker-compose & ports
  - docker-compose exposes DB/Redis ports for local dev. Do not expose these in production.
  - If ports conflict (5432/6379), stop local services or change ports in docker-compose.yml.

- Frontend common issues
  - When exporting binary responses (CSV), axios returns response.data – ensure responseType: 'blob' and use response.data to createObjectURL.
  - React list rendering: avoid using array index as key; prefer stable ids to avoid UI bugs.

Useful commands (Windows / PowerShell)
- Create branch, commit, push:
  powershell
  git checkout -b fix/your-branch
  git add .
  git commit -m "describe change"
  git push -u origin HEAD

- Run backend dev server:
  powershell
  cd backend
  .\.venv\Scripts\Activate.ps1
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

- Run migrations:
  powershell
  cd backend
  alembic revision --autogenerate -m "describe"
  alembic upgrade head

- Inspect docker-compose services:
  powershell
  docker-compose -f forgescan/docker-compose.yml ps
  docker-compose -f forgescan/docker-compose.yml logs -f backend

Dependency notes
- See backend/requirements.txt for pinned Python packages. Update carefully and test (especially SQLAlchemy, FastAPI, pydantic versions).

When to update code / debug
- Update dependencies when a security patch or required feature is released. Run tests and smoke-test migrations locally before pushing.
- Update migrations when DB schema changes. Never edit applied migrations on production.
- Debug by reproducing locally with docker-compose, inspect logs, and run backend with --reload to get full stack traces.

Contributing & style
- Keep functions small and prefer explicit transactions for DB writes (use async with session.begin()).
- Avoid catching bare Exception unless re-raising after logging.
- Keep sensitive config in .env and do not commit secrets.

If you want, I can:
- Create the README file in your repo and stage a commit.
- Generate a checklist script to validate local environment and common health checks.

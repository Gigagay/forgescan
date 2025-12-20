# ForgeScan

ForgeScan is a web-based security scanning platform: it runs vulnerability scans, stores & aggregates findings, provides dashboards and CI integration, and processes jobs in background workers.

Important pieces
- Backend: FastAPI (async) + SQLAlchemy (async) + Alembic migrations.
- Database: PostgreSQL (data persisted).
- Broker & cache: Redis (Celery broker/worker state).
- Workers: Celery for background tasks.
- Frontend: Vite + React (TypeScript).
- Local orchestration: docker-compose (services: postgres, redis, backend, worker, frontend).

Quick start (local dev)
1. Prereqs
   - Docker Desktop (Windows) OR Python 3.11+, Node 18+, Git.
2. Build & run (recommended)
   - From repo root:
     powershell
     docker-compose -f forgescan/docker-compose.yml up -d --build
   - View logs:
     docker-compose -f forgescan/docker-compose.yml logs -f backend
3. Backend local (no Docker)
   powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   Set env vars (see backend/.env.example) and run:
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Migrations & DB
- Create / update DB schema:
  cd backend
  alembic upgrade head
- Avoid editing applied migrations on production. Prefer new migration scripts for schema changes.

Testing
- Backend:
  cd backend
  .\.venv\Scripts\Activate.ps1
  pytest -q
- Frontend:
  cd frontend
  npm install
  npm run build
  npm run dev

Common troubleshooting
- "object is not awaitable" in middleware: audit logging may be synchronous. We've implemented detection and a safe execution path; prefer making AuditLogger async.
- TypeScript build errors: check for stray characters or comments in JSON/TSX files.
- DB connectivity/migrations: ensure POSTGRES_* env vars match docker-compose.
- Exposed DB/Redis ports: in production do not expose; use internal networking or secrets management.

Security & maintenance
- Keep secrets out of repo (use .env and .env.example).
- Use non-root users in Docker images (applied).
- Use server_default or callable defaults for JSON columns to avoid shared mutable defaults (applied to models/migrations).
- Add CI jobs for lint/test/build on PRs.

Next recommended steps (prioritized)
1. Make AuditLogger fully async (preferred) and use async DB client for writes.
2. Run full test suite and inspect failing tests; fix compatibility shims (pydantic/email-validator) if necessary.
3. Replace frontend stubs added during build with real auth/API implementations.
4. Harden production configuration: secrets store, remove local port mappings for DB, enable TLS.

If you want, I will:
- Make AuditLogger async (I prepared a compatible change above).
- Prepare and run a focused grep patch to replace other mutable defaults across repo.
- Help fix any failing tests next (share pytest output).

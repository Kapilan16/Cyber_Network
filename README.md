# Cyber Network — Cybersecurity Data-Reasoning Platform

> **Stage 1** — Analyst dashboard and end-to-end demo workflow

See [STAGE1_STATUS.md](STAGE1_STATUS.md) for implemented behavior, limitations, and the Stage 2 backlog.

---

## Project Structure

```
Cyber Network/
├── backend/                  # FastAPI · Python 3.11 · SQLAlchemy 2.x
│   ├── app/
│   │   ├── main.py           # Application factory
│   │   ├── core/
│   │   │   ├── config.py     # Pydantic-Settings (reads .env)
│   │   │   ├── database.py   # SQLAlchemy engine + session dependency
│   │   │   └── security.py   # bcrypt hashing + JWT sign/verify
│   │   ├── models/
│   │   │   └── user.py       # User ORM model (id, email, role, created_at)
│   │   └── api/
│   │       ├── deps.py       # get_current_user / get_current_admin deps
│   │       └── v1/
│   │           ├── router.py
│   │           └── endpoints/
│   │               ├── health.py  # GET /api/health
│   │               └── auth.py    # POST register/login/refresh, GET /me
│   ├── alembic/
│   │   └── versions/
│   │       └── 0001_create_users.py   # users table migration
│   ├── tests/
│   │   ├── conftest.py       # SQLite in-memory fixtures
│   │   └── test_auth.py      # 13 tests (register/login/refresh/me)
│   ├── pytest.ini
│   ├── alembic.ini
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                 # React 19 · Vite · TypeScript
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthContext.tsx   # Token in memory (useRef), authFetch wrapper
│   │   ├── pages/
│   │   │   ├── AuthPage.tsx      # Login + Register form (animated tabs)
│   │   │   └── AuthPage.css
│   │   ├── main.tsx
│   │   ├── App.tsx           # Auth gate → Dashboard or AuthPage
│   │   └── index.css         # Cybersecurity dark theme
│   ├── nginx.conf            # SPA routing + /api proxy
│   └── Dockerfile
│
├── infra/
│   └── docker-compose.yml    # postgres:16, backend, frontend
│
├── .env.example              # Template — copy to .env, fill in values
├── .gitignore
└── README.md
```

---

## Milestone Progress

### ✅ Milestone 1 — Scaffolding & Environment Wiring
- FastAPI + Uvicorn backend, React + Vite frontend
- PostgreSQL 16 via Docker Compose
- `GET /api/health`, Swagger UI, CORS, Alembic wired up

### ✅ Milestone 2 — JWT Authentication
- SQLAlchemy `User` model (`analyst` / `admin` roles)
- Alembic migration `0001_create_users`
- `POST /api/auth/register` — create account
- `POST /api/auth/login` — returns access + refresh JWT
- `POST /api/auth/refresh` — rolling refresh token
- `GET /api/auth/me` — current user info
- `get_current_user()` + `get_current_admin()` FastAPI dependencies
- Password hashing via **bcrypt** directly (compatible with bcrypt ≥ 4.x)
- JWT signing via **python-jose**, secret from env
- Frontend: `AuthContext` (token in memory, never localStorage), login/register form, auth gate
- 13/13 pytest tests passing (SQLite in-memory, no Postgres needed)

### 🔲 Milestone 3 — Network Data Ingestion *(next)*
- `NetworkEvent` model + migration
- `POST /api/events` (bulk ingest), `GET /api/events` (paginated)
- Protected routes (analyst+)

### 🔲 Milestone 4 — Threat Detection Engine
- Rule-based anomaly detection
- `ThreatAlert` model + endpoints
- Background scoring on ingest

### 🔲 Milestone 5 — AI Reasoning Layer
- Gemini/OpenAI integration via `AI_API_KEY`
- `POST /api/analyze` — natural-language threat summary
- Streaming response (SSE)

### 🔲 Milestone 6 — Dashboard & Visualisation
- Real-time event feed
- Charts: events/min, top IPs, protocol breakdown
- Role-gated UI

### 🔲 Milestone 7 — Hardening & CI
- Rate limiting on auth endpoints
- Refresh token blocklist (Redis)
- GitHub Actions: pytest + docker build

---

## Quick Start (Docker Compose) 🐳

### Prerequisites
- Docker Desktop ≥ 4.x with Compose V2

### 1 — Clone & configure environment

```bash
cp .env.example .env
# Edit .env — set JWT_SECRET to a long random string
```

### 2 — Boot the full stack

```bash
cd infra
docker compose up --build
```

Services start in order:
1. **postgres** — waits until `pg_isready` passes
2. **backend** — runs `alembic upgrade head`, then starts uvicorn
3. **frontend** — waits until backend health check passes, serves via nginx

### 3 — Verify

| URL | What you see |
|-----|-------------|
| `http://localhost:3000` | Login / Register form |
| `http://localhost:3000` (after login) | Dashboard with user email + role |
| `http://localhost:8000/api/health` | `{"status":"ok"}` |
| `http://localhost:8000/api/docs` | Swagger UI (all auth endpoints) |

The backend seeds demo accounts, rules, MITRE techniques, and 20 analyzed submissions on first boot. Public registration always creates an analyst account.

---

## Local Development (no Docker)

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Run Tests

```bash
cd backend
.venv\Scripts\python.exe -m pytest tests/ -v
# 13 passed — no Postgres required (uses SQLite in-memory)
```

### Frontend

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

### Database Migrations (Alembic)

```bash
cd backend
alembic upgrade head          # apply all migrations
alembic revision --autogenerate -m "describe_change"
alembic downgrade -1
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `JWT_SECRET` | ✅ | Secret key for signing JWTs |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | ⬜ | Default: 30 minutes |
| `REFRESH_TOKEN_EXPIRE_MINUTES` | ⬜ | Default: 10080 (7 days) |
| `AI_API_KEY` | ⬜ | API key for AI provider (Milestone 5) |
| `ENVIRONMENT` | ⬜ | `development` or `production` |

> **Never commit `.env`** — only `.env.example` is tracked.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI 0.115 · Uvicorn · Python 3.11 |
| ORM | SQLAlchemy 2.x · Alembic |
| Database | PostgreSQL 16 |
| Auth | python-jose (JWT) · bcrypt |
| Validation | Pydantic v2 · pydantic-settings |
| Frontend | React 19 · Vite · TypeScript |
| Serving | Nginx 1.27 (production) |
| Containers | Docker Compose V2 |
| Testing | pytest · SQLite in-memory |

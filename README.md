# Cyber Network

Cyber Network is a security-operations demo application for triage, threat detection, and analyst workflow tracking. The project combines a FastAPI backend, a Vite/React frontend, and a PostgreSQL database with pgvector support for semantic search and rule-driven findings.

The application builds on Stage 1's secure auth, analyst dashboard, submission intake, rule evaluation, MITRE mapping, and demo seed data. New submissions are correlated to memory nodes in a background task using their findings and qualifying recent embedding matches. A periodic scan flags recurring memory patterns as campaigns and marks stale nodes dormant.

---

## What is included

- Analyst and admin authentication flow
- Protected dashboard and navigation shell
- New submission intake form
- Automated rule evaluation against submitted artifacts
- Findings and severity summaries
- MITRE ATT&CK technique linkage
- Semantic-search endpoint powered by the configured embedding provider
- CPU-local MiniLM embeddings by default, with configurable OpenAI-compatible and explicit feature-hash providers
- Fixed 1536-dimensional vectors across local and central storage; MiniLM's native 384 values are zero-padded
- FAISS in-memory nearest-neighbor acceleration backed by pgvector as the source of truth
- Opt-in, org-local IOC enrichment via read-only VirusTotal and AbuseIPDB lookups
- On-demand, cached AI analyst recommendations with validated JSON and an advisory-only warning
- Rule-based early warnings and analytics for risk, MITRE tactic volume, and enrichment signals
- Long-term memory nodes and correlation links with authenticated read endpoints
- Recurring campaign detection and `GET /api/memory/campaigns`
- Opt-in anonymized sharing to an isolated central network service
- Org-local Network settings and a central aggregate-only admin dashboard
- Multi-organization demo seed with live central ingest and cross-org search verification
- Docker Compose setup for the full stack
- Backend test suite and frontend production build

---

## Project structure

```text
Cyber Network/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── endpoints/
│   │   │       │   ├── auth.py
│   │   │       │   ├── dashboard.py
│   │   │       │   ├── health.py
│   │   │       │   ├── memory.py
│   │   │       │   ├── mitre.py
│   │   │       │   ├── rules.py
│   │   │       │   ├── search.py
│   │   │       │   └── submissions.py
│   │   │       └── router.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── database.py
│   │   │   └── security.py
│   │   ├── embeddings/
│   │   │   └── client.py
│   │   ├── correlation/
│   │   │   └── engine.py
│   │   ├── models/
│   │   │   ├── memory.py
│   │   │   ├── mitre_technique.py
│   │   │   ├── raw_submission.py
│   │   │   ├── rule.py
│   │   │   └── user.py
│   │   ├── rules/
│   │   │   ├── evaluator.py
│   │   │   └── seed_rules.py
│   │   └── main.py
│   ├── alembic/
│   ├── scripts/
│   │   └── seed_demo.py
│   ├── tests/
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── alembic.ini
│   └── Dockerfile
├── central-server/
│   ├── app/                 # Independent organization registry API
│   ├── alembic/             # Central registry schema migrations
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   ├── vite.config.ts
│   ├── nginx.conf
│   └── Dockerfile
├── infra/
│   └── docker-compose.yml
├── .env.example
├── .gitignore
├── STAGE1_STATUS.md
├── README.md
└── LICENSE
```

---

## Technology stack

- Frontend: React + TypeScript + Vite
- Backend: FastAPI + SQLAlchemy + Alembic
- Database: PostgreSQL 16 + pgvector
- Authentication: JWT + bcrypt
- Validation: Pydantic
- Containerization: Docker + Docker Compose
- Testing: pytest

## Embedding provider

`EMBEDDING_PROVIDER` selects the embedding implementation:

- `local_sentence_transformers` (default): CPU inference with `sentence-transformers/all-MiniLM-L6-v2`. Model weights are downloaded on first startup/use and cached under the `huggingface_cache` Compose volume.
- `openai_compatible`: uses `EMBEDDINGS_API_URL`, `EMBEDDINGS_MODEL`, and `EMBEDDINGS_API_KEY`.
- `feature_hash`: retains the previous deterministic feature-hashing implementation. It is also the fallback if local model loading or inference fails.

All providers are fitted to the existing 1536-value vector width. MiniLM emits 384 values and zero-padding preserves cosine similarity for vectors produced by that same model. No pgvector dimension migration is needed. Network participants must use the same provider and model to share a compatible vector space; vector width alone does not make different embedding models comparable.
The central server uses the same `EMBEDDING_PROVIDER` and provider settings when rebuilding existing SharedIntel embeddings. Configure the same provider/model (and API credentials, when applicable) on central and each org-local instance before enabling network similarity search.

Compose images constrain PyTorch to its CPU-only wheel to avoid pulling GPU/CUDA runtime packages for this CPU inference workload.

New submission and rule-description embeddings use the selected provider. After changing the embedding provider/model, re-embed org-local vectors with:

```powershell
Set-Location backend
python scripts/reembed_local_vectors.py
```

For central shared-intel rows created with an older vector space, quiesce central writes and run:

```powershell
Set-Location central-server
python scripts/reembed_shared_intel.py
```

The central re-embedding utility uses the configured provider and model. It updates existing SharedIntel rows in one transaction and rolls back if embedding fails. Re-embed both org-local vectors and central SharedIntel rows after changing the provider/model; do not query across providers or models because equally sized vectors are not necessarily comparable.

Both the org-local and central services build an exact `IndexFlatIP` FAISS index from their stored vectors at startup, append newly persisted vectors, and rebuild every 24 hours to discard deleted or outdated IDs. Search validates candidate IDs and recomputes similarity from database-stored vectors. If an index is cold or FAISS is unavailable, search falls back to the existing pgvector path. `GET /api/search/semantic/benchmark` is an admin-only development/test endpoint for comparing local FAISS and pgvector query latency; it is not part of the UI.

## IOC enrichment

IOC enrichment is an explicit, org-local action on a submission's Enrichment tab or via `POST /api/submissions/{id}/enrich`. It extracts IPv4 addresses, domains, and MD5/SHA-1/SHA-256 hashes from sanitized text, queues VirusTotal lookups and IP-only AbuseIPDB lookups, and returns stored status through `GET /api/submissions/{id}/enrichment`. Configure `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY` in the org-local environment. Requests use read-only HTTPS APIs, sequential per-provider throttling (15 seconds for VirusTotal and 86.4 seconds for AbuseIPDB by default), bounded timeout/retry, and trimmed response summaries. Private/reserved IPs and internal-use domain suffixes are never sent. Enrichment records remain in the org-local database and are not included in central sharing payloads. Missing keys or provider failures mark results failed without affecting submission processing.

## Composite risk score

The org-local service stores a deterministic 0–100 risk score for each submission in `risk_scores`; `GET /api/submissions/{id}/risk-score` returns the score, band, component breakdown, and computation time. The score is the normalized weighted sum of three 0–100 signals: maximum finding severity (low 25, medium 50, high 75, critical 100), recurrence (similar prior submissions capped at five matches; central matches count at the configurable multiplier), and the worst completed threat-intelligence reputation score. Missing signals contribute zero. Default weights are 0.4/0.3/0.3 and can be changed with `RISK_WEIGHT_RULE_SEVERITY`, `RISK_WEIGHT_RECURRENCE`, and `RISK_WEIGHT_ENRICHMENT`; weights are normalized automatically. Bands are low 0–24, medium 25–49, high 50–74, and critical 75–100. Central lookup failures omit the network recurrence signal while preserving local recurrence scoring. Scores are refreshed after submission processing, rule evaluation, and completion of queued enrichment.

---

## Demo accounts

The seed process creates demo users automatically when the backend starts for the first time or when the seed script is run.

- Admin: `admin@cybernetwork.demo` / `Admin@Demo2025!`
- Analyst: `analyst@cybernetwork.demo` / `Analyst@Demo2025!`

Use the analyst account for the normal UI flow.

---

## Quick start with Docker

### Requirements

- Docker Desktop or Docker Engine with Compose
- Git

### Start the project

From the project root:

```bash
cd infra
docker compose --env-file ../.env up --build
```

This starts:

- PostgreSQL
- FastAPI backend
- React frontend via nginx
- Central organization registry API and its separate PostgreSQL database

Then open:

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/api/docs
- Health check: http://localhost:8000/api/health
- Central registration API docs: http://localhost:8100/api/docs
- Central health check: http://localhost:8100/api/central/health

The central registry is isolated from the org-local database. It creates its own
`central_postgres_data` volume and stores organization registration metadata and
hashed API keys; threat-intelligence sharing is not part of this milestone.
Before deploying beyond local development, set strong, unique
`CENTRAL_POSTGRES_PASSWORD`, `CENTRAL_SIGNING_SECRET`, and `CENTRAL_ADMIN_TOKEN`
values in `.env`. Compose defaults are for local development only.
Compose publishes the central API over plain HTTP for local development; in
production, place it behind a TLS-terminating HTTPS ingress and do not expose
its container port directly. The org-local client refuses an `http://`
`CENTRAL_SERVER_URL` outside development.

Register an org-local Stage 1 instance:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8100/api/central/orgs/register `
  -ContentType "application/json" `
  -Body '{"name":"Example SOC","contact_email":"soc@example.org"}'
```

The response includes the signed `api_key` once. Store it securely; the central
database retains only its SHA-256 hash. Central administrators can list the
non-sensitive organization name/status fields with:

```powershell
Invoke-RestMethod -Uri http://localhost:8100/api/central/orgs `
  -Headers @{ "X-Central-Admin-Token" = "<CENTRAL_ADMIN_TOKEN from .env>" }
```

After putting the returned key in the org-local `.env` as `CENTRAL_API_KEY`,
the local central client checks the registration using
`GET /api/central/orgs/me` with `Authorization: Bearer <api-key>`. Invalid keys
are rejected, suspended organizations are denied, and active organizations
default to 60 authenticated requests per 60-second window.

The org-local migration also creates a `Default Organization` and backfills
every existing user to its `org_id`, preserving existing accounts.

For org-local central authentication, set `CENTRAL_SERVER_URL` and the
one-time-issued `CENTRAL_API_KEY` in the org-local `.env`. Non-development
environments reject non-HTTPS central URLs. `backend/app/central_client.py`
provides authenticated identity checks with bounded retries and a circuit
breaker; local ingestion and analysis do not call or require the central
service, so central outages do not block existing Stage 1 workflows. Central
requests are rate-limited per organization (60 requests per 60 seconds by
default); the in-memory limiter is per server process.

External sharing is a separate, explicit opt-in. The org-local
`share_with_network` flag defaults to `false`; migration `0010` keeps all
existing organizations opted out. The
`backend/app/sharing/payload.py` builder checks that flag before reading a
submission and applies a second redaction pass for organization names,
usernames, hostnames, internal IP ranges, and non-allow-listed IOCs. Add
environment-specific CIDRs, hostnames, and usernames to
`SHARING_INTERNAL_RANGES`, `SHARING_INTERNAL_HOSTNAMES`, and
`SHARING_INTERNAL_USERNAMES` as comma-separated values. Raw IPs, hashes, URLs,
and domains are removed unless explicitly allow-listed; configured internal
ranges and hostnames remain blocked even when allow-listed. This milestone
builds payloads only and does not transmit threat intelligence.

When sharing is enabled for an organization, each completed local evaluation
queues an outbound submission as a FastAPI background task. The local API
response and local findings do not wait for the central service. The central
server authenticates the bearer key, validates the strict anonymized payload,
stores the vector in its isolated pgvector database, and deduplicates repeated
payloads per source organization. Central admins can query aggregate counts
only at `GET /api/central/intel/stats`; the response has no per-organization
breakdown. Authenticated organizations can search other organizations'
anonymized incidents through `POST /api/central/intel/search`; the requesting
organization's own records are excluded and source identifiers are never
included in results.

Network search is controlled explicitly by
`CENTRAL_ALLOW_READ_WITHOUT_CONTRIBUTION` on the central server. It defaults
to `true`, allowing any active authenticated organization to search the
anonymized pool even when `share_with_network=false`. Set it to `false` to
require at least one prior accepted contribution from the organization.
Searches exclude the caller's own submissions and
return only sanitized text, MITRE IDs, severity, and similarity—not source
organization identifiers.

### Stop the project

```bash
cd infra
docker compose stop
```

This stops the stack without deleting the database volume. Use `docker compose down -v` only if you want to reset the database completely.

---

## Local development without Docker

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Tests

```bash
cd backend
python -m pytest tests/ -q
```

Central service tests:

```bash
cd central-server
python -m pytest tests/ -q
```

---

## Environment variables

Copy the template file and fill in the values you need before deploying:

```bash
copy .env.example .env
```

Required values for real deployment:

- `DATABASE_URL`
- `JWT_SECRET`
- optional `OPENAI_API_KEY` or embedding provider settings if using a production semantic model

Analyst recommendations are optional and generated only when an analyst requests them.
Configure `AI_API_KEY`, `AI_API_URL` (HTTPS, OpenAI-compatible chat completions), and
`AI_MODEL` on the org-local backend. The request contains sanitized submission text and
available rule, risk, enrichment, and brief shared-network context. Provider output is
validated against a strict JSON schema before it is saved; malformed output is rejected.
Recommendations are cached per submission and are regenerated only through an explicit
request. They are advisory and do not execute response actions.

## Analytics and early warnings

The authenticated `GET /api/analytics/overview` endpoint and workspace Analytics page
summarize local risk-band counts, distinct submission counts by MITRE tactic (7/30 days),
the percentage of enriched IOCs with a positive reputation score, daily risk averages,
and active rule-based warnings. Analytics are scoped to the signed-in user's organization.
If network sharing is enabled for that organization, the page also compares local
all-time tactic counts with central aggregate technique counts; it does not disclose
other organizations' incident text.

`WARNING_WINDOW_HOURS` and `WARNING_THRESHOLD` control the rolling high/critical
submission rule (defaults: 24 hours and 3 submissions sharing a MITRE tactic or
technique). Scans run after risk-score calculation and periodically according to
`WARNING_SCAN_INTERVAL_SECONDS`; warnings age out of the active list after the configured
window.

Do not commit real secrets to GitHub.

---

## Deployment notes

This repository is structured as a monorepo, so the actual frontend app is in `frontend/` rather than the repo root.

For public web deployment:

- Deploy the frontend to Vercel with the root directory set to `frontend`
- Deploy the backend separately on a platform such as Render, Railway, Azure App Service, or a VPS
- Use a managed PostgreSQL instance with the pgvector extension enabled
- Set the frontend environment variable:

```bash
VITE_API_URL=https://your-backend-domain.com
```

Before production release, remove or disable the demo seed logic in `backend/scripts/seed_demo.py` and replace default demo credentials with your own secure values.

---

## Notes

- The app is already working in local Docker mode.
- The interactive seed is intended for demo use and is not a replacement for production data initialization.
- The semantic-search fallback is a deterministic local vector fallback for demo scenarios when no external embedding key is present.

See [STAGE1_STATUS.md](STAGE1_STATUS.md) for the implemented Stage 1 status and remaining follow-up work.

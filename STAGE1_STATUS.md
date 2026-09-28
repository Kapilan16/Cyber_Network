# Stage 1 Status

## Implemented

- JWT registration and login, in-memory frontend auth state, protected analyst pages, and role-aware backend dependencies.
- Public registration always creates an analyst. Admin accounts are provisioned by the demo seed or an operator; callers cannot self-assign admin.
- Analyst dashboard summary at `GET /api/dashboard/summary`: submissions today and this week, totals, open findings by severity, top MITRE tactics this week, rule counts, and embedding counts. Since Stage 1 has no finding-resolution lifecycle, every persisted finding is currently counted as open.
- Separate frontend routes for overview, submission intake, paginated submissions, submission detail, and semantic search. Submission detail includes raw and sanitized text plus findings and MITRE technique/tactic tags.
- Intake sanitizes submitted text, evaluates active rules, persists findings, and attempts embedding. The list shows sanitization and embedding status plus severity counts.
- Admin-only rule listing, seed, create, update, and delete endpoints. Analyst requests to create, update, or delete rules are rejected.
- Demo seed creates `admin@cybernetwork.demo` and `analyst@cybernetwork.demo`, seed rules and MITRE techniques, and 20 sample submissions with sanitization, rule evaluation, and embeddings. The seed is safe to rerun and executes after migrations when the backend container starts.
- With `EMBEDDINGS_API_KEY` unset, the app uses normalized deterministic feature-hash vectors so the demo intake/search path works offline. Configure a real OpenAI-compatible provider for production-quality semantic retrieval.

## Stubbed Or Limited

- Embedding and semantic-search quality is lexical feature hashing without a configured provider; it is a demo fallback, not a substitute for a semantic model.
- Rule evaluation and embeddings run synchronously in the request/startup process. Larger workloads need a background worker and retry queue.
- “Open” findings are an aggregate alias only; findings cannot yet be acknowledged, assigned, suppressed, or resolved.
- The dashboard is request/refresh driven; there is no live event stream or automatic refresh.
- Admin rule CRUD exists in the API but no rule-management UI is included.
- Demo login credentials are intended only for local development and must be rotated or removed before deployment.

## Stage 2 TODOs

- Add finding lifecycle, ownership/assignment, analyst comments, audit history, and resolution workflow.
- Move rule evaluation and embedding generation to durable background jobs with retries and observable failure states.
- Add supported model/provider configuration and quality tests for semantic retrieval; define the behavior when a provider is unavailable.
- Add production identity provisioning, stronger password policy, auth rate limits, refresh-token revocation, and audit logging.
- Add dashboard filters, time-range selection, pagination/aggregation performance checks, and live updates if required.
- Add admin rule management screens, rule validation/versioning, and safe re-evaluation on rule changes.
- Add end-to-end browser coverage and CI for Compose boot, migrations, authorization, intake, findings, semantic search, and dashboard aggregates.
- Review data retention, raw-submission access policy, encryption, backup/restore, and production secret management.

## Local Compose Smoke Path

From `infra/`, run `docker compose up --build`. The backend applies migrations and seeds demo data before reporting healthy. The frontend is served at `http://localhost:3000`; API docs are at `http://localhost:8000/api/docs`.

For the Stage 1 smoke test, register a new analyst account, log in, submit a security artifact, open the generated submission detail to inspect sanitization/findings/MITRE tags, search for related text, and return to the overview to inspect the summary. The seeded accounts are `admin@cybernetwork.demo` / `Admin@Demo2025!` and `analyst@cybernetwork.demo` / `Analyst@Demo2025!`.
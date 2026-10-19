# Stage 2 Status

Stage 2 implements long-term memory correlation, recurring-pattern detection, and an analyst-facing memory network. The current demo also includes the first central-network handoff needed to demonstrate the Stage 3 multi-organization path.

## Implemented

- SQLAlchemy models and Alembic migrations for memory nodes, correlation links, recurrence flags, and unique node signatures.
- Background correlation after submission evaluation, linking findings to rule and MITRE technique nodes and linking sufficiently similar recent embeddings to clusters.
- Periodic configurable recurrence scanning. Nodes meeting their recent-link threshold are flagged recurring; nodes with no links in their rolling window and stale `last_seen` are marked dormant.
- Authenticated, analyst-readable APIs for memory-node lists/details, recurring campaigns, and chronological paginated timelines. Analyst responses are scoped to submissions they own; no admin-only mutation endpoints are provided.
- Stage 1 dashboard campaign count and the authenticated Memory Network overview/detail timeline.
- Idempotent Stage 2 demo seed samples: six related finding-producing submissions are created with simulated dates across the last 21 days. Repeated PowerShell and phishing activity should produce at least four recurring nodes (two technique nodes and two rule nodes) at the default threshold.
- Idempotent central demo bootstrap registers/reuses Demo Network Alpha, Beta, and Gamma. The seed creates two local, sanitized, evaluated, embedded submissions per demo organization; Alpha and Beta opt in, while Gamma remains opted out.
- Opted-in demo submissions pass through the outbound anonymizer and are submitted to the independent central service using each demo org's authenticated key. The seed then searches as Beta and fails startup visibly if it cannot find Alpha's anonymized result or if an organization identifier appears in the search response.
- Org-local admin-only Network settings page to change the sharing opt-in and view the most recent delivery status/error and accepted-submission count. Delivery state is persisted per submission.
- Separate central admin view at `/central-admin`; it accepts the central admin token in memory and displays registered organization name/status plus aggregate intel counts and technique distribution. It does not render raw shared intel or source-org attribution.
- Local CPU MiniLM embedding provider (384 native values zero-padded to the stable 1536 pgvector width), configurable OpenAI-compatible alternative, and explicit feature-hash provider/fallback. Submission text, semantic queries, rule descriptions, and shared-intel payloads share the selected provider.
- Compose starts the backend only after both databases and the central API are healthy, so the first-boot network seed can complete before the app reports ready.

## Stubbed and current limitations

- Correlation similarity (0.85) and time window (30 days) are environment-backed defaults, not organization-level configuration.
- Recurrence thresholds/windows are stored on each node with defaults of 3 and 30 days. There is no manual override, campaign dismissal, or mark-dormant action.
- Campaign summaries are generated from node type/key and recent link count; they are not AI-generated.
- The periodic recurrence scan runs in each API process. Multi-worker deployments can run redundant scans; scans are idempotent but are not coordinated by a scheduler/leader lock.
- Demo campaign records are seeded once per analyst account and are not re-timestamped on subsequent starts. After their rolling window elapses, they become dormant naturally.
- The central demo identities and submissions are simulated fixtures in the single org-local Compose database. The seed uses one-time central keys in memory; real organizations still need a separately deployed local instance and its own `CENTRAL_API_KEY` configuration.
- Central network contribution is opt-in, but key provisioning/rotation and an organization deactivation workflow are not provided by the local Network settings page. Central status changes remain an operator action.
- The outbound anonymization denylist is static configuration; it is not learned from local traffic. This is defense-in-depth, not a guarantee that arbitrary text is safe to share; production deployments need org-specific review and HTTPS.
- Every contributing deployment must use the same embedding provider/model; padding to a shared width does not make different model spaces comparable. Re-embed existing local and central rows after switching vector spaces using `backend/scripts/reembed_local_vectors.py` and `central-server/scripts/reembed_shared_intel.py`.
- Network sync status stores the latest attempt result and accepted count; there is no retry queue or central-delivery reconciliation job yet.

## Stage 3 entry point (S3-M1 through S3-M6)

Stage 3 attaches to this implementation at the central-network boundary: organization registration, outbound anonymization, central ingestion, and anonymized search are present. The existing S3-M1–S3-M6 AI Cyber Intelligence work should continue from this baseline rather than rebuilding Stage 2 memory correlation.

| Milestone | Entry point |
|---|---|
| S3-M1 — Central network foundation | Separate central service/database, organization registration, signed org keys, rate limiting, and aggregate-only central admin APIs are implemented. |
| S3-M2 — Privacy-safe sharing | Local opt-in and second-pass anonymized payload builder are implemented; this milestone should extend policy/configuration and verification rather than replace them. |
| S3-M3 — Central intelligence ingestion | Authenticated ingest, deduplication, pgvector storage, and aggregate stats are implemented. Production retention, quotas, and abuse controls remain follow-up work. |
| S3-M4 — Cross-org intelligence search | Authenticated cosine search, caller exclusion, explicit provenance groups, and read-without-contribution policy are implemented. |
| S3-M5 — Production interoperability | Next hardening point: HTTPS ingress, key provisioning/rotation, model/vector compatibility checks, and operational delivery retry/reconciliation. |
| S3-M6 — AI Cyber Intelligence | Attach enrichment, analyst-facing campaign intelligence, and alert/notification behavior to central search and Stage 2 campaigns, with explicit privacy and audit controls. |

Cross-user correlation, per-organization thresholds, campaign lifecycle actions, alerting, and a coordinated multi-worker scheduler remain later candidates.

## Demo verification

From `infra/`, build and start the stack:

```powershell
docker compose --env-file ../.env up --build -d
docker compose ps
```

The backend migrates its org-local database, seeds Stage 2 campaigns, bootstraps the fixed demo organizations using `CENTRAL_ADMIN_TOKEN`, and uploads the opted-in anonymized demo data before it becomes healthy. The central admin token must match between the central service and the backend; use matching values from `.env`.
The regular org-local accounts remain available. Seeded org-specific admin accounts are `network-alpha-admin@cybernetwork.demo`, `network-beta-admin@cybernetwork.demo`, and `network-gamma-admin@cybernetwork.demo`; each uses `Admin@Demo2025!` and opens Network settings for that demo org.

The backend runs Alembic migrations and the demo seed on startup. Sign in to the frontend at `http://localhost:3000` with `analyst@cybernetwork.demo` / `Analyst@Demo2025!`, then:

1. Open **Memory Network** and confirm recurring technique/rule nodes appear near the top with active badges.
2. Open **Network settings** as the demo admin to see sharing opt-in and delivery status/count.
3. Open **Central admin** and enter the configured central admin token. Confirm only org name/status and aggregate counts are shown.
4. Open Semantic search, enable network search, and confirm results appear in the separate organization/network groups. The seed logs a Beta-to-Alpha search assertion on startup.
5. Open a memory node and confirm its timeline shows the simulated submission dates and linked findings.

The read-only API checks can also be made with an analyst access token:

```text
GET http://localhost:8000/api/memory/campaigns
GET http://localhost:8000/api/memory/nodes
GET http://localhost:8000/api/memory/nodes/{id}/timeline?page=1&page_size=20
```

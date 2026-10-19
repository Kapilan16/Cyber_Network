# Stage 3 status

Stage 3 adds local IOC enrichment, deterministic risk scoring, cached advisory
recommendations, analytics, and rule-based early warnings on top of the Stage 2
semantic search and central sharing path.

## Implemented

- Local CPU sentence-transformer embeddings with feature-hash fallback and an optional
  OpenAI-compatible provider; local and central vectors use the same 1536-wide schema.
- FAISS nearest-neighbor indexes for local submissions and central SharedIntel, with
  PostgreSQL/pgvector retained as source of truth and periodic index rebuilds.
- Org-local, read-only VirusTotal and AbuseIPDB enrichment for extracted IOCs. Provider
  requests are paced, private/internal indicators are not sent, and only trimmed
  summaries are persisted.
- Deterministic 0–100 composite risk scores from rule severity, recurrence, and the
  strongest available enrichment reputation. Default weights are static configuration,
  not learned.
- On-demand OpenAI-compatible response recommendations using sanitized evidence. The
  provider must return schema-valid JSON; results are cached per submission and remain
  advisory rather than executing response actions.
- `GET /api/analytics/overview` and a workspace Analytics page with risk bands, 7/30-day
  tactic counts, a daily risk trend, enrichment hit rate, optional aggregate network
  context, and active warnings.
- Rolling-window early warnings when the configured threshold of high/critical-risk
  submissions share a MITRE tactic or technique. Warnings are persisted, refreshed by
  scans, and naturally expire from the active view after the window.

## Current limitations / stubs

- FAISS rebuilds are periodic (daily by default), not continuously reconciled with every
  deletion or vector update. Database verification/fallback remains the correctness path.
- Threat-intelligence integrations are limited to VirusTotal and AbuseIPDB. Other feeds,
  commercial tiers, and richer reputation normalization are not implemented.
- Risk weights and thresholds are configured constants, not learned or auto-calibrated.
- Recommendations require an operator-configured OpenAI-compatible endpoint and API
  key. No local model training, automated containment, or execution of suggested
  actions is implemented.
- Network tactic comparison depends on opt-in sharing and availability of the central
  aggregate endpoint; central data is all-time while local tactic summaries show the
  selected 7/30-day windows.
- Warnings are deterministic thresholds over currently stored risk scores and rule/MITRE
  matches; there is no statistical anomaly detection or deduplication across changing
  MITRE taxonomies beyond the current tactic/technique keys.

## Next-stage candidates

- Add transactional/outbox-backed index maintenance and operational FAISS health,
  compaction, and rebuild observability.
- Add configurable additional threat-intel providers with provider-specific quotas,
  provenance, freshness, and score normalization.
- Add analyst feedback for recommendation quality and warning disposition before
  considering any calibrated scoring changes.
- Add warning acknowledgement/resolution workflows, notification routing, and
  configurable per-organization rule policies.
- Add retention controls and privacy review for enriched IOCs, recommendation prompts,
  and centrally shared aggregate comparisons.
- Add production observability for task failures, API latency, enrichment queue depth,
  and central-service availability.

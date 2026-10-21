/**
 * SubmissionDetail — full detail view for a single submission.
 * Shows: metadata header, raw vs sanitized text comparison, and FindingsPanel.
 * All API calls, hooks, state, and logic are unchanged. Only presentation updated.
 */
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import FindingsPanel from './FindingsPanel'
import './SubmissionDetail.css'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SubmissionFull {
  id: number
  user_id: number
  source_type: string
  submitted_at: string
  sanitization_status: string
  sanitized_text: string | null
  raw_text: string
  embedding_status: string
  sanitization_meta?: {
    redaction_count: number
    flag_count: number
    was_truncated: boolean
    warnings: string[]
  } | null
}

interface EnrichmentResult {
  id: number
  submission_id: number
  ioc_type: 'ip' | 'domain' | 'hash'
  ioc_value: string
  source: 'virustotal' | 'abuseipdb'
  reputation_score: number | null
  raw_response_summary: Record<string, unknown> | null
  queried_at: string | null
  status: 'pending' | 'complete' | 'failed'
}

interface Recommendation {
  id: number
  submission_id: number
  recommendation_text: string | null
  suggested_actions: string[] | null
  confidence: number | null
  generated_at: string | null
  model_used: string | null
  status: 'pending' | 'complete' | 'failed'
  error: string | null
}

interface Props {
  submissionId: number
  onBack: () => void
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function sanStatusClass(status: string): string {
  const map: Record<string, string> = {
    clean: 'sd-badge-clean',
    redacted: 'sd-badge-redacted',
    flagged: 'sd-badge-flagged',
    pending: 'sd-badge-pending',
  }
  return map[status] ?? 'sd-badge-pending'
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function SubmissionDetail({ submissionId, onBack }: Props) {
  const { authFetch } = useAuth()
  const [sub, setSub]         = useState<SubmissionFull | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)
  const [tab, setTab]         = useState<'content' | 'findings' | 'enrichment' | 'recommendation'>('content')
  const [enrichments, setEnrichments]                     = useState<EnrichmentResult[]>([])
  const [enrichmentLoading, setEnrichmentLoading]         = useState(false)
  const [enrichmentError, setEnrichmentError]             = useState<string | null>(null)
  const [recommendation, setRecommendation]               = useState<Recommendation | null>(null)
  const [recommendationLoading, setRecommendationLoading] = useState(false)
  const [recommendationError, setRecommendationError]     = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await authFetch(`/api/submissions/${submissionId}`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setSub(await r.json() as SubmissionFull)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load submission')
    } finally {
      setLoading(false)
    }
  }, [authFetch, submissionId])

  const loadEnrichment = useCallback(async () => {
    setEnrichmentLoading(true)
    setEnrichmentError(null)
    try {
      const response = await authFetch(`/api/submissions/${submissionId}/enrichment`)
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      setEnrichments(await response.json() as EnrichmentResult[])
    } catch (e: unknown) {
      setEnrichmentError(e instanceof Error ? e.message : 'Failed to load enrichment results')
    } finally {
      setEnrichmentLoading(false)
    }
  }, [authFetch, submissionId])

  const runEnrichment = async () => {
    setEnrichmentLoading(true)
    setEnrichmentError(null)
    try {
      const response = await authFetch(`/api/submissions/${submissionId}/enrich`, { method: 'POST' })
      if (!response.ok) throw new Error(`Enrichment request failed: HTTP ${response.status}`)
      const data = await response.json() as { results: EnrichmentResult[] }
      setEnrichments(data.results)
    } catch (e: unknown) {
      setEnrichmentError(e instanceof Error ? e.message : 'Failed to queue enrichment')
    } finally {
      setEnrichmentLoading(false)
    }
  }

  const loadRecommendation = useCallback(async () => {
    setRecommendationError(null)
    try {
      const response = await authFetch(`/api/submissions/${submissionId}/recommendation`)
      if (response.status === 404) { setRecommendation(null); return }
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      setRecommendation(await response.json() as Recommendation)
    } catch (e: unknown) {
      setRecommendationError(e instanceof Error ? e.message : 'Failed to load recommendation')
    }
  }, [authFetch, submissionId])

  const runRecommendation = async () => {
    setRecommendationLoading(true)
    setRecommendationError(null)
    try {
      const regenerate = recommendation !== null
      const suffix = regenerate ? '?regenerate=true' : ''
      const response = await authFetch(
        `/api/submissions/${submissionId}/recommend${suffix}`,
        { method: 'POST' },
      )
      if (!response.ok) throw new Error(`Recommendation request failed: HTTP ${response.status}`)
      setRecommendation(await response.json() as Recommendation)
    } catch (e: unknown) {
      setRecommendationError(e instanceof Error ? e.message : 'Failed to request recommendation')
    } finally {
      setRecommendationLoading(false)
    }
  }

  useEffect(() => { load() }, [load])
  useEffect(() => { if (tab === 'enrichment') void loadEnrichment() }, [tab, loadEnrichment])
  useEffect(() => { if (tab === 'recommendation') void loadRecommendation() }, [tab, loadRecommendation])

  useEffect(() => {
    if (tab !== 'enrichment' || !enrichments.some(r => r.status === 'pending')) return
    const timer = window.setInterval(() => { void loadEnrichment() }, 3000)
    return () => window.clearInterval(timer)
  }, [tab, enrichments, loadEnrichment])

  useEffect(() => {
    if (tab !== 'recommendation' || recommendation?.status !== 'pending') return
    const timer = window.setInterval(() => { void loadRecommendation() }, 2000)
    return () => window.clearInterval(timer)
  }, [tab, recommendation, loadRecommendation])

  // ── Loading / error states ────────────────────────────────────────────────

  if (loading) return (
    <div className="sd-loading">
      <div className="sd-loading-spinner" />
      Loading submission…
    </div>
  )

  if (error || !sub) return (
    <div className="sd-root">
      <button id="sd-back-btn" className="sd-back-btn" onClick={onBack}>← Back</button>
      <div className="sd-tab-error">⚠ {error ?? 'Submission not found'}</div>
    </div>
  )

  // ── Main render ───────────────────────────────────────────────────────────

  return (
    <div className="sd-root">
      {/* Back button */}
      <button id="sd-back-btn" className="sd-back-btn" onClick={onBack}>
        ← Back to submissions
      </button>

      {/* Header */}
      <div className="sd-header">
        <span className="sd-id">#{sub.id}</span>
        <span className={`sd-badge sd-badge-source`}>{sub.source_type}</span>
        <span className={`sd-badge ${sanStatusClass(sub.sanitization_status)}`}>
          {sub.sanitization_status}
        </span>
        {sub.embedding_status === 'complete' && (
          <span className="sd-badge sd-badge-embedded">🧠 embedded</span>
        )}
        <span className="sd-header-date">{fmtDate(sub.submitted_at)}</span>
      </div>

      {/* Sanitization meta banner */}
      {sub.sanitization_meta && (sub.sanitization_meta.redaction_count > 0 || sub.sanitization_meta.flag_count > 0) && (
        <div className="sd-san-meta">
          {sub.sanitization_meta.redaction_count > 0 && (
            <span className="sd-san-chip">🔒 {sub.sanitization_meta.redaction_count} secret(s) redacted</span>
          )}
          {sub.sanitization_meta.flag_count > 0 && (
            <span className="sd-san-chip">⚑ {sub.sanitization_meta.flag_count} suspicious pattern(s) flagged</span>
          )}
          {sub.sanitization_meta.was_truncated && (
            <span className="sd-san-chip">✂ Text was truncated to max length</span>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="sd-tabs" role="tablist" aria-label="Submission details">
        <button id="sd-tab-content" role="tab" aria-selected={tab === 'content'} aria-controls="sd-tab-panel" className={`sd-tab-btn ${tab === 'content' ? 'active' : ''}`} onClick={() => setTab('content')}>📄 Content</button>
        <button id="sd-tab-findings" role="tab" aria-selected={tab === 'findings'} aria-controls="sd-tab-panel" className={`sd-tab-btn ${tab === 'findings' ? 'active' : ''}`} onClick={() => setTab('findings')}>🔍 Findings</button>
        <button id="sd-tab-enrichment" role="tab" aria-selected={tab === 'enrichment'} aria-controls="sd-tab-panel" className={`sd-tab-btn ${tab === 'enrichment' ? 'active' : ''}`} onClick={() => setTab('enrichment')}>🛡 Enrichment</button>
        <button id="sd-tab-recommendation" role="tab" aria-selected={tab === 'recommendation'} aria-controls="sd-tab-panel" className={`sd-tab-btn ${tab === 'recommendation' ? 'active' : ''}`} onClick={() => setTab('recommendation')}>✨ Recommendation</button>
      </div>

      {/* Tab body */}
      <div id="sd-tab-panel" className="sd-tab-body" role="tabpanel" aria-labelledby={`sd-tab-${tab}`}>

        {/* Content tab */}
        {tab === 'content' && (
          <div className="sd-content-grid">
            <div>
              <span className="sd-text-label">Raw text (original)</span>
              <div className="sd-text-box">{sub.raw_text}</div>
            </div>
            <div>
              <span className="sd-text-label">Sanitized text (stored)</span>
              <div className={`sd-text-box ${sub.sanitization_status}`}>
                {sub.sanitized_text ?? <em>No sanitized text</em>}
              </div>
            </div>
          </div>
        )}

        {/* Findings tab */}
        {tab === 'findings' && (
          <FindingsPanel submissionId={sub.id} onClose={() => setTab('content')} />
        )}

        {/* Enrichment tab */}
        {tab === 'enrichment' && (
          <section aria-label="IOC enrichment">
            <div className="sd-enrich-header">
              <span className="sd-enrich-desc">
                Extracted indicators are checked read-only against VirusTotal and AbuseIPDB.
                Private IPs are never sent to external providers.
              </span>
              <button
                type="button"
                className="sd-action-btn"
                onClick={() => { void runEnrichment() }}
                disabled={enrichmentLoading}
              >
                {enrichmentLoading ? '⏳ Working…' : '🔍 Enrich IOCs'}
              </button>
            </div>
            {enrichmentError && (
              <div role="alert" className="sd-tab-error">⚠ {enrichmentError}</div>
            )}
            {enrichmentLoading && enrichments.length === 0 ? (
              <div className="sd-loading" role="status">
                <div className="sd-loading-spinner" />
                Checking sanitized indicators…
              </div>
            ) : enrichments.length === 0 ? (
              <div className="sd-empty">
                No enrichment results yet. Start a lookup to extract and check indicators from sanitized text.
              </div>
            ) : (
              <div className="sl-table-wrap">
                <table className="sl-table">
                  <thead>
                    <tr>
                      {['IOC', 'Type', 'Source', 'Reputation', 'Status'].map(label => (
                        <th key={label}>{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {enrichments.map(result => {
                      const iocClass = result.ioc_type === 'ip' ? 'sd-badge-ioc-ip'
                        : result.ioc_type === 'domain' ? 'sd-badge-ioc-domain'
                        : 'sd-badge-ioc-hash'
                      const repScore = result.reputation_score
                      const repClass = repScore === null ? 'sd-rep-none'
                        : repScore >= 75 ? 'sd-rep-critical'
                        : repScore >= 50 ? 'sd-rep-high'
                        : repScore >= 25 ? 'sd-rep-medium'
                        : 'sd-rep-low'
                      return (
                        <tr key={result.id}>
                          <td className="sd-ioc-value">{result.ioc_value}</td>
                          <td><span className={`sd-badge ${iocClass}`}>{result.ioc_type.toUpperCase()}</span></td>
                          <td>
                            {result.source === 'virustotal'
                              ? <span className="sd-source-vt">VirusTotal</span>
                              : <span className="sd-source-abuseipdb">AbuseIPDB</span>}
                          </td>
                          <td><span className={repClass}>{repScore ?? '—'}</span></td>
                          <td><span className={`sd-badge ${sanStatusClass(result.status)}`}>{result.status}</span></td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {/* Recommendation tab */}
        {tab === 'recommendation' && (
          <section aria-label="Analyst recommendation">
            <div className="sd-advisory-banner">
              ⚠ Advisory only — this AI-generated content is not an automated response. An analyst must review and approve any action.
            </div>
            <div className="sd-enrich-header">
              <span className="sd-enrich-desc">
                The recommendation uses sanitized submission text and available findings, risk, enrichment, and network context.
              </span>
              <button
                type="button"
                className="sd-alert-btn"
                onClick={() => { void runRecommendation() }}
                disabled={recommendationLoading || recommendation?.status === 'pending'}
              >
                {recommendationLoading || recommendation?.status === 'pending'
                  ? '⏳ Generating…'
                  : recommendation ? '🔄 Regenerate' : '✨ Generate recommendation'}
              </button>
            </div>
            {recommendationError && (
              <div role="alert" className="sd-tab-error">⚠ {recommendationError}</div>
            )}
            {!recommendation && !recommendationError && (
              <div className="sd-empty">No recommendation requested yet.</div>
            )}
            {recommendation?.status === 'pending' && (
              <div className="sd-loading" role="status">
                <div className="sd-loading-spinner" />
                Generating an advisory recommendation…
              </div>
            )}
            {recommendation?.status === 'failed' && (
              <div role="alert" className="sd-tab-error">
                {(recommendation.error ?? '').toLowerCase().includes('api key') ||
                 (recommendation.error ?? '').toLowerCase().includes('not configured') ? (
                  <div className="sd-ai-unconfigured">
                    <span className="sd-ai-unconfigured-icon">🔑</span>
                    <span className="sd-ai-unconfigured-title">AI model not configured</span>
                    <span className="sd-ai-unconfigured-desc">
                      An API key for the AI provider is required. Ask your administrator to configure it in Network Settings.
                    </span>
                  </div>
                ) : (
                  <>⚠ Recommendation generation failed: {recommendation.error ?? 'AI service unavailable'}. You can explicitly retry.</>
                )}
              </div>
            )}
            {recommendation?.status === 'complete' && (
              <div className="sd-rec-card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-4)', flexWrap: 'wrap', gap: 'var(--space-3)' }}>
                  <span className="sd-text-label">Analyst summary</span>
                  {recommendation.confidence !== null && (
                    <span className="sd-rec-confidence">
                      Confidence {(recommendation.confidence * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
                <p className="sd-rec-text">{recommendation.recommendation_text}</p>
                <span className="sd-text-label">Suggested next actions</span>
                <ol className="sd-rec-actions">
                  {(recommendation.suggested_actions ?? []).map((action, index) => (
                    <li key={`${index}-${action}`}>{action}</li>
                  ))}
                </ol>
                <div className="sd-rec-meta">
                  {recommendation.model_used ?? 'Configured AI model'}
                  {recommendation.generated_at ? ` · ${fmtDate(recommendation.generated_at)}` : ''}
                </div>
              </div>
            )}
          </section>
        )}

      </div>
    </div>
  )
}

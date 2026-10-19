/**
 * SubmissionDetail — full detail view for a single submission.
 * Shows: metadata header, raw vs sanitized text comparison, and FindingsPanel.
 */
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import FindingsPanel from './FindingsPanel'

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

// ── Inline styles (small one-off component, no separate css file needed) ──────

const S = {
  root: { width: '100%' } as const,
  backBtn: {
    background: 'transparent',
    border: '1px solid var(--clr-border)',
    borderRadius: '6px',
    color: 'var(--clr-text-muted)',
    fontFamily: 'var(--font-sans)',
    fontSize: '0.78rem',
    padding: '6px 14px',
    cursor: 'pointer',
    marginBottom: '1.1rem',
    transition: 'border-color 0.15s, color 0.15s',
  } as const,
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    flexWrap: 'wrap' as const,
    marginBottom: '1.1rem',
  },
  badge: (bg: string, color: string, border: string) => ({
    padding: '3px 10px',
    borderRadius: '999px',
    fontSize: '0.68rem',
    fontWeight: 700,
    background: bg,
    color,
    border: `1px solid ${border}`,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.05em',
  }),
  label: {
    fontSize: '0.72rem',
    color: 'var(--clr-text-muted)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.06em',
    fontWeight: 700,
    marginBottom: '0.4rem',
    display: 'block',
  } as const,
  textBox: {
    background: 'var(--clr-surface-2)',
    border: '1px solid var(--clr-border)',
    borderRadius: '8px',
    padding: '0.85rem',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.74rem',
    color: 'var(--clr-text-muted)',
    lineHeight: '1.6',
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-word' as const,
    maxHeight: '220px',
    overflowY: 'auto' as const,
  } as const,
}

function sevBadgeStyle(status: string) {
  const map: Record<string, [string, string, string]> = {
    clean:    ['rgba(34,211,165,0.1)',  '#6ee7b7', 'rgba(34,211,165,0.25)'],
    redacted: ['rgba(245,158,11,0.1)',  '#fcd34d', 'rgba(245,158,11,0.25)'],
    flagged:  ['rgba(239,68,68,0.1)',   '#f87171', 'rgba(239,68,68,0.25)'],
    pending:  ['rgba(100,116,139,0.1)', '#94a3b8', 'rgba(100,116,139,0.25)'],
  }
  return S.badge(...(map[status] ?? map.pending))
}

function fmtDate(iso: string) {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function SubmissionDetail({ submissionId, onBack }: Props) {
  const { authFetch } = useAuth()
  const [sub, setSub]     = useState<SubmissionFull | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab]     = useState<'content' | 'findings' | 'enrichment' | 'recommendation'>('content')
  const [enrichments, setEnrichments] = useState<EnrichmentResult[]>([])
  const [enrichmentLoading, setEnrichmentLoading] = useState(false)
  const [enrichmentError, setEnrichmentError] = useState<string | null>(null)
  const [recommendation, setRecommendation] = useState<Recommendation | null>(null)
  const [recommendationLoading, setRecommendationLoading] = useState(false)
  const [recommendationError, setRecommendationError] = useState<string | null>(null)

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
      const response = await authFetch(`/api/submissions/${submissionId}/enrich`, {
        method: 'POST',
      })
      if (!response.ok) throw new Error(`Enrichment request failed: HTTP ${response.status}`)
      const data = await response.json() as {
        results: EnrichmentResult[]
      }
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
      if (response.status === 404) {
        setRecommendation(null)
        return
      }
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

  useEffect(() => {
    if (tab === 'enrichment') void loadEnrichment()
  }, [tab, loadEnrichment])

  useEffect(() => {
    if (tab === 'recommendation') void loadRecommendation()
  }, [tab, loadRecommendation])

  useEffect(() => {
    if (tab !== 'enrichment' || !enrichments.some(result => result.status === 'pending')) return
    const timer = window.setInterval(() => { void loadEnrichment() }, 3000)
    return () => window.clearInterval(timer)
  }, [tab, enrichments, loadEnrichment])

  useEffect(() => {
    if (tab !== 'recommendation' || recommendation?.status !== 'pending') return
    const timer = window.setInterval(() => { void loadRecommendation() }, 2000)
    return () => window.clearInterval(timer)
  }, [tab, recommendation, loadRecommendation])

  const tabBtnStyle = (active: boolean) => ({
    padding: '7px 18px',
    borderRadius: '6px 6px 0 0',
    border: '1px solid var(--clr-border)',
    borderBottom: active ? '1px solid var(--clr-surface)' : '1px solid var(--clr-border)',
    background: active ? 'var(--clr-surface)' : 'var(--clr-surface-2)',
    color: active ? 'var(--clr-accent)' : 'var(--clr-text-muted)',
    fontFamily: 'var(--font-sans)',
    fontSize: '0.8rem',
    fontWeight: active ? 700 : 400,
    cursor: 'pointer',
    transition: 'all 0.15s',
    marginBottom: '-1px',
    position: 'relative' as const,
    zIndex: active ? 1 : 0,
  })

  if (loading) return <div style={{ padding: '2rem', color: 'var(--clr-text-muted)', textAlign: 'center' }}>Loading…</div>
  if (error || !sub) return (
    <div>
      <button style={S.backBtn} onClick={onBack}>← Back</button>
      <div style={{ color: '#f87171', padding: '1rem' }}>⚠ {error ?? 'Submission not found'}</div>
    </div>
  )

  return (
    <div style={S.root}>
      {/* Back button */}
      <button
        id="sd-back-btn"
        style={S.backBtn}
        onClick={onBack}
        onMouseEnter={e => { (e.target as HTMLElement).style.borderColor = 'rgba(0,200,255,0.35)'; (e.target as HTMLElement).style.color = 'var(--clr-accent)' }}
        onMouseLeave={e => { (e.target as HTMLElement).style.borderColor = 'var(--clr-border)'; (e.target as HTMLElement).style.color = 'var(--clr-text-muted)' }}
      >
        ← Back to submissions
      </button>

      {/* Header */}
      <div style={S.header}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--clr-text-muted)' }}>
          #{sub.id}
        </span>
        <span style={S.badge('rgba(0,200,255,0.1)', 'var(--clr-accent)', 'rgba(0,200,255,0.22)')}>
          {sub.source_type}
        </span>
        <span style={sevBadgeStyle(sub.sanitization_status)}>
          {sub.sanitization_status}
        </span>
        {sub.embedding_status === 'complete' && (
          <span style={S.badge('rgba(167,139,250,0.1)', '#c4b5fd', 'rgba(167,139,250,0.22)')}>
            🧠 embedded
          </span>
        )}
        <span style={{ marginLeft: 'auto', fontSize: '0.72rem', color: 'var(--clr-text-muted)' }}>
          {fmtDate(sub.submitted_at)}
        </span>
      </div>

      {/* Sanitization meta */}
      {sub.sanitization_meta && (sub.sanitization_meta.redaction_count > 0 || sub.sanitization_meta.flag_count > 0) && (
        <div style={{
          display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem',
          padding: '0.6rem 0.9rem',
          background: 'rgba(245,158,11,0.06)',
          border: '1px solid rgba(245,158,11,0.2)',
          borderRadius: '8px',
          fontSize: '0.75rem', color: '#fcd34d',
        }}>
          {sub.sanitization_meta.redaction_count > 0 && (
            <span>🔒 {sub.sanitization_meta.redaction_count} secret(s) redacted</span>
          )}
          {sub.sanitization_meta.flag_count > 0 && (
            <span>⚑ {sub.sanitization_meta.flag_count} suspicious pattern(s) flagged</span>
          )}
          {sub.sanitization_meta.was_truncated && (
            <span>✂ Text was truncated to max length</span>
          )}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0', marginBottom: '0', borderBottom: '1px solid var(--clr-border)' }}>
        <button id="sd-tab-content" style={tabBtnStyle(tab === 'content')} onClick={() => setTab('content')}>
          📄 Content
        </button>
        <button id="sd-tab-findings" style={tabBtnStyle(tab === 'findings')} onClick={() => setTab('findings')}>
          🔍 Findings
        </button>
        <button id="sd-tab-enrichment" style={tabBtnStyle(tab === 'enrichment')} onClick={() => setTab('enrichment')}>
          🛡 Enrichment
        </button>
        <button id="sd-tab-recommendation" style={tabBtnStyle(tab === 'recommendation')} onClick={() => setTab('recommendation')}>
          ✨ Recommendation
        </button>
      </div>

      {/* Tab content */}
      <div style={{
        border: '1px solid var(--clr-border)',
        borderTop: 'none',
        borderRadius: '0 8px 8px 8px',
        background: 'var(--clr-surface)',
        padding: '1.1rem',
      }}>
        {tab === 'content' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            {/* Raw text */}
            <div>
              <span style={S.label}>Raw text (original)</span>
              <div style={{ ...S.textBox, borderColor: 'rgba(100,116,139,0.3)' }}>
                {sub.raw_text}
              </div>
            </div>

            {/* Sanitized text */}
            <div>
              <span style={S.label}>Sanitized text (stored)</span>
              <div style={{ ...S.textBox,
                borderColor: sub.sanitization_status === 'clean'
                  ? 'rgba(34,211,165,0.25)'
                  : 'rgba(245,158,11,0.25)',
              }}>
                {sub.sanitized_text ?? <em>No sanitized text</em>}
              </div>
            </div>
          </div>
        )}

        {tab === 'findings' && (
          <FindingsPanel
            submissionId={sub.id}
            onClose={() => setTab('content')}
          />
        )}

        {tab === 'enrichment' && (
          <section aria-label="IOC enrichment">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
              <span style={{ color: 'var(--clr-text-muted)', fontSize: '0.78rem', flex: 1 }}>
                Extracted indicators are checked read-only against VirusTotal and AbuseIPDB. Private IPs are never sent to external providers.
              </span>
              <button
                type="button"
                onClick={() => { void runEnrichment() }}
                disabled={enrichmentLoading}
                style={{
                  border: '1px solid rgba(0,200,255,0.3)',
                  borderRadius: '6px',
                  background: 'rgba(0,200,255,0.08)',
                  color: 'var(--clr-accent)',
                  padding: '7px 12px',
                  cursor: enrichmentLoading ? 'wait' : 'pointer',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.78rem',
                }}
              >
                {enrichmentLoading ? 'Working…' : 'Enrich IOCs'}
              </button>
            </div>
            {enrichmentError && (
              <div role="alert" style={{ color: '#f87171', marginBottom: '0.8rem', fontSize: '0.78rem' }}>
                ⚠ {enrichmentError}
              </div>
            )}
            {enrichments.length === 0 ? (
              <p style={{ color: 'var(--clr-text-muted)', fontSize: '0.8rem' }}>
                No enrichment results yet. Start a lookup to extract and check indicators from sanitized text.
              </p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ color: 'var(--clr-text-muted)' }}>
                      {['IOC', 'Type', 'Source', 'Reputation', 'Status'].map(label => (
                        <th key={label} style={{ padding: '0.65rem', borderBottom: '1px solid var(--clr-border)' }}>{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {enrichments.map(result => (
                      <tr key={result.id}>
                        <td style={{ padding: '0.65rem', borderBottom: '1px solid var(--clr-border)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{result.ioc_value}</td>
                        <td style={{ padding: '0.65rem', borderBottom: '1px solid var(--clr-border)' }}>{result.ioc_type.toUpperCase()}</td>
                        <td style={{ padding: '0.65rem', borderBottom: '1px solid var(--clr-border)' }}>{result.source === 'virustotal' ? 'VirusTotal' : 'AbuseIPDB'}</td>
                        <td style={{ padding: '0.65rem', borderBottom: '1px solid var(--clr-border)' }}>{result.reputation_score ?? '—'}</td>
                        <td style={{ padding: '0.65rem', borderBottom: '1px solid var(--clr-border)' }}>
                          <span style={sevBadgeStyle(result.status)}>{result.status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {tab === 'recommendation' && (
          <section aria-label="Analyst recommendation">
            <div style={{
              border: '1px solid rgba(245,158,11,0.3)',
              borderRadius: '6px',
              background: 'rgba(245,158,11,0.06)',
              color: 'var(--clr-text-muted)',
              fontSize: '0.78rem',
              lineHeight: 1.5,
              padding: '0.7rem 0.85rem',
              marginBottom: '1rem',
            }}>
              Advisory only — this AI-generated content is not an automated response. An analyst must review and approve any action.
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
              <span style={{ color: 'var(--clr-text-muted)', fontSize: '0.78rem', flex: 1 }}>
                The recommendation uses sanitized submission text and available findings, risk, enrichment, and network context.
              </span>
              <button
                type="button"
                onClick={() => { void runRecommendation() }}
                disabled={recommendationLoading || recommendation?.status === 'pending'}
                style={{
                  border: '1px solid rgba(0,200,255,0.3)',
                  borderRadius: '6px',
                  background: 'rgba(0,200,255,0.08)',
                  color: 'var(--clr-accent)',
                  padding: '7px 12px',
                  cursor: recommendationLoading ? 'wait' : 'pointer',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.78rem',
                }}
              >
                {recommendationLoading || recommendation?.status === 'pending'
                  ? 'Generating…'
                  : recommendation ? 'Regenerate recommendation' : 'Generate recommendation'}
              </button>
            </div>
            {recommendationError && (
              <div role="alert" style={{ color: '#f87171', marginBottom: '0.8rem', fontSize: '0.78rem' }}>
                ⚠ {recommendationError}
              </div>
            )}
            {!recommendation && !recommendationError && (
              <p style={{ color: 'var(--clr-text-muted)', fontSize: '0.8rem' }}>
                No recommendation requested yet.
              </p>
            )}
            {recommendation?.status === 'pending' && (
              <p role="status" style={{ color: 'var(--clr-text-muted)', fontSize: '0.8rem' }}>
                Generating an advisory recommendation…
              </p>
            )}
            {recommendation?.status === 'failed' && (
              <p role="alert" style={{ color: '#f87171', fontSize: '0.8rem' }}>
                Recommendation generation failed: {recommendation.error ?? 'AI service unavailable'}. You can explicitly retry.
              </p>
            )}
            {recommendation?.status === 'complete' && (
              <div>
                <span style={S.label}>Analyst summary</span>
                <p style={{ color: 'var(--clr-text)', lineHeight: 1.6, fontSize: '0.86rem' }}>
                  {recommendation.recommendation_text}
                </p>
                <span style={S.label}>Suggested next actions</span>
                <ol style={{ color: 'var(--clr-text-muted)', fontSize: '0.82rem', lineHeight: 1.7, paddingLeft: '1.4rem' }}>
                  {(recommendation.suggested_actions ?? []).map((action, index) => (
                    <li key={`${index}-${action}`}>{action}</li>
                  ))}
                </ol>
                <div style={{ color: 'var(--clr-text-muted)', fontSize: '0.7rem', marginTop: '0.8rem' }}>
                  {recommendation.model_used ?? 'Configured AI model'}
                  {recommendation.generated_at ? ` · ${fmtDate(recommendation.generated_at)}` : ''}
                  {recommendation.confidence !== null ? ` · Confidence ${(recommendation.confidence * 100).toFixed(0)}%` : ''}
                </div>
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  )
}

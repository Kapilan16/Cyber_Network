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
  const [tab, setTab]     = useState<'content' | 'findings'>('content')

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

  useEffect(() => { load() }, [load])

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
      </div>
    </div>
  )
}

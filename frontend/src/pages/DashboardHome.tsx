/**
 * DashboardHome — analyst dashboard overview card.
 * Fetches /api/dashboard/summary and renders stats, severity breakdown,
 * MITRE tactics, and quick navigation actions.
 */
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import './DashboardHome.css'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SeverityBreakdown {
  critical: number
  high: number
  medium: number
  low: number
}

interface TacticCount {
  tactic: string
  count: number
}

interface DashboardSummary {
  submissions_today: number
  submissions_this_week: number
  total_submissions: number
  findings_by_severity: SeverityBreakdown
  open_findings_by_severity: SeverityBreakdown
  total_findings: number
  top_tactics_this_week: TacticCount[]
  total_rules: number
  active_rules: number
  embedding_complete_count: number
  embedding_pending_count: number
  active_campaign_count: number
}

type NavTarget = 'submissions' | 'search' | 'memory'

interface Props {
  onNavigate: (page: NavTarget) => void
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function DashboardHome({ onNavigate }: Props) {
  const { authFetch } = useAuth()
  const [summary, setSummary]   = useState<DashboardSummary | null>(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await authFetch('/api/dashboard/summary')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setSummary(await r.json() as DashboardSummary)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load summary')
    } finally {
      setLoading(false)
    }
  }, [authFetch])

  useEffect(() => { load() }, [load])

  if (loading) return <div className="dh-loading">Loading dashboard…</div>
  if (error || !summary) return <div className="dh-loading" style={{ color: '#f87171' }}>⚠ {error ?? 'No data'}</div>

  const sev = summary.open_findings_by_severity
  const maxSev = Math.max(sev.critical, sev.high, sev.medium, sev.low, 1)

  return (
    <div className="dh-root">
      {/* ── Stats cards ── */}
      <div className="dh-stats-grid">
        <div id="dh-stat-today" className="dh-stat-card accent-cyan">
          <span className="dh-stat-icon">📥</span>
          <span className="dh-stat-value">{summary.submissions_today}</span>
          <span className="dh-stat-label">Submissions today</span>
          <span className="dh-stat-sub">{summary.submissions_this_week} this week</span>
        </div>

        <div id="dh-stat-total" className="dh-stat-card accent-slate">
          <span className="dh-stat-icon">🗃️</span>
          <span className="dh-stat-value">{summary.total_submissions}</span>
          <span className="dh-stat-label">Total submissions</span>
          <span className="dh-stat-sub">
            {summary.embedding_complete_count} embedded
          </span>
        </div>

        <div id="dh-stat-findings" className="dh-stat-card accent-amber">
          <span className="dh-stat-icon">🔍</span>
          <span className="dh-stat-value">{summary.total_findings}</span>
          <span className="dh-stat-label">Open findings</span>
          <span className="dh-stat-sub">{sev.critical} critical</span>
        </div>

        <div id="dh-stat-rules" className="dh-stat-card accent-green">
          <span className="dh-stat-icon">📋</span>
          <span className="dh-stat-value">{summary.active_rules}</span>
          <span className="dh-stat-label">Active rules</span>
          <span className="dh-stat-sub">{summary.total_rules} total</span>
        </div>

        <div id="dh-stat-critical" className="dh-stat-card accent-red">
          <span className="dh-stat-icon">🚨</span>
          <span className="dh-stat-value">{sev.critical + sev.high}</span>
          <span className="dh-stat-label">High+ findings</span>
          <span className="dh-stat-sub">{sev.critical} critical, {sev.high} high</span>
        </div>

        <div id="dh-stat-embed" className="dh-stat-card accent-purple">
          <span className="dh-stat-icon">🧠</span>
          <span className="dh-stat-value">{summary.embedding_complete_count}</span>
          <span className="dh-stat-label">Embeddings indexed</span>
          <span className="dh-stat-sub">
            {summary.embedding_pending_count > 0
              ? `${summary.embedding_pending_count} pending`
              : 'All indexed'}
          </span>
        </div>

        <button
          id="dh-stat-campaigns"
          className="dh-stat-card accent-green dh-campaign-card"
          onClick={() => onNavigate('memory')}
        >
          <span className="dh-stat-icon">🕸️</span>
          <span className="dh-stat-value">{summary.active_campaign_count}</span>
          <span className="dh-stat-label">Recurring patterns</span>
          <span className="dh-stat-sub">Active campaigns · View memory network →</span>
        </button>
      </div>

      {/* ── Lower panels ── */}
      <div className="dh-lower">
        {/* Severity breakdown */}
        <div className="dh-panel">
          <div className="dh-panel-title">Open findings by severity</div>
          {(['critical', 'high', 'medium', 'low'] as const).map(s => (
            <div key={s} className="dh-sev-row">
              <span className={`dh-sev-label ${s}`}>{s}</span>
              <div className="dh-sev-bar-wrap">
                <div
                  className={`dh-sev-bar ${s}`}
                  style={{ width: `${(sev[s] / maxSev) * 100}%` }}
                />
              </div>
              <span className="dh-sev-count">{sev[s]}</span>
            </div>
          ))}
        </div>

        {/* MITRE tactics */}
        <div className="dh-panel">
          <div className="dh-panel-title">Top MITRE tactics this week</div>
          {summary.top_tactics_this_week.length === 0 ? (
            <p className="dh-no-tactics">No findings with MITRE mappings yet this week.</p>
          ) : (
            <div className="dh-tactic-list">
              {summary.top_tactics_this_week.map(t => (
                <span key={t.tactic} className="dh-tactic-tag">
                  {t.tactic}
                  <span className="dh-tactic-count">{t.count}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Quick actions */}
        <div className="dh-panel" style={{ gridColumn: '1 / -1' }}>
          <div className="dh-panel-title">Quick actions</div>
          <div className="dh-actions">
            <button
              id="dh-action-submissions"
              className="dh-action-btn"
              onClick={() => onNavigate('submissions')}
            >
              <span className="dh-action-btn-icon">📋</span>
              <span className="dh-action-btn-text">
                View all submissions
                <span style={{ display: 'block', fontSize: '0.68rem', color: 'var(--clr-text-muted)', marginTop: '1px' }}>
                  Browse, filter and evaluate past artifacts
                </span>
              </span>
              <span className="dh-action-btn-arrow">›</span>
            </button>

            <button
              id="dh-action-search"
              className="dh-action-btn"
              onClick={() => onNavigate('search')}
            >
              <span className="dh-action-btn-icon">🧠</span>
              <span className="dh-action-btn-text">
                Semantic search
                <span style={{ display: 'block', fontSize: '0.68rem', color: 'var(--clr-text-muted)', marginTop: '1px' }}>
                  Find similar past submissions by meaning
                </span>
              </span>
              <span className="dh-action-btn-arrow">›</span>
            </button>

            <button
              id="dh-action-refresh"
              className="dh-action-btn"
              onClick={load}
            >
              <span className="dh-action-btn-icon">🔄</span>
              <span className="dh-action-btn-text">Refresh stats</span>
              <span className="dh-action-btn-arrow">›</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

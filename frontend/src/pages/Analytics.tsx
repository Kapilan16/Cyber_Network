import { useCallback, useEffect, useMemo, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import './Analytics.css'

interface CountItem {
  name: string
  count: number
}

interface TrendItem {
  date: string
  average_score: number
  submissions: number
}

interface EarlyWarning {
  id: number
  triggered_at: string
  description: string
  submission_ids: number[]
}

interface NetworkContext {
  enabled: boolean
  available: boolean
  central_total: number | null
  by_tactic: Array<{ tactic: string; local_count: number; network_count: number }>
  error: string | null
}

interface AnalyticsOverview {
  risk_band_distribution: CountItem[]
  top_mitre_tactics: {
    last_7_days: CountItem[]
    last_30_days: CountItem[]
  }
  enrichment_hit_rate: number
  enriched_iocs: number
  non_clean_iocs: number
  average_risk_score_trend: TrendItem[]
  network_context: NetworkContext | null
  active_warnings: EarlyWarning[]
}

const bandColors: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fcd34d',
  low: '#34d399',
}

export default function Analytics() {
  const { authFetch } = useAuth()
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null)
  const [period, setPeriod] = useState<7 | 30>(7)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await authFetch('/api/analytics/overview')
      if (!response.ok) throw new Error(`Analytics request failed: HTTP ${response.status}`)
      setOverview(await response.json() as AnalyticsOverview)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to load analytics')
    } finally {
      setLoading(false)
    }
  }, [authFetch])

  useEffect(() => { void load() }, [load])

  const trendPoints = useMemo(() => {
    const items = overview?.average_risk_score_trend ?? []
    if (!items.length) return ''
    return items.map((item, index) => {
      const x = items.length === 1 ? 50 : (index / (items.length - 1)) * 100
      const y = 100 - Math.min(100, Math.max(0, item.average_score))
      return `${x},${y}`
    }).join(' ')
  }, [overview])

  const tactics = period === 7
    ? overview?.top_mitre_tactics.last_7_days ?? []
    : overview?.top_mitre_tactics.last_30_days ?? []
  const maximumTacticCount = Math.max(1, ...tactics.map(item => item.count))

  return (
    <div className="analytics-page">
      <header className="analytics-toolbar">
        <p>Deterministic summaries of local risk, rule findings, and enrichment signals.</p>
        <button type="button" onClick={() => { void load() }} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </header>

      {error && <div className="analytics-error" role="alert">{error}</div>}
      {loading && !overview && <div className="analytics-empty">Loading analytics…</div>}
      {overview && (
        <>
          <section className="analytics-risk-grid" aria-label="Risk band distribution">
            {overview.risk_band_distribution.map(item => (
              <article className="analytics-card analytics-risk-card" key={item.name}>
                <span style={{ color: bandColors[item.name] ?? 'var(--clr-text-muted)' }}>
                  {item.name}
                </span>
                <strong>{item.count}</strong>
                <small>submissions</small>
              </article>
            ))}
            <article className="analytics-card analytics-risk-card">
              <span>Enrichment hit rate</span>
              <strong>{overview.enrichment_hit_rate.toFixed(1)}%</strong>
              <small>{overview.non_clean_iocs} non-clean / {overview.enriched_iocs} enriched IOCs</small>
            </article>
          </section>

          <section className="analytics-chart-grid">
            <article className="analytics-card">
              <header className="analytics-card-header">
                <div>
                  <h2>MITRE tactic volume</h2>
                  <p>Distinct submissions with a matched technique</p>
                </div>
                <div className="analytics-period" role="group" aria-label="Tactic period">
                  <button className={period === 7 ? 'selected' : ''} onClick={() => setPeriod(7)}>7 days</button>
                  <button className={period === 30 ? 'selected' : ''} onClick={() => setPeriod(30)}>30 days</button>
                </div>
              </header>
              {tactics.length === 0 ? <p className="analytics-empty">No MITRE-tagged findings in this period.</p> : (
                <div className="analytics-bars">
                  {tactics.map(item => (
                    <div className="analytics-bar-row" key={item.name}>
                      <span title={item.name}>{item.name}</span>
                      <div className="analytics-bar-track">
                        <div style={{ width: `${Math.max(3, item.count / maximumTacticCount * 100)}%` }} />
                      </div>
                      <strong>{item.count}</strong>
                    </div>
                  ))}
                </div>
              )}
            </article>

            <article className="analytics-card">
              <header className="analytics-card-header">
                <div>
                  <h2>Average risk score</h2>
                  <p>Daily average · last 30 days</p>
                </div>
              </header>
              <div className="analytics-line-chart">
                <div className="analytics-chart-axis"><span>100</span><span>50</span><span>0</span></div>
                <svg viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label="Daily average risk score trend">
                  <line x1="0" y1="0" x2="100" y2="0" />
                  <line x1="0" y1="50" x2="100" y2="50" />
                  <line x1="0" y1="100" x2="100" y2="100" />
                  {trendPoints && <polyline points={trendPoints} />}
                </svg>
              </div>
              <div className="analytics-trend-foot">
                <span>{overview.average_risk_score_trend[0]?.date}</span>
                <span>{overview.average_risk_score_trend.at(-1)?.date}</span>
              </div>
            </article>
          </section>

          <section className="analytics-lower-grid">
            <article className="analytics-card">
              <h2>Early warnings</h2>
              <p className="analytics-card-description">
                {`Rule-based: ${overview.active_warnings.length} active warning(s), using the configured rolling window and threshold.`}
              </p>
              {overview.active_warnings.length === 0 ? (
                <p className="analytics-empty">No active warnings.</p>
              ) : (
                <ul className="analytics-warning-list">
                  {overview.active_warnings.map(warning => (
                    <li key={warning.id}>
                      <strong>{warning.description}</strong>
                      <span>{new Date(warning.triggered_at).toLocaleString()} · submissions {warning.submission_ids.map(id => `#${id}`).join(', ')}</span>
                    </li>
                  ))}
                </ul>
              )}
            </article>

            {overview.network_context && (
              <article className="analytics-card">
                <h2>Network context</h2>
                <p className="analytics-card-description">
                  Opted-in central aggregate comparison · {overview.network_context.available
                    ? `${overview.network_context.central_total ?? 0} shared records`
                    : overview.network_context.error ?? 'Unavailable'}
                </p>
                {overview.network_context.available && (
                  <div className="analytics-network-table">
                    <div><strong>MITRE tactic</strong><strong>Local</strong><strong>Network</strong></div>
                    {overview.network_context.by_tactic.map(row => (
                      <div key={row.tactic}><span>{row.tactic}</span><span>{row.local_count}</span><span>{row.network_count}</span></div>
                    ))}
                    {!overview.network_context.by_tactic.length && <p>No tactic-tagged aggregate records.</p>}
                  </div>
                )}
              </article>
            )}
          </section>
        </>
      )}
    </div>
  )
}

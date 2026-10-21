/**
 * FindingsPanel
 *
 * Displays findings for a submission with:
 *   - Severity badge (critical / high / medium / low)
 *   - Matched snippet in monospace
 *   - Linked MITRE ATT&CK technique badge (id · name · tactic)
 *   - MITRE tactic summary bar (aggregated from /mitre-summary)
 *   - Evaluate button to (re-)run the rule engine
 */
import { useEffect, useState, useCallback } from 'react'
import { useAuth } from '../context/AuthContext'
import './FindingsPanel.css'

// ── Types ────────────────────────────────────────────────────────────────────

interface MitreTechniqueRef {
  id: string
  name: string
  tactic: string
}

interface Finding {
  id: number
  submission_id: number
  rule_id: number
  rule_name: string
  matched_snippet: string | null
  severity: 'critical' | 'high' | 'medium' | 'low'
  created_at: string
  mitre_technique: MitreTechniqueRef | null
}

interface TacticBreakdown {
  tactic: string
  finding_count: number
  technique_ids: string[]
}

interface MitreSummary {
  submission_id: number
  total_findings: number
  mapped_findings: number
  tactics: TacticBreakdown[]
}

interface EvaluateResponse {
  submission_id: number
  rules_evaluated: number
  findings_created: number
  findings: Finding[]
}

interface Props {
  submissionId: number
  onClose?: () => void
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_LABEL: Record<string, string> = {
  critical: '🔴 Critical',
  high:     '🟠 High',
  medium:   '🟡 Medium',
  low:      '🟢 Low',
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function FindingsPanel({ submissionId, onClose }: Props) {
  const { authFetch } = useAuth()

  const [findings, setFindings]     = useState<Finding[]>([])
  const [summary, setSummary]       = useState<MitreSummary | null>(null)
  const [loading, setLoading]       = useState(false)
  const [evaluating, setEvaluating] = useState(false)
  const [error, setError]           = useState<string | null>(null)
  const [snippet, setSnippet]       = useState('')

  // ── Load findings + summary ───────────────────────────────────────────────

  const loadFindings = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [findR, summR] = await Promise.all([
        authFetch(`/api/submissions/${submissionId}/findings`),
        authFetch(`/api/mitre/submissions/${submissionId}/mitre-summary`),
      ])
      if (!findR.ok) throw new Error(`Findings fetch failed: HTTP ${findR.status}`)
      if (!summR.ok) throw new Error(`MITRE summary fetch failed: HTTP ${summR.status}`)
      setFindings(await findR.json())
      setSummary(await summR.json())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [authFetch, submissionId])

  useEffect(() => { void loadFindings() }, [loadFindings])

  // ── Evaluate ──────────────────────────────────────────────────────────────

  const handleEvaluate = async () => {
    setEvaluating(true)
    setError(null)
    try {
      const r = await authFetch(`/api/submissions/${submissionId}/evaluate`, {
        method: 'POST',
      })
      if (!r.ok) {
        const body = await r.json().catch(() => ({}))
        throw new Error((body as { detail?: string }).detail ?? `HTTP ${r.status}`)
      }
      const data: EvaluateResponse = await r.json()
      setFindings(data.findings)
      // Reload MITRE summary after evaluation
      const summR = await authFetch(`/api/mitre/submissions/${submissionId}/mitre-summary`)
      if (summR.ok) setSummary(await summR.json())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Evaluation failed')
    } finally {
      setEvaluating(false)
    }
  }

  // ── Filter ────────────────────────────────────────────────────────────────

  const filtered = snippet.trim()
    ? findings.filter(
        f =>
          f.rule_name.toLowerCase().includes(snippet.toLowerCase()) ||
          f.matched_snippet?.toLowerCase().includes(snippet.toLowerCase()) ||
          f.mitre_technique?.name.toLowerCase().includes(snippet.toLowerCase()) ||
          f.mitre_technique?.tactic.toLowerCase().includes(snippet.toLowerCase()),
      )
    : findings

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="fp-root">
      {/* Header row */}
      <div className="fp-toolbar">
        <span className="fp-toolbar-label">
          🔍 Findings — Submission #{submissionId}
        </span>
        <input
          id="fp-filter-input"
          className="fp-input"
          placeholder="Filter by rule name, snippet or MITRE…"
          value={snippet}
          onChange={e => setSnippet(e.target.value)}
        />
        <button
          id="fp-evaluate-btn"
          className="fp-btn primary"
          onClick={handleEvaluate}
          disabled={evaluating}
        >
          {evaluating ? '⏳ Evaluating…' : '▶ Re-evaluate'}
        </button>
        <button
          id="fp-refresh-btn"
          className="fp-btn"
          onClick={loadFindings}
          disabled={loading}
        >
          ↻ Refresh
        </button>
        {onClose && (
          <button id="fp-close-btn" className="fp-btn" onClick={onClose}>
            ✕ Close
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="fp-error" role="alert">
          ⚠ {error}
        </div>
      )}

      {/* MITRE Summary bar */}
      {summary && (
        <div className="fp-summary">
          <div className="fp-summary-stat">
            <span className="fp-summary-stat-value">{summary.total_findings}</span>
            <span className="fp-summary-stat-label">Findings</span>
          </div>
          <div className="fp-summary-divider" />
          <div className="fp-summary-stat">
            <span className="fp-summary-stat-value">{summary.mapped_findings}</span>
            <span className="fp-summary-stat-label">Mapped</span>
          </div>
          <div className="fp-summary-divider" />
          <div className="fp-summary-stat">
            <span className="fp-summary-stat-value">{summary.tactics.length}</span>
            <span className="fp-summary-stat-label">Tactics</span>
          </div>
          {summary.tactics.length > 0 && (
            <>
              <div className="fp-summary-divider" />
              <div className="fp-tactic-pills">
                {summary.tactics.map(t => (
                  <span key={t.tactic} className="fp-tactic-pill" title={t.technique_ids.join(', ')}>
                    {t.tactic} ×{t.finding_count}
                  </span>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* Loading */}
      {loading && <div className="fp-loading">Loading findings…</div>}

      {/* Empty state */}
      {!loading && filtered.length === 0 && (
        <div className="fp-empty">
          <span className="fp-empty-icon">
            {findings.length === 0 ? '🛡️' : '🔎'}
          </span>
          {findings.length === 0
            ? 'No findings yet. Click Re-evaluate to run the rule engine.'
            : 'No findings match the current filter.'}
        </div>
      )}

      {/* Findings list */}
      <div className="fp-list">
        {filtered.map(f => (
          <div key={f.id} className={`fp-card sev-${f.severity}`}>
            {/* Card header */}
            <div className="fp-card-header">
              <span className="fp-rule-name">{f.rule_name}</span>

              {/* Severity badge */}
              <span className={`fp-sev-badge ${f.severity}`}>
                {SEV_LABEL[f.severity] ?? f.severity}
              </span>

              {/* MITRE badge */}
              {f.mitre_technique && (
                <span
                  className="fp-mitre-badge"
                  title={`${f.mitre_technique.id} · ${f.mitre_technique.name}\nTactic: ${f.mitre_technique.tactic}`}
                >
                  <span className="fp-mitre-id">{f.mitre_technique.id}</span>
                  <span className="fp-mitre-name">{f.mitre_technique.name}</span>
                  <span className="fp-mitre-tactic">{f.mitre_technique.tactic}</span>
                </span>
              )}
            </div>

            {/* Matched snippet */}
            {f.matched_snippet && (
              <div className="fp-snippet">
                …{f.matched_snippet}…
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

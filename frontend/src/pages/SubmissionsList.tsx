/**
 * SubmissionsList — paginated table of past submissions.
 * Clicking a row calls onSelectSubmission(id) to open the detail view.
 */
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import './SubmissionsList.css'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SubmissionRow {
  id: number
  source_type: string
  submitted_at: string
  sanitization_status: string
  embedding_status: string
  risk_score: number | null
  risk_band: 'low' | 'medium' | 'high' | 'critical' | null
  sanitized_text: string | null
  findings_by_severity: { critical: number; high: number; medium: number; low: number }
}

interface PaginatedResponse {
  total: number
  page: number
  page_size: number
  items: SubmissionRow[]
}

interface Props {
  onSelectSubmission: (id: number) => void
}

const PAGE_SIZE = 15

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function SrcBadge({ type }: { type: string }) {
  return <span className={`sl-src ${type}`}>{type}</span>
}

function SanBadge({ status }: { status: string }) {
  return <span className={`sl-san ${status}`}>{status}</span>
}

function EmbBadge({ status }: { status: string }) {
  const icon = status === 'complete' ? '🟢' : status === 'failed' ? '🔴' : '⏳'
  return <span className={`sl-emb ${status}`}>{icon} {status}</span>
}

function RiskBadge({ score, band }: { score: number | null; band: SubmissionRow['risk_band'] }) {
  if (score === null || band === null) return <span className="sl-risk sl-risk-pending">Pending</span>
  return <span className={`sl-risk sl-risk-${band}`}>{band} · {score}</span>
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function SubmissionsList({ onSelectSubmission }: Props) {
  const { authFetch } = useAuth()

  const [items, setItems]           = useState<SubmissionRow[]>([])
  const [total, setTotal]           = useState(0)
  const [page, setPage]             = useState(1)
  const [sourceFilter, setSource]   = useState('')
  const [loading, setLoading]       = useState(false)

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const load = useCallback(async (p: number, src: string) => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(p), page_size: String(PAGE_SIZE) })
      if (src) params.set('source_type', src)
      const r = await authFetch(`/api/submissions?${params}`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const data = await r.json() as PaginatedResponse
      setItems(data.items)
      setTotal(data.total)
    } catch {
      setItems([])
    } finally {
      setLoading(false)
    }
  }, [authFetch])

  useEffect(() => {
    load(page, sourceFilter)
  }, [load, page, sourceFilter])

  function handleFilter(src: string) {
    setSource(src)
    setPage(1)
  }

  return (
    <div className="sl-root">
      {/* Toolbar */}
      <div className="sl-toolbar">
        <select
          id="sl-source-filter"
          className="sl-filter-select"
          value={sourceFilter}
          onChange={e => handleFilter(e.target.value)}
        >
          <option value="">All sources</option>
          <option value="alert">Alert</option>
          <option value="log">Log</option>
          <option value="report">Report</option>
          <option value="freeform">Freeform</option>
        </select>

        <span className="sl-count">
          {loading ? 'Loading…' : `${total} submission${total !== 1 ? 's' : ''}`}
        </span>

        <button
          id="sl-refresh-btn"
          className="sl-refresh-btn"
          onClick={() => load(page, sourceFilter)}
          disabled={loading}
        >
          🔄 Refresh
        </button>
      </div>

      {/* Table */}
      <div className="sl-table-wrap">
        <table className="sl-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Source</th>
              <th>Submitted</th>
              <th>Sanitization</th>
              <th>Embedding</th>
              <th>Findings</th>
              <th>Risk</th>
              <th>Preview</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr className="sl-loading-row">
                <td colSpan={9}>Loading submissions…</td>
              </tr>
            )}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--clr-text-muted)' }}>
                  No submissions found. Submit your first security artifact above.
                </td>
              </tr>
            )}
            {!loading && items.map(sub => (
              <tr
                key={sub.id}
                id={`sl-row-${sub.id}`}
                className="sl-row"
                onClick={() => onSelectSubmission(sub.id)}
              >
                <td className="sl-id">#{sub.id}</td>
                <td><SrcBadge type={sub.source_type} /></td>
                <td className="sl-date">{fmtDate(sub.submitted_at)}</td>
                <td><SanBadge status={sub.sanitization_status} /></td>
                <td><EmbBadge status={sub.embedding_status} /></td>
                <td className="sl-severity-summary" aria-label={`Critical ${sub.findings_by_severity.critical}, high ${sub.findings_by_severity.high}, medium ${sub.findings_by_severity.medium}, low ${sub.findings_by_severity.low}`}>
                  <span className="critical">C {sub.findings_by_severity.critical}</span>
                  <span className="high">H {sub.findings_by_severity.high}</span>
                  <span className="medium">M {sub.findings_by_severity.medium}</span>
                  <span className="low">L {sub.findings_by_severity.low}</span>
                </td>
                <td><RiskBadge score={sub.risk_score} band={sub.risk_band} /></td>
                <td style={{ maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--clr-text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                  {sub.sanitized_text?.slice(0, 80) ?? '—'}
                </td>
                <td>
                  <button
                    className="sl-view-btn"
                    onClick={e => { e.stopPropagation(); onSelectSubmission(sub.id) }}
                  >
                    View →
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="sl-pagination">
          <button
            id="sl-prev-btn"
            className="sl-page-btn"
            disabled={page <= 1}
            onClick={() => setPage(p => p - 1)}
          >
            ‹ Prev
          </button>
          <span>Page {page} of {totalPages}</span>
          <button
            id="sl-next-btn"
            className="sl-page-btn"
            disabled={page >= totalPages}
            onClick={() => setPage(p => p + 1)}
          >
            Next ›
          </button>
        </div>
      )}
    </div>
  )
}

/**
 * SemanticSearch
 *
 * AI-powered search bar that calls POST /api/search/semantic and renders
 * results ranked by cosine similarity, with a visual gauge per result.
 */
import { useState, type FormEvent } from 'react'
import { useAuth } from '../context/AuthContext'
import './SemanticSearch.css'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SearchResult {
  id: number
  source_type: string
  sanitized_text_preview: string
  similarity: number
  submitted_at: string
  embedding_status: string
}

interface SearchResponse {
  results: SearchResult[]
  query: string
  top_k: number
  total_found: number
}

interface Props {
  /** Called when the user clicks a result row (e.g. to open findings). */
  onSelectSubmission?: (id: number) => void
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function simClass(score: number): 'high' | 'medium' | 'low' {
  if (score >= 0.8) return 'high'
  if (score >= 0.55) return 'medium'
  return 'low'
}

function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function SemanticSearch({ onSelectSubmission }: Props) {
  const { authFetch } = useAuth()

  const [query, setQuery]       = useState('')
  const [topK, setTopK]         = useState(10)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState<string | null>(null)
  const [response, setResponse] = useState<SearchResponse | null>(null)

  const handleSearch = async (e: FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setError(null)

    try {
      const r = await authFetch('/api/search/semantic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: query.trim(), top_k: topK }),
      })

      if (r.status === 503) {
        setError(
          'Embeddings service unavailable. Configure EMBEDDINGS_API_KEY to enable semantic search.',
        )
        return
      }
      if (!r.ok) {
        const body = await r.json().catch(() => ({}))
        throw new Error((body as { detail?: string }).detail ?? `HTTP ${r.status}`)
      }

      setResponse(await r.json() as SearchResponse)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Search failed')
    } finally {
      setLoading(false)
    }
  }

  const results = response?.results ?? []

  return (
    <div className="ss-root">
      {/* Search bar */}
      <form id="ss-form" onSubmit={handleSearch}>
        <div className="ss-bar">
          <div className="ss-input-wrap">
            <input
              id="ss-query-input"
              className="ss-input"
              placeholder="Describe what you're looking for… (e.g. 'PowerShell C2 beacon')"
              value={query}
              onChange={e => setQuery(e.target.value)}
              disabled={loading}
            />
            <span className="ss-icon">🔍</span>
          </div>

          <input
            id="ss-topk-input"
            type="number"
            className="ss-topk"
            min={1}
            max={50}
            value={topK}
            onChange={e => setTopK(Math.min(50, Math.max(1, Number(e.target.value))))}
            title="Max results (1–50)"
            disabled={loading}
          />

          <button
            id="ss-search-btn"
            type="submit"
            className="ss-btn"
            disabled={loading || !query.trim()}
          >
            {loading ? '⏳ Searching…' : '⚡ Search'}
          </button>
        </div>
      </form>

      {/* Error banner */}
      {error && <div className="ss-error">⚠ {error}</div>}

      {/* Summary line */}
      <div className="ss-summary">
        {response && !loading && (
          <>
            Found <strong>{response.total_found}</strong> result
            {response.total_found !== 1 ? 's' : ''} for &ldquo;{response.query}&rdquo;
          </>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <div className="ss-loading">
          <span>Embedding query &amp; running similarity search</span>
          <span className="ss-loading-dots" />
        </div>
      )}

      {/* Empty state (after a search returned nothing) */}
      {!loading && response && results.length === 0 && (
        <div className="ss-empty">
          <span className="ss-empty-icon">🧩</span>
          No semantically similar submissions found.
          <br />
          Try broadening your query or submit more artifacts first.
        </div>
      )}

      {/* Results list */}
      {!loading && results.length > 0 && (
        <div className="ss-list">
          {results.map(res => {
            const cls = simClass(res.similarity)
            const pct = Math.round(res.similarity * 100)
            return (
              <div
                key={res.id}
                id={`ss-result-${res.id}`}
                className="ss-card"
                onClick={() => onSelectSubmission?.(res.id)}
                style={{ cursor: onSelectSubmission ? 'pointer' : 'default' }}
                role={onSelectSubmission ? 'button' : undefined}
                tabIndex={onSelectSubmission ? 0 : undefined}
                onKeyDown={onSelectSubmission
                  ? e => e.key === 'Enter' && onSelectSubmission(res.id)
                  : undefined
                }
              >
                {/* Similarity gauge */}
                <div className="ss-gauge">
                  <div className={`ss-gauge-ring ${cls}`}>
                    {pct}%
                  </div>
                  <span className="ss-gauge-label">match</span>
                </div>

                {/* Card body */}
                <div className="ss-body">
                  <div className="ss-card-header">
                    <span className="ss-card-id">#{res.id}</span>
                    <span className="ss-src-badge">{res.source_type}</span>
                    <span className="ss-date">{fmtDate(res.submitted_at)}</span>
                  </div>

                  <div className="ss-snippet">
                    {res.sanitized_text_preview || <em>No preview available</em>}
                  </div>

                  {/* Similarity bar */}
                  <div className="ss-sim-bar-wrap">
                    <div
                      className={`ss-sim-bar ${cls}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

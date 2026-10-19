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
  network_results: NetworkSearchResult[]
  network_search_attempted: boolean
  network_search_error: string | null
  query: string
  top_k: number
  total_found: number
}

interface NetworkSearchResult {
  sanitized_text: string
  mitre_technique_ids: string[]
  severity: string[]
  similarity_score: number
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
  const [searchNetwork, setSearchNetwork] = useState(false)
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
        body: JSON.stringify({
          query: query.trim(),
          top_k: topK,
          search_network: searchNetwork,
        }),
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
  const networkResults = response?.network_results ?? []

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

      <label className="ss-network-toggle">
        <input
          type="checkbox"
          checked={searchNetwork}
          onChange={e => setSearchNetwork(e.target.checked)}
          disabled={loading}
        />
        <span>Also search the shared network</span>
        <span className="ss-network-note">Only anonymized results from other organizations</span>
      </label>

      {/* Error banner */}
      {error && <div className="ss-error">⚠ {error}</div>}
      {response?.network_search_error && (
        <div className="ss-network-warning" role="status">
          {response.network_search_error} Your organization’s results are unaffected.
        </div>
      )}

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
      {!loading && response && results.length === 0 && networkResults.length === 0 && (
        <div className="ss-empty">
          <span className="ss-empty-icon">🧩</span>
          No semantically similar submissions found.
          <br />
          Try broadening your query or submit more artifacts first.
        </div>
      )}

      {/* Results list */}
      {!loading && response && (
        <>
          <section className="ss-result-group" aria-labelledby="ss-local-heading">
            <h2 id="ss-local-heading" className="ss-group-heading">
              From your organization <span>{results.length}</span>
            </h2>
            {results.length > 0 ? (
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
                    <span className="ss-src-badge">Your organization · {res.source_type}</span>
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
            ) : (
              <p className="ss-group-empty">No matching incidents from your organization.</p>
            )}
          </section>

          {response.network_search_attempted && (
            <section className="ss-result-group" aria-labelledby="ss-network-heading">
              <h2 id="ss-network-heading" className="ss-group-heading">
                From the network <span>{networkResults.length}</span>
              </h2>
              {networkResults.length > 0 ? (
                <div className="ss-list">
                  {networkResults.map((res, index) => {
                    const cls = simClass(res.similarity_score)
                    const pct = Math.max(0, Math.min(100, Math.round(res.similarity_score * 100)))
                    return (
                      <article key={`network-${index}`} className="ss-card">
                        <div className="ss-gauge">
                          <div className={`ss-gauge-ring ${cls}`}>{pct}%</div>
                          <span className="ss-gauge-label">match</span>
                        </div>
                        <div className="ss-body">
                          <div className="ss-card-header">
                            <span className="ss-src-badge ss-network-badge">Shared network · anonymized</span>
                            {res.severity.map(value => (
                              <span key={value} className={`ss-severity-badge ${value}`}>{value}</span>
                            ))}
                          </div>
                          {res.mitre_technique_ids.length > 0 && (
                            <div className="ss-network-techniques">
                              {res.mitre_technique_ids.join(', ')}
                            </div>
                          )}
                          <div className="ss-snippet">{res.sanitized_text || <em>No text available</em>}</div>
                          <div className="ss-sim-bar-wrap">
                            <div className={`ss-sim-bar ${cls}`} style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      </article>
                    )
                  })}
                </div>
              ) : (
                <p className="ss-group-empty">
                  {response.network_search_error
                    ? 'No network results are available for this search.'
                    : 'No similar incidents from other organizations were found.'}
                </p>
              )}
            </section>
          )}
        </>
      )}
    </div>
  )
}

import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import './MemoryNetwork.css'

interface MemoryNode {
  id: number
  signature_type: 'mitre_technique' | 'rule' | 'embedding_cluster'
  signature_key: string
  first_seen: string
  last_seen: string
  occurrence_count: number
  status: 'active' | 'dormant'
  is_recurring: boolean
  recurrence_window_days: number
  recurrence_threshold: number
  summary: string | null
}

interface PaginatedNodes {
  total: number
  page: number
  page_size: number
  items: MemoryNode[]
}

interface TimelineLink {
  id: number
  finding_id: number | null
  linked_at: string
  link_reason: 'shared_technique' | 'shared_rule' | 'embedding_similarity'
  similarity_score: number | null
  submission: {
    id: number
    source_type: string
    submitted_at: string
    sanitization_status: string
    sanitized_text: string | null
  }
  finding: {
    id: number
    rule_id: number
    severity: string
    matched_snippet: string | null
    created_at: string
  } | null
}

interface PaginatedTimeline {
  total: number
  page: number
  page_size: number
  items: TimelineLink[]
}

const PAGE_SIZE = 20

function formatDate(value: string): string {
  return new Date(value).toLocaleString()
}

function signatureLabel(type: MemoryNode['signature_type']): string {
  return type.replaceAll('_', ' ')
}

interface Props {
  nodeId: number | null
  onSelectNode: (id: number) => void
  onBack: () => void
}

export default function MemoryNetwork({ nodeId, onSelectNode, onBack }: Props) {
  const { authFetch } = useAuth()
  const [nodes, setNodes] = useState<MemoryNode[]>([])
  const [campaignIds, setCampaignIds] = useState<Set<number>>(new Set())
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedNode, setSelectedNode] = useState<MemoryNode | null>(null)
  const [timeline, setTimeline] = useState<PaginatedTimeline | null>(null)
  const [timelinePage, setTimelinePage] = useState(1)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState<string | null>(null)

  const loadNodes = useCallback(async (requestedPage: number) => {
    setLoading(true)
    setError(null)
    try {
      const [nodeResponse, campaignResponse] = await Promise.all([
        authFetch(`/api/memory/nodes?page=${requestedPage}&page_size=${PAGE_SIZE}`),
        authFetch('/api/memory/campaigns'),
      ])
      if (!nodeResponse.ok) throw new Error(`Memory nodes: HTTP ${nodeResponse.status}`)
      if (!campaignResponse.ok) throw new Error(`Campaigns: HTTP ${campaignResponse.status}`)
      const data = await nodeResponse.json() as PaginatedNodes
      const campaigns = await campaignResponse.json() as Array<{ id: number }>
      setNodes(data.items)
      setTotal(data.total)
      setCampaignIds(new Set(campaigns.map(campaign => campaign.id)))
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : 'Failed to load memory network')
      setNodes([])
    } finally {
      setLoading(false)
    }
  }, [authFetch])

  const loadTimeline = useCallback(async (id: number, requestedPage: number) => {
    setDetailLoading(true)
    setDetailError(null)
    try {
      const [nodeResponse, timelineResponse] = await Promise.all([
        authFetch(`/api/memory/nodes/${id}`),
        authFetch(`/api/memory/nodes/${id}/timeline?page=${requestedPage}&page_size=${PAGE_SIZE}`),
      ])
      if (!nodeResponse.ok) throw new Error(`Memory node: HTTP ${nodeResponse.status}`)
      if (!timelineResponse.ok) throw new Error(`Timeline: HTTP ${timelineResponse.status}`)
      setSelectedNode(await nodeResponse.json() as MemoryNode)
      setTimeline(await timelineResponse.json() as PaginatedTimeline)
    } catch (cause: unknown) {
      setDetailError(cause instanceof Error ? cause.message : 'Failed to load memory timeline')
      setSelectedNode(null)
      setTimeline(null)
    } finally {
      setDetailLoading(false)
    }
  }, [authFetch])

  useEffect(() => {
    if (nodeId === null) {
      setSelectedNode(null)
      setTimeline(null)
      void loadNodes(page)
    } else {
      setTimelinePage(1)
      void loadTimeline(nodeId, 1)
    }
  }, [loadNodes, loadTimeline, nodeId, page])

  useEffect(() => {
    if (nodeId !== null && timelinePage > 1) {
      void loadTimeline(nodeId, timelinePage)
    }
  }, [loadTimeline, nodeId, timelinePage])

  const orderedNodes = [...nodes].sort((left, right) => {
    const recurringDifference = Number(campaignIds.has(right.id)) - Number(campaignIds.has(left.id))
    return recurringDifference || new Date(right.last_seen).getTime() - new Date(left.last_seen).getTime()
  })

  if (nodeId !== null) {
    const pageCount = Math.max(1, Math.ceil((timeline?.total ?? 0) / PAGE_SIZE))
    return (
      <section className="mn-root">
        <button className="mn-back" type="button" onClick={onBack}>← Memory Network</button>
        {detailLoading && <p className="mn-message">Loading timeline…</p>}
        {detailError && <p className="mn-error" role="alert">{detailError}</p>}
        {selectedNode && (
          <>
            <article className="mn-detail-card">
              <div className="mn-node-heading">
                <div>
                  <span className="mn-signature-type">{signatureLabel(selectedNode.signature_type)}</span>
                  <h2>{selectedNode.signature_key}</h2>
                </div>
                <span className={`mn-status ${selectedNode.status}`}>{selectedNode.status}</span>
              </div>
              <div className="mn-node-facts">
                <span><strong>{selectedNode.occurrence_count}</strong> occurrences</span>
                <span>First seen {formatDate(selectedNode.first_seen)}</span>
                <span>Last seen {formatDate(selectedNode.last_seen)}</span>
                {selectedNode.is_recurring && <span className="mn-campaign-tag">Recurring pattern</span>}
              </div>
            </article>

            <div className="mn-section-heading">
              <div>
                <h2>Activity timeline</h2>
                <p>{timeline?.total ?? 0} linked event{timeline?.total === 1 ? '' : 's'}, oldest first</p>
              </div>
            </div>
            {!detailLoading && timeline?.items.length === 0 && (
              <p className="mn-message">No linked activity is available for this node.</p>
            )}
            <ol className="mn-timeline">
              {timeline?.items.map(link => (
                <li className="mn-timeline-item" key={link.id}>
                  <span className="mn-timeline-dot" />
                  <article className="mn-event-card">
                    <div className="mn-event-topline">
                      <time dateTime={link.linked_at}>{formatDate(link.linked_at)}</time>
                      <span className="mn-reason">{link.link_reason.replaceAll('_', ' ')}</span>
                    </div>
                    <h3>Submission #{link.submission.id} · {link.submission.source_type}</h3>
                    <p className="mn-event-meta">
                      Submitted {formatDate(link.submission.submitted_at)}
                      {' · '}{link.submission.sanitization_status}
                    </p>
                    {link.finding && (
                      <div className="mn-finding">
                        <span className={`mn-severity ${link.finding.severity}`}>{link.finding.severity}</span>
                        <span>Finding #{link.finding.id} · Rule #{link.finding.rule_id}</span>
                        {link.finding.matched_snippet && <p>{link.finding.matched_snippet}</p>}
                      </div>
                    )}
                    {link.similarity_score !== null && (
                      <p className="mn-similarity">Cosine similarity {(link.similarity_score * 100).toFixed(1)}%</p>
                    )}
                    {link.submission.sanitized_text && (
                      <p className="mn-submission-preview">{link.submission.sanitized_text}</p>
                    )}
                  </article>
                </li>
              ))}
            </ol>
            {pageCount > 1 && (
              <div className="mn-pagination">
                <button type="button" onClick={() => setTimelinePage(value => Math.max(1, value - 1))} disabled={timelinePage <= 1 || detailLoading}>Previous</button>
                <span>Page {timelinePage} of {pageCount}</span>
                <button type="button" onClick={() => setTimelinePage(value => Math.min(pageCount, value + 1))} disabled={timelinePage >= pageCount || detailLoading}>Next</button>
              </div>
            )}
          </>
        )}
      </section>
    )
  }

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  return (
    <section className="mn-root">
      <div className="mn-overview-intro">
        <div>
          <p>Correlated activity across submissions, detections, and recurring patterns.</p>
          <span>{total} memory node{total === 1 ? '' : 's'} · recurring campaigns are prioritized</span>
        </div>
        <button className="mn-refresh" type="button" onClick={() => loadNodes(page)} disabled={loading}>Refresh</button>
      </div>
      {error && <p className="mn-error" role="alert">{error}</p>}
      {loading && <p className="mn-message">Loading memory network…</p>}
      {!loading && !error && orderedNodes.length === 0 && (
        <div className="mn-empty">
          <h2>No memory nodes yet</h2>
          <p>Nodes appear here after submissions produce findings or similar embeddings.</p>
        </div>
      )}
      <div className="mn-node-grid">
        {orderedNodes.map(node => (
          <button className="mn-node-card" type="button" key={node.id} onClick={() => onSelectNode(node.id)}>
            <div className="mn-node-heading">
              <div>
                <span className="mn-signature-type">{signatureLabel(node.signature_type)}</span>
                <h2>{node.signature_key}</h2>
              </div>
              <span className={`mn-status ${node.status}`}>{node.status}</span>
            </div>
            <div className="mn-node-facts">
              <span><strong>{node.occurrence_count}</strong> occurrences</span>
              <span>First seen {formatDate(node.first_seen)}</span>
              <span>Last seen {formatDate(node.last_seen)}</span>
            </div>
            {campaignIds.has(node.id) && <span className="mn-campaign-tag">Recurring campaign</span>}
            {node.summary && <p className="mn-node-summary">{node.summary}</p>}
            <span className="mn-card-link">View activity timeline →</span>
          </button>
        ))}
      </div>
      {pageCount > 1 && (
        <div className="mn-pagination">
          <button type="button" onClick={() => setPage(value => Math.max(1, value - 1))} disabled={page <= 1 || loading}>Previous</button>
          <span>Page {page} of {pageCount}</span>
          <button type="button" onClick={() => setPage(value => Math.min(pageCount, value + 1))} disabled={page >= pageCount || loading}>Next</button>
        </div>
      )}
    </section>
  )
}

import { useEffect, useRef, useState } from 'react'
import './index.css'
import { AuthProvider, useAuth } from './context/AuthContext'
import AuthPage from './pages/AuthPage'
import DashboardHome from './pages/DashboardHome'
import FindingsPanel from './pages/FindingsPanel'
import SubmissionDetail from './pages/SubmissionDetail'
import SubmissionsList from './pages/SubmissionsList'
import SubmissionIntake from './pages/SubmissionIntake'
import SemanticSearch from './pages/SemanticSearch'
import './pages/WorkspaceShell.css'

type HealthStatus = 'loading' | 'ok' | 'error'

interface ApiHealth { status: string }
interface Submission { id: number; source_type: string; submitted_at: string; sanitization_status: string }

const SOURCE_TYPES = ['alert', 'log', 'report', 'freeform'] as const

// ── Dashboard ─────────────────────────────────────────────────────────────────

export function Dashboard() {
  const { user, logout, authFetch } = useAuth()
  const [healthStatus, setHealthStatus] = useState<HealthStatus>('loading')
  const [apiData, setApiData]           = useState<ApiHealth | null>(null)

  // Submission form
  const [rawText, setRawText]       = useState('')
  const [srcType, setSrcType]       = useState<string>('alert')
  const [submitting, setSubmitting] = useState(false)
  const [subError, setSubError]     = useState<string | null>(null)
  const [subSuccess, setSubSuccess] = useState<string | null>(null)

  // Findings view
  const [activeSubId, setActiveSubId]         = useState<number | null>(null)
  const [recentSubs, setRecentSubs]           = useState<Submission[]>([])
  const findingsPanelRef = useRef<HTMLDivElement>(null)

  // Health check
  useEffect(() => {
    fetch('/api/health')
      .then(r => { if (!r.ok) throw new Error(); return r.json() as Promise<ApiHealth> })
      .then(d => { setApiData(d); setHealthStatus(d.status === 'ok' ? 'ok' : 'error') })
      .catch(() => setHealthStatus('error'))
  }, [])

  // Load recent submissions
  const loadRecentSubs = async () => {
    const r = await authFetch('/api/submissions?limit=5')
    if (r.ok) setRecentSubs((await r.json()).items ?? await r.clone().json())
  }

  useEffect(() => { void loadRecentSubs() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  // Submit
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!rawText.trim()) return
    setSubmitting(true); setSubError(null); setSubSuccess(null)
    try {
      const r = await authFetch('/api/submissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_text: rawText, source_type: srcType }),
      })
      if (!r.ok) {
        const b = await r.json().catch(() => ({}))
        throw new Error((b as { detail?: string }).detail ?? `HTTP ${r.status}`)
      }
      const sub: Submission = await r.json()
      setSubSuccess(`Submitted #${sub.id} (${sub.sanitization_status})`)
      setRawText('')
      setActiveSubId(sub.id)
      await loadRecentSubs()
      setTimeout(() => findingsPanelRef.current?.scrollIntoView({ behavior: 'smooth' }), 150)
    } catch (e: unknown) {
      setSubError(e instanceof Error ? e.message : 'Submission failed')
    } finally {
      setSubmitting(false)
    }
  }

  const chipLabel: Record<HealthStatus, string> = {
    loading: 'Checking…', ok: 'Operational', error: 'Unreachable',
  }

  return (
    <div className="app">
      {/* ── Nav ── */}
      <nav className="nav">
        <a href="/" className="nav-brand">
          <span className="brand-icon">⚡</span>Cyber Network
        </a>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <span className="nav-badge">
            {user?.role === 'admin' ? '👑 Admin' : '🔎 Analyst'} · {user?.email}
          </span>
          <button
            id="nav-logout-btn"
            onClick={logout}
            style={{
              background: 'transparent', border: '1px solid var(--clr-border)',
              borderRadius: 'var(--radius-sm)', color: 'var(--clr-text-muted)',
              padding: '4px 12px', fontSize: '0.75rem', cursor: 'pointer',
              fontFamily: 'var(--font-sans)', transition: 'color 0.2s, border-color 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--clr-danger)'; e.currentTarget.style.borderColor = 'rgba(239,68,68,0.4)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--clr-text-muted)'; e.currentTarget.style.borderColor = 'var(--clr-border)' }}
          >
            Sign Out
          </button>
        </div>
      </nav>

      <main className="hero">
        <p className="hero-eyebrow">Cybersecurity Data-Reasoning Platform</p>
        <h1 className="hero-title">Intelligence at the<br />Speed of Threats</h1>

        {/* ── Status card ── */}
        <div className="status-card">
          <span className="status-card-title">System Status</span>
          <div className="status-row">
            <span className="status-label">Backend API</span>
            <span className={`status-chip ${healthStatus}`}>
              <span className="dot" />{chipLabel[healthStatus]}
            </span>
          </div>
          <div className="status-row">
            <span className="status-label">GET /api/health</span>
            <code style={{ fontSize: '0.75rem', color: 'var(--clr-text-muted)' }}>
              {apiData ? JSON.stringify(apiData) : '—'}
            </code>
          </div>
          <div className="status-row">
            <span className="status-label">Authenticated as</span>
            <code style={{ fontSize: '0.75rem', color: 'var(--clr-accent)' }}>{user?.email}</code>
          </div>
          <div className="divider" />
          <div className="status-row">
            <a className="docs-link" href="/api/docs" target="_blank" rel="noreferrer">📄 Swagger UI →</a>
            <a className="docs-link" href="/api/redoc" target="_blank" rel="noreferrer">📘 ReDoc →</a>
          </div>
        </div>

        {/* ── Submission form ── */}
        <div className="status-card" style={{ marginTop: '1.5rem', width: '100%', maxWidth: '760px' }}>
          <span className="status-card-title">🗂 Submit Security Artifact</span>
          <form id="submission-form" onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
            <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--clr-text-muted)', fontWeight: 500 }}>Source type</label>
              {SOURCE_TYPES.map(t => (
                <button
                  key={t}
                  type="button"
                  id={`src-type-${t}`}
                  onClick={() => setSrcType(t)}
                  style={{
                    padding: '3px 10px', borderRadius: '999px', fontSize: '0.72rem', fontWeight: 600,
                    cursor: 'pointer', fontFamily: 'var(--font-sans)',
                    background: srcType === t ? 'rgba(0,200,255,0.14)' : 'transparent',
                    border: `1px solid ${srcType === t ? 'rgba(0,200,255,0.4)' : 'var(--clr-border)'}`,
                    color: srcType === t ? 'var(--clr-accent)' : 'var(--clr-text-muted)',
                    transition: 'all 0.15s',
                  }}
                >
                  {t}
                </button>
              ))}
            </div>

            <textarea
              id="submission-text-input"
              rows={5}
              placeholder="Paste alert text, log line, or threat report excerpt here…"
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              style={{
                width: '100%', background: 'var(--clr-surface-2)', border: '1px solid var(--clr-border)',
                borderRadius: 'var(--radius-sm)', color: 'var(--clr-text)', fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem', padding: '0.6rem 0.8rem', resize: 'vertical', outline: 'none',
                transition: 'border-color 0.2s', lineHeight: 1.6,
              }}
              onFocus={e => { e.currentTarget.style.borderColor = 'rgba(0,200,255,0.4)' }}
              onBlur={e => { e.currentTarget.style.borderColor = 'var(--clr-border)' }}
            />

            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                id="submit-artifact-btn"
                type="submit"
                disabled={submitting || !rawText.trim()}
                style={{
                  padding: '7px 20px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(0,200,255,0.35)',
                  background: 'rgba(0,200,255,0.12)', color: 'var(--clr-accent)', fontFamily: 'var(--font-sans)',
                  fontSize: '0.8rem', fontWeight: 700, cursor: submitting ? 'not-allowed' : 'pointer',
                  opacity: submitting || !rawText.trim() ? 0.5 : 1, transition: 'background 0.18s',
                }}
              >
                {submitting ? '⏳ Submitting…' : '➕ Submit & Sanitize'}
              </button>

              {subSuccess && <span style={{ fontSize: '0.78rem', color: 'var(--clr-success)' }}>✓ {subSuccess}</span>}
              {subError   && <span style={{ fontSize: '0.78rem', color: 'var(--clr-danger)' }}>⚠ {subError}</span>}
            </div>
          </form>

          {/* Recent submissions picker */}
          {recentSubs.length > 0 && (
            <div style={{ marginTop: '0.9rem' }}>
              <div className="divider" style={{ marginBottom: '0.75rem' }} />
              <span style={{ fontSize: '0.72rem', color: 'var(--clr-text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Recent submissions
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', marginTop: '0.5rem' }}>
                {recentSubs.map(s => (
                  <button
                    key={s.id}
                    id={`recent-sub-${s.id}`}
                    onClick={() => {
                      setActiveSubId(s.id)
                      setTimeout(() => findingsPanelRef.current?.scrollIntoView({ behavior: 'smooth' }), 100)
                    }}
                    style={{
                      padding: '3px 10px', borderRadius: '999px', fontSize: '0.7rem', fontWeight: 600,
                      cursor: 'pointer', fontFamily: 'var(--font-sans)',
                      background: activeSubId === s.id ? 'rgba(0,200,255,0.14)' : 'transparent',
                      border: `1px solid ${activeSubId === s.id ? 'rgba(0,200,255,0.4)' : 'var(--clr-border)'}`,
                      color: activeSubId === s.id ? 'var(--clr-accent)' : 'var(--clr-text-muted)',
                      transition: 'all 0.15s',
                    }}
                  >
                    #{s.id} · {s.source_type} · {s.sanitization_status}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Findings panel ── */}
        {activeSubId !== null && (
          <div
            ref={findingsPanelRef}
            className="status-card"
            style={{ marginTop: '1.5rem', width: '100%', maxWidth: '900px' }}
          >
            <FindingsPanel
              submissionId={activeSubId}
              onClose={() => setActiveSubId(null)}
            />
          </div>
        )}

        {/* ── Semantic search ── */}
        <div className="status-card" style={{ marginTop: '1.5rem', width: '100%', maxWidth: '900px' }}>
          <span className="status-card-title" style={{ marginBottom: '1rem', display: 'block' }}>
            🧠 Semantic Search
          </span>
          <SemanticSearch
            onSelectSubmission={(id) => {
              setActiveSubId(id)
              setTimeout(() => findingsPanelRef.current?.scrollIntoView({ behavior: 'smooth' }), 100)
            }}
          />
        </div>
      </main>

      <footer className="footer">
        Cyber Network · Milestone 5 — Embedding &amp; Semantic Search
      </footer>
    </div>
  )
}

// ── Root ──────────────────────────────────────────────────────────────────────

function AppInner() {
  const { isAuthenticated, user, logout } = useAuth()
  const [path, setPath] = useState(window.location.pathname)

  useEffect(() => {
    const updatePath = () => setPath(window.location.pathname)
    window.addEventListener('popstate', updatePath)
    return () => window.removeEventListener('popstate', updatePath)
  }, [])

  const navigate = (destination: string) => {
    window.history.pushState({}, '', destination)
    setPath(destination)
  }

  if (!isAuthenticated) {
    return <AuthPage onSuccess={() => navigate('/')} />
  }

  const detailMatch = path.match(/^\/submissions\/(\d+)$/)
  const activePath = detailMatch ? '/submissions' : path
  const pageTitle = detailMatch
    ? `Submission #${detailMatch[1]}`
    : path === '/submissions/new' ? 'New submission'
      : path === '/submissions' ? 'Submissions'
        : path === '/search' ? 'Semantic search' : 'Analyst overview'

  return (
    <div className="app workspace-app">
      <nav className="nav workspace-nav" aria-label="Main navigation">
        <a href="/" className="nav-brand" onClick={event => { event.preventDefault(); navigate('/') }}>
          <span className="brand-icon">CN</span>Cyber Network
        </a>
        <div className="workspace-links">
          <a className={activePath === '/' ? 'active' : ''} href="/" onClick={event => { event.preventDefault(); navigate('/') }}>Overview</a>
          <a className={activePath === '/submissions' ? 'active' : ''} href="/submissions" onClick={event => { event.preventDefault(); navigate('/submissions') }}>Submissions</a>
          <a className={activePath === '/submissions/new' ? 'active' : ''} href="/submissions/new" onClick={event => { event.preventDefault(); navigate('/submissions/new') }}>Intake</a>
          <a className={activePath === '/search' ? 'active' : ''} href="/search" onClick={event => { event.preventDefault(); navigate('/search') }}>Semantic search</a>
        </div>
        <div className="workspace-account">
          <span className="nav-badge">{user?.role} · {user?.email}</span>
          <button type="button" className="workspace-logout" onClick={logout} aria-label="Sign out">Sign out</button>
        </div>
      </nav>

      <main className="workspace-main">
        <header className="workspace-heading">
          <div>
            <p className="workspace-kicker">Cyber Network / Analyst workspace</p>
            <h1>{pageTitle}</h1>
          </div>
          <a className="workspace-primary" href="/submissions/new" onClick={event => { event.preventDefault(); navigate('/submissions/new') }}>＋ New submission</a>
        </header>

        {path === '/submissions/new' ? (
          <SubmissionIntake onCreated={id => navigate(`/submissions/${id}`)} />
        ) : path === '/submissions' ? (
          <SubmissionsList onSelectSubmission={id => navigate(`/submissions/${id}`)} />
        ) : detailMatch ? (
          <SubmissionDetail submissionId={Number(detailMatch[1])} onBack={() => navigate('/submissions')} />
        ) : path === '/search' ? (
          <SemanticSearch onSelectSubmission={id => navigate(`/submissions/${id}`)} />
        ) : (
          <DashboardHome onNavigate={page => navigate(page === 'search' ? '/search' : '/submissions')} />
        )}
      </main>
      <footer className="footer">Cyber Network · Stage 1 analyst workspace</footer>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  )
}


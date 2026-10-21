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
import MemoryNetwork from './pages/MemoryNetwork'
import NetworkSettings from './pages/NetworkSettings'
import CentralAdmin from './pages/CentralAdmin'
import Analytics from './pages/Analytics'
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

function NavIcon({ name }: { name: string }) {
  const paths: Record<string, string> = {
    dashboard: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
    incidents: 'M12 3.5 19 6v5.5c0 4.5-3 7.3-7 9-4-1.7-7-4.5-7-9V6l7-2.5Z',
    add: 'M12 5v14M5 12h14',
    search: 'M10.8 17.2a6.4 6.4 0 1 1 0-12.8 6.4 6.4 0 0 1 0 12.8ZM16 16l4.2 4.2',
    network: 'M12 12 5 5M12 12l7-7M12 12l-7 7M12 12l7 7',
    analytics: 'M4 19V5M4 19h16M7 15l4-4 3 2 5-6',
    settings: 'M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7ZM19.4 13.5l1.1.8-1.5 2.6-1.3-.5a7.8 7.8 0 0 1-1.5.9L16 18.7h-3l-.3-1.4a7.8 7.8 0 0 1-1.5-.9l-1.3.5-1.5-2.6 1.1-.8a7.1 7.1 0 0 1 0-1.8l-1.1-.8 1.5-2.6 1.3.5a7.8 7.8 0 0 1 1.5-.9L13 6.7h3l.3 1.4a7.8 7.8 0 0 1 1.5.9l1.3-.5 1.5 2.6-1.1.8a7.1 7.1 0 0 1-.1 1.6Z',
    admin: 'M12 3 20 7.5v9L12 21l-8-4.5v-9L12 3ZM8 12h8M12 8v8',
  }

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={paths[name] ?? paths.dashboard} />
      {name === 'network' && (
        <>
          <circle cx="12" cy="12" r="2.5" />
          <circle cx="5" cy="5" r="1.8" />
          <circle cx="19" cy="5" r="1.8" />
          <circle cx="5" cy="19" r="1.8" />
          <circle cx="19" cy="19" r="1.8" />
        </>
      )}
    </svg>
  )
}

function AppInner() {
  const { isAuthenticated, user, logout } = useAuth()
  const [path, setPath] = useState(window.location.pathname)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    const updatePath = () => setPath(window.location.pathname)
    window.addEventListener('popstate', updatePath)
    return () => window.removeEventListener('popstate', updatePath)
  }, [])

  const navigate = (destination: string) => {
    window.history.pushState({}, '', destination)
    setPath(destination)
    setSidebarOpen(false)
  }

  if (path === '/central-admin') return <CentralAdmin />

  if (!isAuthenticated) {
    return <AuthPage onSuccess={() => navigate('/')} />
  }

  const detailMatch = path.match(/^\/submissions\/(\d+)$/)
  const memoryDetailMatch = path.match(/^\/memory\/(\d+)$/)
  const activePath = detailMatch ? '/submissions' : memoryDetailMatch ? '/memory' : path
  const pageTitle = detailMatch
    ? `Submission #${detailMatch[1]}`
    : memoryDetailMatch ? 'Memory node'
      : path === '/memory' ? 'Memory Network'
        : path === '/analytics' ? 'Analytics'
        : path === '/network-settings' ? 'Network settings'
        : path === '/submissions/new' ? 'New submission'
          : path === '/submissions' ? 'Submissions'
            : path === '/search' ? 'Semantic search' : 'Analyst overview'

  const navItems = [
    { path: '/',                icon: 'dashboard', label: 'Dashboard' },
    { path: '/submissions',     icon: 'incidents', label: 'Incidents' },
    { path: '/submissions/new', icon: 'add',       label: 'New Submission' },
    { path: '/search',          icon: 'search',    label: 'Search' },
    { path: '/memory',          icon: 'network',   label: 'Memory Network' },
    { path: '/analytics',       icon: 'analytics', label: 'Analytics' },
  ]

  const adminItems = [
    { path: '/network-settings', icon: 'settings', label: 'Network Settings' },
    { path: '/central-admin',    icon: 'admin',    label: 'Central Admin' },
  ]

  return (
    <div className="app workspace-app">
      {/* ── Mobile overlay ── */}
      {sidebarOpen && <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />}

      {/* ── Sidebar ── */}
      <aside className={`sidebar${sidebarOpen ? ' sidebar-mobile-open' : ''}`} aria-label="Main navigation">
        <div className="sidebar-brand">
          <span className="sidebar-brand-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32" focusable="false">
              <path d="M16 5 25 10v11l-9 6-9-6V10l9-5Z" />
              <path d="m11 13 5-3 5 3v6l-5 3-5-3v-6Z" />
              <circle cx="16" cy="5" r="2.2" />
              <circle cx="25" cy="10" r="2.2" />
              <circle cx="7" cy="10" r="2.2" />
              <circle cx="25" cy="21" r="2.2" />
              <circle cx="7" cy="21" r="2.2" />
            </svg>
          </span>
          <span className="sidebar-brand-text">Cyber Memory Network</span>
        </div>
        <nav className="sidebar-nav">
          {navItems.map(item => (
            <a
              key={item.path}
              className={`sidebar-item${activePath === item.path ? ' active' : ''}`}
              href={item.path}
              aria-current={activePath === item.path ? 'page' : undefined}
              onClick={event => { event.preventDefault(); navigate(item.path) }}
            >
              <span className="sidebar-item-icon"><NavIcon name={item.icon} /></span>
              {item.label}
            </a>
          ))}
          {user?.role === 'admin' && (
            <>
              <span className="sidebar-section-label">Administration</span>
              {adminItems.map(item => (
                <a
                  key={item.path}
                  className={`sidebar-item${activePath === item.path ? ' active' : ''}`}
                  href={item.path}
                  aria-current={activePath === item.path ? 'page' : undefined}
                  onClick={event => { event.preventDefault(); navigate(item.path) }}
                >
                  <span className="sidebar-item-icon"><NavIcon name={item.icon} /></span>
                  {item.label}
                </a>
              ))}
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-user">
            <span className="sidebar-user-avatar">{user?.email?.[0]?.toUpperCase() ?? '?'}</span>
            <div className="sidebar-user-info">
              <span className="sidebar-user-email">{user?.email}</span>
              <span className="sidebar-user-role">{user?.role}</span>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Page shell ── */}
      <div className="page-shell">
        {/* ── Topbar ── */}
        <header className="topbar">
          <button className="topbar-hamburger btn-ghost" type="button" onClick={() => setSidebarOpen(o => !o)} aria-label="Toggle navigation" aria-expanded={sidebarOpen}>☰</button>
          <button className="topbar-search" type="button" onClick={() => navigate('/search')} aria-label="Open semantic search">
            <NavIcon name="search" />
            <span>Search incidents, IOCs, or memory</span>
          </button>
          <div className="topbar-actions">
            <a className="btn btn-primary btn-sm" href="/submissions/new" onClick={event => { event.preventDefault(); navigate('/submissions/new') }}>＋ New submission</a>
            <button type="button" className="btn btn-ghost btn-sm" onClick={logout} aria-label="Sign out">Sign out</button>
          </div>
        </header>

        {/* ── Page content ── */}
        <main className="page-content">
          <div className="page-header">
            <div>
              <p className="page-breadcrumb">Cyber Network / Analyst workspace</p>
              <h1 className="page-title">{pageTitle}</h1>
            </div>
          </div>

          {path === '/submissions/new' ? (
            <SubmissionIntake onCreated={id => navigate(`/submissions/${id}`)} />
          ) : path === '/submissions' ? (
            <SubmissionsList onSelectSubmission={id => navigate(`/submissions/${id}`)} />
          ) : detailMatch ? (
            <SubmissionDetail submissionId={Number(detailMatch[1])} onBack={() => navigate('/submissions')} />
          ) : path === '/search' ? (
            <SemanticSearch onSelectSubmission={id => navigate(`/submissions/${id}`)} />
          ) : path === '/analytics' ? (
            <Analytics />
          ) : path === '/memory' || memoryDetailMatch ? (
            <MemoryNetwork
              nodeId={memoryDetailMatch ? Number(memoryDetailMatch[1]) : null}
              onSelectNode={id => navigate(`/memory/${id}`)}
              onBack={() => navigate('/memory')}
            />
          ) : path === '/network-settings' && user?.role === 'admin' ? (
            <NetworkSettings />
          ) : (
            <DashboardHome onNavigate={page => navigate(page === 'search' ? '/search' : page === 'memory' ? '/memory' : '/submissions')} />
          )}
        </main>
        <footer className="footer">Cyber Network · Analyst workspace</footer>
      </div>
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

import { useState } from 'react'
import './CentralAdmin.css'

interface CentralOrganization {
  name: string
  status: 'active' | 'suspended'
}

interface TechniqueCount {
  technique_id: string
  count: number
}

interface CentralStats {
  total: number
  by_technique: TechniqueCount[]
  by_severity: Array<{ severity: string; count: number }>
}

export default function CentralAdmin() {
  const [token, setToken] = useState('')
  const [organizations, setOrganizations] = useState<CentralOrganization[] | null>(null)
  const [stats, setStats] = useState<CentralStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadDashboard = async () => {
    setLoading(true)
    setError(null)
    try {
      const headers = { 'X-Central-Admin-Token': token }
      const [orgResponse, statsResponse] = await Promise.all([
        fetch('/central-api/orgs', { headers }),
        fetch('/central-api/intel/stats', { headers }),
      ])
      if (!orgResponse.ok || !statsResponse.ok) {
        const response = !orgResponse.ok ? orgResponse : statsResponse
        throw new Error(response.status === 401 || response.status === 403
          ? 'Central admin token was rejected'
          : `Central API request failed (HTTP ${response.status})`)
      }
      setOrganizations(await orgResponse.json() as CentralOrganization[])
      setStats(await statsResponse.json() as CentralStats)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load central aggregates')
      setOrganizations(null)
      setStats(null)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="central-admin">
      <header className="central-admin-header">
        <p>Cyber Memory Network / Central operations</p>
        <h1>Central network administration</h1>
        <span>Aggregate-only view. Shared incident text and source organization attribution are not displayed.</span>
      </header>
      <form className="central-admin-auth" onSubmit={event => { event.preventDefault(); void loadDashboard() }}>
        <label htmlFor="central-admin-token">Central admin token</label>
        <input
          id="central-admin-token"
          type="password"
          autoComplete="off"
          value={token}
          onChange={event => setToken(event.target.value)}
          required
        />
        <button type="submit" disabled={loading}>{loading ? 'Loading…' : 'Load aggregates'}</button>
        <a href="/">Return to organization workspace</a>
      </form>
      {error && <p className="central-admin-error" role="alert">{error}</p>}
      {stats && organizations && (
        <>
          <section className="central-admin-summary">
            <article className="central-admin-card">
              <span>Total shared intel</span><strong>{stats.total}</strong>
            </article>
            <article className="central-admin-card">
              <span>Registered organizations</span><strong>{organizations.length}</strong>
            </article>
          </section>
          <div className="central-admin-columns">
            <section className="central-admin-card">
              <h2>Registered organizations</h2>
              <ul className="central-admin-orgs">
                {organizations.map(org => (
                  <li key={org.name}>
                    <span>{org.name}</span><span className={`central-admin-status ${org.status}`}>{org.status}</span>
                  </li>
                ))}
              </ul>
            </section>
            <section className="central-admin-card">
              <h2>Technique distribution</h2>
              {stats.by_technique.length === 0 ? <p>No technique-tagged intel yet.</p> : (
                <ul className="central-admin-techniques">
                  {stats.by_technique.map(item => (
                    <li key={item.technique_id}>
                      <code>{item.technique_id}</code><span>{item.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}
    </main>
  )
}

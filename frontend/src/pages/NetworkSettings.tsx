import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import './NetworkSettings.css'

interface NetworkSettingsData {
  share_with_network: boolean
  last_sync_status: 'not_shared' | 'pending' | 'shared' | 'duplicate' | 'failed' | null
  last_sync_error: string | null
  last_synced_at: string | null
  submissions_shared: number
}

export default function NetworkSettings() {
  const { authFetch } = useAuth()
  const [settings, setSettings] = useState<NetworkSettingsData | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadSettings = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await authFetch('/api/network/settings')
      if (!response.ok) throw new Error(`Network settings: HTTP ${response.status}`)
      setSettings(await response.json() as NetworkSettingsData)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load network settings')
    } finally {
      setLoading(false)
    }
  }, [authFetch])

  useEffect(() => { void loadSettings() }, [loadSettings])

  const updateOptIn = async (enabled: boolean) => {
    setSaving(true)
    setError(null)
    try {
      const response = await authFetch('/api/network/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ share_with_network: enabled }),
      })
      if (!response.ok) throw new Error(`Saving network settings: HTTP ${response.status}`)
      setSettings(await response.json() as NetworkSettingsData)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to save network settings')
    } finally {
      setSaving(false)
    }
  }

  const syncStatus = settings?.last_sync_status ?? 'unknown'
  const syncLabel  = (settings?.last_sync_status ?? 'No sync yet').replaceAll('_', ' ')

  return (
    <section className="ns-root">
      {/* Error banner */}
      {error && settings && (
        <p className="ns-error-banner" role="alert">
          ⚠ {error}
        </p>
      )}

      {/* Loading skeleton */}
      {loading ? (
        <div className="ns-skeleton-section" role="status" aria-label="Loading network settings">
          {/* Main card skeleton */}
          <div className="ns-skeleton-card">
            <div className="ns-skeleton-line w-20" />
            <div className="ns-skeleton-line w-60" />
            <div className="ns-skeleton-line w-80" />
            <div className="ns-skeleton-line w-40" />
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.5rem' }}>
              <div className="ns-skeleton-toggle" />
              <div className="ns-skeleton-line w-40" style={{ margin: 0 }} />
            </div>
          </div>
          {/* Metrics skeleton */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%,240px),1fr))', gap: '1rem' }}>
            {[0, 1].map(i => (
              <div key={i} className="ns-skeleton-card">
                <div className="ns-skeleton-line w-40" />
                <div className="ns-skeleton-value" />
                <div className="ns-skeleton-line w-60" />
              </div>
            ))}
          </div>
        </div>
      ) : settings ? (
        <div className="ns-section">
          {/* ── Sharing opt-in card ─────────────────────────────────── */}
          <article className="ns-card">
            <div className="ns-card-header">
              <span className="ns-card-kicker">Organization contribution</span>
              <h2 className="ns-card-title">Share anonymized intelligence</h2>
              <p className="ns-card-desc">
                When enabled, completed submissions may be sent to the central network
                after a second redaction pass. User identity, organization identity,
                internal hosts, and non-allow-listed indicators are excluded.
              </p>
            </div>
            <div className="ns-card-body">
              <div className="ns-toggle-row">
                <label className="ns-toggle-label">
                  <input
                    type="checkbox"
                    checked={settings.share_with_network}
                    disabled={saving}
                    onChange={event => void updateOptIn(event.target.checked)}
                    aria-label="Share anonymized intelligence with the network"
                  />
                  <span>
                    {settings.share_with_network ? 'Sharing enabled' : 'Sharing disabled'}
                  </span>
                </label>
                {saving && (
                  <span className="ns-saving-indicator">Saving…</span>
                )}
              </div>
            </div>
          </article>

          {/* ── Metrics cards ───────────────────────────────────────── */}
          <div className="ns-metrics-grid">
            <article className="ns-metric-card accent-blue">
              <span className="ns-metric-kicker">Successful deliveries</span>
              <strong className="ns-metric-value">{settings.submissions_shared}</strong>
              <p className="ns-metric-sub">
                Submissions accepted by the central service, including deduplicated retries.
              </p>
            </article>

            <article className="ns-metric-card accent-green">
              <span className="ns-metric-kicker">Latest sync</span>
              <span className={`ns-sync-badge ${syncStatus}`}>
                {syncLabel}
              </span>
              <p className="ns-metric-sub">
                {settings.last_synced_at
                  ? new Date(settings.last_synced_at).toLocaleString()
                  : 'No successful delivery recorded'}
              </p>
              {settings.last_sync_error && (
                <p className="ns-sync-error" role="status">
                  ⚠ {settings.last_sync_error}
                </p>
              )}
            </article>
          </div>

          {/* ── Footer ─────────────────────────────────────────────── */}
          <div className="ns-footer-row">
            <button
              className="ns-refresh-btn"
              type="button"
              disabled={loading || saving}
              onClick={() => void loadSettings()}
            >
              ↻ Refresh status
            </button>
          </div>
        </div>
      ) : error ? (
        <div className="ns-error-state" role="alert">
          <strong>Network settings could not be loaded</strong>
          <p>{error} Check the connection and try again.</p>
          <button
            className="ns-refresh-btn"
            type="button"
            disabled={loading}
            onClick={() => void loadSettings()}
          >
            ↻ Try again
          </button>
        </div>
      ) : null}
    </section>
  )
}

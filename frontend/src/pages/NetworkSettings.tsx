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

  return (
    <section className="network-settings">
      {error && <p className="network-settings-error" role="alert">{error}</p>}
      {loading || !settings ? (
        <div className="network-settings-card"><p>Loading network sharing settings…</p></div>
      ) : (
        <>
          <article className="network-settings-card">
            <div>
              <p className="network-settings-kicker">Organization contribution</p>
              <h2>Share anonymized intelligence</h2>
              <p>
                When enabled, completed submissions may be sent to the central network
                after a second redaction pass. User identity, organization identity,
                internal hosts, and non-allow-listed indicators are excluded.
              </p>
            </div>
            <label className="network-settings-toggle">
              <input
                type="checkbox"
                checked={settings.share_with_network}
                disabled={saving}
                onChange={event => void updateOptIn(event.target.checked)}
                aria-label="Share anonymized intelligence with the network"
              />
              <span>{settings.share_with_network ? 'Sharing enabled' : 'Sharing disabled'}</span>
            </label>
          </article>

          <div className="network-settings-metrics">
            <article className="network-settings-card">
              <span className="network-settings-kicker">Successful deliveries</span>
              <strong>{settings.submissions_shared}</strong>
              <p>Submissions accepted by the central service, including deduplicated retries.</p>
            </article>
            <article className="network-settings-card">
              <span className="network-settings-kicker">Latest sync</span>
              <strong className={`network-sync-state ${settings.last_sync_status ?? 'unknown'}`}>
                {(settings.last_sync_status ?? 'No sync yet').replaceAll('_', ' ')}
              </strong>
              <p>
                {settings.last_synced_at
                  ? new Date(settings.last_synced_at).toLocaleString()
                  : 'No successful delivery recorded'}
              </p>
              {settings.last_sync_error && (
                <p className="network-settings-error" role="status">{settings.last_sync_error}</p>
              )}
            </article>
          </div>
          <button className="network-settings-refresh" type="button" onClick={() => void loadSettings()}>
            Refresh status
          </button>
        </>
      )}
    </section>
  )
}

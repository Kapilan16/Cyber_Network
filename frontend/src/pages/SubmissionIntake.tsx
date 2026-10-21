import { useState, type FormEvent } from 'react'
import { useAuth } from '../context/AuthContext'
import './SubmissionIntake.css'

const sourceTypes = ['alert', 'log', 'report', 'freeform'] as const

const SOURCE_META: Record<(typeof sourceTypes)[number], { icon: string; desc: string }> = {
  alert:    { icon: '🚨', desc: 'Security alert or IDS/SIEM event' },
  log:      { icon: '📋', desc: 'Log excerpt or raw log data' },
  report:   { icon: '📄', desc: 'Threat or incident report' },
  freeform: { icon: '✍️',  desc: 'Unstructured threat description' },
}

const MAX_LEN = 200_000

export default function SubmissionIntake({ onCreated }: { onCreated: (id: number) => void }) {
  const { authFetch } = useAuth()
  const [sourceType, setSourceType] = useState<(typeof sourceTypes)[number]>('alert')
  const [rawText, setRawText] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const response = await authFetch('/api/submissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_text: rawText, source_type: sourceType }),
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({})) as { detail?: string }
        throw new Error(body.detail ?? `Submission failed (${response.status})`)
      }
      const submission = await response.json() as { id: number }
      onCreated(submission.id)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Submission failed')
    } finally {
      setSubmitting(false)
    }
  }

  const pct = rawText.length / MAX_LEN
  const nearLimit = pct > 0.85

  return (
    <div className="intake-wrapper">
      {/* Info banner */}
      <div className="intake-info-banner">
        <span className="intake-info-icon">🛡️</span>
        <div>
          <div className="intake-info-title">Sanitize &amp; Analyze</div>
          <div className="intake-info-desc">
            Paste raw alerts, log excerpts, or threat reports. The platform will sanitize
            sensitive data, extract IOCs, run rule matching, and embed for semantic search.
          </div>
        </div>
      </div>

      {/* Form card */}
      <div className="intake-card">
        <form className="intake-form" onSubmit={submit}>

          {/* Source type selector */}
          <div className="intake-field">
            <label className="intake-label">Source type</label>
            {/* Visual picker */}
            <div className="intake-source-grid" role="radiogroup" aria-label="Source type">
              {sourceTypes.map(type => (
                <div
                  key={type}
                  className={`intake-source-option ${sourceType === type ? 'selected' : ''}`}
                  onClick={() => setSourceType(type)}
                  role="radio"
                  aria-checked={sourceType === type}
                  tabIndex={0}
                  onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && setSourceType(type)}
                >
                  <span className="intake-source-icon">{SOURCE_META[type].icon}</span>
                  <span className="intake-source-label">{type}</span>
                  <span className="intake-source-desc">{SOURCE_META[type].desc}</span>
                </div>
              ))}
            </div>
            {/* Real select preserved for form semantics & test IDs */}
            <select
              id="intake-source"
              className="intake-select-hidden"
              value={sourceType}
              onChange={e => setSourceType(e.target.value as typeof sourceType)}
              aria-hidden="true"
              tabIndex={-1}
            >
              {sourceTypes.map(type => <option key={type} value={type}>{type}</option>)}
            </select>
          </div>

          {/* Artifact content */}
          <div className="intake-field">
            <label className="intake-label" htmlFor="intake-content">Artifact content</label>
            <textarea
              id="intake-content"
              className="intake-textarea"
              required
              minLength={1}
              maxLength={MAX_LEN}
              rows={14}
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              placeholder="Paste an alert, log excerpt, or threat report…"
            />
          </div>

          {/* Error */}
          {error && (
            <p className="intake-error" role="alert">
              ⚠ {error}
            </p>
          )}

          {/* Actions */}
          <div className="intake-actions">
            <span className={`intake-char-count ${nearLimit ? 'near-limit' : ''}`}>
              {rawText.length.toLocaleString()} / {MAX_LEN.toLocaleString()} characters
            </span>
            <button
              className="intake-submit-btn workspace-primary"
              type="submit"
              disabled={submitting || !rawText.trim()}
            >
              {submitting ? '⏳ Processing…' : '🔍 Sanitize and analyze'}
            </button>
          </div>

        </form>
      </div>
    </div>
  )
}
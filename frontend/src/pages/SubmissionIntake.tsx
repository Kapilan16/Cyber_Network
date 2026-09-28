import { useState, type FormEvent } from 'react'
import { useAuth } from '../context/AuthContext'

const sourceTypes = ['alert', 'log', 'report', 'freeform'] as const

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

  return (
    <form className="intake-form" onSubmit={submit}>
      <label className="intake-label" htmlFor="intake-source">Source type</label>
      <select id="intake-source" value={sourceType} onChange={event => setSourceType(event.target.value as typeof sourceType)}>
        {sourceTypes.map(type => <option key={type} value={type}>{type}</option>)}
      </select>
      <label className="intake-label" htmlFor="intake-content">Artifact content</label>
      <textarea
        id="intake-content"
        required
        minLength={1}
        maxLength={200000}
        rows={14}
        value={rawText}
        onChange={event => setRawText(event.target.value)}
        placeholder="Paste an alert, log excerpt, or threat report..."
      />
      {error && <p className="intake-error" role="alert">{error}</p>}
      <div className="intake-actions">
        <span>{rawText.length.toLocaleString()} / 200,000 characters</span>
        <button className="workspace-primary" type="submit" disabled={submitting || !rawText.trim()}>
          {submitting ? 'Processing…' : 'Sanitize and analyze'}
        </button>
      </div>
    </form>
  )
}
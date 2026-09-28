/**
 * AuthPage – combined Login / Register form with animated tab switching.
 * No router dependency; the parent controls visibility.
 */
import { useState, type FormEvent } from 'react'
import { useAuth } from '../context/AuthContext'
import './AuthPage.css'

type Tab = 'login' | 'register'

interface AuthPageProps {
  onSuccess?: () => void
}

export default function AuthPage({ onSuccess }: AuthPageProps) {
  const { login, register } = useAuth()

  const [tab, setTab] = useState<Tab>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setErrorMsg('')
    setLoading(true)
    try {
      if (tab === 'login') {
        await login(email, password)
      } else {
        await register(email, password)
      }
      onSuccess?.()
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        {/* ── Logo ── */}
        <div className="auth-logo">
          <span className="auth-logo-icon">⚡</span>
          <span className="auth-logo-text">Cyber Network</span>
        </div>

        {/* ── Tabs ── */}
        <div className="auth-tabs" role="tablist">
          <button
            id="tab-login"
            role="tab"
            aria-selected={tab === 'login'}
            className={`auth-tab ${tab === 'login' ? 'active' : ''}`}
            onClick={() => { setTab('login'); setErrorMsg('') }}
            type="button"
          >
            Sign In
          </button>
          <button
            id="tab-register"
            role="tab"
            aria-selected={tab === 'register'}
            className={`auth-tab ${tab === 'register' ? 'active' : ''}`}
            onClick={() => { setTab('register'); setErrorMsg('') }}
            type="button"
          >
            Register
          </button>
          <div className={`auth-tab-slider ${tab}`} aria-hidden="true" />
        </div>

        {/* ── Form ── */}
        <form
          id={`form-${tab}`}
          className="auth-form"
          onSubmit={handleSubmit}
          aria-labelledby={`tab-${tab}`}
          noValidate
        >
          <div className="auth-field">
            <label htmlFor="auth-email" className="auth-label">
              Email
            </label>
            <input
              id="auth-email"
              type="email"
              className="auth-input"
              placeholder="you@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </div>

          <div className="auth-field">
            <label htmlFor="auth-password" className="auth-label">
              Password
            </label>
            <input
              id="auth-password"
              type="password"
              className="auth-input"
              placeholder={tab === 'register' ? 'Min. 8 characters' : '••••••••'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
              required
            />
          </div>

          {errorMsg && (
            <p id="auth-error" className="auth-error" role="alert">
              {errorMsg}
            </p>
          )}

          <button
            id="auth-submit"
            type="submit"
            className="auth-btn"
            disabled={loading}
          >
            {loading
              ? 'Please wait…'
              : tab === 'login'
              ? 'Sign In'
              : 'Create Account'}
          </button>
        </form>

        <p className="auth-footer-note">
          {tab === 'login' ? (
            <>
              No account?{' '}
              <button
                id="auth-switch-to-register"
                className="auth-link-btn"
                onClick={() => setTab('register')}
                type="button"
              >
                Register
              </button>
            </>
          ) : (
            <>
              Already registered?{' '}
              <button
                id="auth-switch-to-login"
                className="auth-link-btn"
                onClick={() => setTab('login')}
                type="button"
              >
                Sign In
              </button>
            </>
          )}
        </p>
      </div>
    </div>
  )
}

/**
 * AuthPage – combined Login / Register form with animated tab switching.
 * Layout: two-panel — left brand hero, right form card.
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
  const [showPassword, setShowPassword] = useState(false)

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

      {/* ── Left Panel: Brand Hero ── */}
      <div className="auth-left">
        <div className="auth-left-inner">
          {/* Brand */}
          <div className="auth-brand">
            <span className="auth-brand-mark">CN</span>
            <span className="auth-brand-name">Cyber Network</span>
          </div>

          {/* Hero copy */}
          <div className="auth-hero-copy">
            <h1 className="auth-hero-title">
              Stronger Together.<br />
              <span className="auth-hero-accent">Safer Tomorrow.</span>
            </h1>
            <p className="auth-hero-sub">
              Share sanitised threat knowledge, detect patterns,
              and stay ahead of evolving cyber threats — together.
            </p>
          </div>

          {/* Feature highlights */}
          <div className="auth-features">
            <div className="auth-feature">
              <span className="auth-feature-icon">🛡️</span>
              <div>
                <div className="auth-feature-title">Privacy First</div>
                <div className="auth-feature-desc">Protect sensitive data with sanitization and approval controls.</div>
              </div>
            </div>
            <div className="auth-feature">
              <span className="auth-feature-icon">🔗</span>
              <div>
                <div className="auth-feature-title">Shared Knowledge</div>
                <div className="auth-feature-desc">Learn from multiple organizations, not just your own data.</div>
              </div>
            </div>
            <div className="auth-feature">
              <span className="auth-feature-icon">🧠</span>
              <div>
                <div className="auth-feature-title">Smarter Intelligence</div>
                <div className="auth-feature-desc">Find similar incidents, identify campaigns, stop threats earlier.</div>
              </div>
            </div>
          </div>

          {/* Stats strip */}
          <div className="auth-stats">
            <div className="auth-stat"><span className="auth-stat-value">3+</span><span className="auth-stat-label">Organizations</span></div>
            <div className="auth-stat-divider" />
            <div className="auth-stat"><span className="auth-stat-value">248+</span><span className="auth-stat-label">Shared Incidents</span></div>
            <div className="auth-stat-divider" />
            <div className="auth-stat"><span className="auth-stat-value">99.9%</span><span className="auth-stat-label">Uptime</span></div>
          </div>
        </div>
      </div>

      {/* ── Right Panel: Form ── */}
      <div className="auth-right">
        <div className="auth-card">

          {/* Greeting heading */}
          <div className="auth-greeting">
            <h2 className="auth-greeting-title">
              {tab === 'login' ? <>Welcome Back <span className="auth-wave">👋</span></> : <>Create Account <span className="auth-wave">🚀</span></>}
            </h2>
            <p className="auth-greeting-sub">
              {tab === 'login'
                ? 'Sign in to access your cyber memory network'
                : 'Join the network — share and protect together'}
            </p>
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
            {/* Email field */}
            <div className="auth-field">
              <label htmlFor="auth-email" className="auth-label">Email Address</label>
              <div className="auth-input-wrap">
                <span className="auth-input-icon">✉️</span>
                <input
                  id="auth-email"
                  type="email"
                  className="auth-input"
                  placeholder="Enter your email address"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  autoComplete="email"
                  required
                />
              </div>
            </div>

            {/* Password field */}
            <div className="auth-field">
              <label htmlFor="auth-password" className="auth-label">Password</label>
              <div className="auth-input-wrap">
                <span className="auth-input-icon">🔒</span>
                <input
                  id="auth-password"
                  type={showPassword ? 'text' : 'password'}
                  className="auth-input"
                  placeholder={tab === 'register' ? 'Min. 8 characters' : 'Enter your password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
                  required
                />
                <button
                  type="button"
                  className="auth-toggle-pw"
                  onClick={() => setShowPassword(v => !v)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
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
                ? '→  Sign In'
                : '→  Create Account'}
            </button>
          </form>

          {/* Security note */}
          <div className="auth-security-note">
            <span className="auth-security-icon">🛡️</span>
            <div>
              <div className="auth-security-title">Secure Access</div>
              <div className="auth-security-desc">Your data is protected with enterprise-grade encryption.</div>
            </div>
          </div>

          {/* Switch tab footer */}
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
    </div>
  )
}

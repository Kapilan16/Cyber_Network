/**
 * AuthContext – holds the access token in memory (never localStorage/cookie),
 * exposes login / register / logout helpers, and provides a pre-authenticated
 * fetch wrapper for protected API calls.
 */
import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from 'react'

// ── Types ─────────────────────────────────────────────────────────────────────

export type UserRole = 'analyst' | 'admin'

export interface AuthUser {
  id: number
  email: string
  role: UserRole
}

interface TokenPair {
  access_token: string
  refresh_token: string
}

interface AuthContextValue {
  user: AuthUser | null
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, role?: UserRole) => Promise<void>
  logout: () => void
  /** fetch() wrapper that automatically attaches the Bearer token */
  authFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
}

// ── Context ───────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue | null>(null)

// ── Provider ──────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)

  // Access token stored only in memory (ref) – survives re-renders but not
  // page refreshes, which is the intended behaviour for an in-memory strategy.
  const accessTokenRef = useRef<string | null>(null)
  const refreshTokenRef = useRef<string | null>(null)

  const storeTokens = useCallback((pair: TokenPair) => {
    accessTokenRef.current = pair.access_token
    refreshTokenRef.current = pair.refresh_token
  }, [])

  const fetchMe = useCallback(async (token: string): Promise<AuthUser> => {
    const res = await fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!res.ok) throw new Error('Failed to fetch current user')
    return res.json() as Promise<AuthUser>
  }, [])

  const login = useCallback(
    async (email: string, password: string) => {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Login failed' }))
        throw new Error(err.detail ?? 'Login failed')
      }
      const pair = (await res.json()) as TokenPair
      storeTokens(pair)
      const me = await fetchMe(pair.access_token)
      setUser(me)
    },
    [storeTokens, fetchMe],
  )

  const register = useCallback(
    async (email: string, password: string, role: UserRole = 'analyst') => {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, role }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Registration failed' }))
        throw new Error(err.detail ?? 'Registration failed')
      }
      // Auto-login after successful registration
      await login(email, password)
    },
    [login],
  )

  const logout = useCallback(() => {
    accessTokenRef.current = null
    refreshTokenRef.current = null
    setUser(null)
  }, [])

  /**
   * Transparent fetch wrapper:
   *   1. Attach the current access token.
   *   2. On 401, try once to refresh, then retry.
   *   3. On second 401, force logout.
   */
  const authFetch = useCallback(
    async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
      const withAuth = (token: string): RequestInit => ({
        ...init,
        headers: {
          ...(init.headers ?? {}),
          Authorization: `Bearer ${token}`,
        },
      })

      const token = accessTokenRef.current
      if (!token) throw new Error('Not authenticated')

      let res = await fetch(input, withAuth(token))

      if (res.status === 401 && refreshTokenRef.current) {
        // Attempt token refresh
        const refreshRes = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshTokenRef.current }),
        })
        if (refreshRes.ok) {
          const pair = (await refreshRes.json()) as TokenPair
          storeTokens(pair)
          res = await fetch(input, withAuth(pair.access_token))
        }
        if (!refreshRes.ok || res.status === 401) {
          logout()
        }
      }

      return res
    },
    [storeTokens, logout],
  )

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: user !== null,
        login,
        register,
        logout,
        authFetch,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}

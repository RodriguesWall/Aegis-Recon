import { useEffect, useState } from "react"
import { Link, Outlet } from "react-router-dom"
import { api } from "../api/client"
import { Login } from "./Login"

export function Layout() {
  const [version, setVersion] = useState("")
  const [auth, setAuth] = useState<{ enabled: boolean; authenticated: boolean } | null>(null)

  function checkAuth() {
    void api
      .getAuth()
      .then(setAuth)
      .catch(() => setAuth({ enabled: false, authenticated: true }))
  }

  useEffect(() => {
    void api.getHealth().then((h) => setVersion(h.version ?? ""))
    checkAuth()
  }, [])

  async function logout() {
    try {
      await api.logout()
    } finally {
      checkAuth()
    }
  }

  if (!auth) return null
  if (auth.enabled && !auth.authenticated) return <Login onDone={checkAuth} />

  return (
    <div className="flex min-h-screen flex-col">
      <nav
        className="sticky top-0 z-50 flex items-center justify-between px-6 py-4"
        style={{
          background: "rgba(10,11,16,0.9)",
          backdropFilter: "blur(10px)",
          borderBottom: "1px solid rgba(255,255,255,0.05)",
        }}
      >
        <div className="flex items-center gap-6">
          <Link to="/" className="text-xl font-bold">
            <span className="gradient-text">Aegis</span>
            <span className="text-white">-Recon</span>
          </Link>
          <Link to="/" className="text-sm text-muted hover:text-white">
            Projects
          </Link>
          <Link to="/findings" className="text-sm text-muted hover:text-white">
            Findings
          </Link>
          <Link to="/settings" className="text-sm text-muted hover:text-white">
            Settings
          </Link>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted">attack surface dashboard</span>
          {auth.enabled && (
            <button className="text-sm text-muted hover:text-white" onClick={() => void logout()}>
              Logout
            </button>
          )}
        </div>
      </nav>
      <main className="mx-auto w-full max-w-7xl px-4 py-8">
        <Outlet />
      </main>
      <footer
        className="mt-auto px-6 py-6 text-center text-xs text-muted"
        style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}
      >
        © {new Date().getFullYear()} Aegis-Recon · open-source attack surface scanner ·
        authorized use only{version && ` · ${version}`}
      </footer>
    </div>
  )
}

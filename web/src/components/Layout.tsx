import { useEffect, useState } from "react"
import { Link, Outlet } from "react-router-dom"
import { api } from "../api/client"

export function Layout() {
  const [version, setVersion] = useState("")

  useEffect(() => {
    void api.getHealth().then((h) => setVersion(h.version ?? ""))
  }, [])

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
        <span className="text-sm text-muted">attack surface dashboard</span>
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

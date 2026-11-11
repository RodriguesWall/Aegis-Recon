import { Link, Outlet } from "react-router-dom"

export function Layout() {
  return (
    <div className="min-h-screen">
      <nav
        className="sticky top-0 z-50 flex items-center justify-between px-6 py-4"
        style={{
          background: "rgba(10,11,16,0.9)",
          backdropFilter: "blur(10px)",
          borderBottom: "1px solid rgba(255,255,255,0.05)",
        }}
      >
        <Link to="/" className="text-xl font-bold">
          <span className="gradient-text">Aegis</span>
          <span className="text-white">-Recon</span>
        </Link>
        <span className="text-sm text-muted">attack surface dashboard</span>
      </nav>
      <main className="mx-auto max-w-5xl px-4 py-8">
        <Outlet />
      </main>
    </div>
  )
}

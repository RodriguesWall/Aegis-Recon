import { useState } from "react"
import { api } from "../api/client"

// Login is the full-screen gate shown when auth is enabled and the visitor has
// no valid session.
export function Login({ onDone }: { onDone: () => void }) {
  const [pw, setPw] = useState("")
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr("")
    try {
      await api.login(pw)
      onDone()
    } catch {
      setErr("Invalid password")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="glass-card w-full max-w-sm space-y-4">
        <div>
          <h1 className="text-2xl font-bold">
            <span className="gradient-text">Aegis</span>
            <span className="text-white">-Recon</span>
          </h1>
          <p className="text-sm text-muted">Sign in to continue.</p>
        </div>
        <input
          className="input"
          type="password"
          placeholder="Admin password"
          value={pw}
          autoFocus
          onChange={(e) => setPw(e.target.value)}
        />
        {err && <p className="text-sm text-sev-critical">{err}</p>}
        <button type="submit" className="btn-primary w-full" disabled={busy}>
          Sign in
        </button>
      </form>
    </div>
  )
}

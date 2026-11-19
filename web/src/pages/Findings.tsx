import { useEffect, useMemo, useState } from "react"
import { api } from "../api/client"
import { SeverityBadge } from "../components/SeverityBadge"
import { OWASP_NAMES, OwaspBadge } from "../components/OwaspBadge"
import type { FindingRow, Project } from "../types"

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
const STATUSES = ["open", "false-positive", "accepted-risk", "fixed"] as const

// Findings is the global, filterable view of current findings (latest completed
// scan per service) across all projects.
export function Findings() {
  const [projects, setProjects] = useState<Project[]>([])
  const [rows, setRows] = useState<FindingRow[]>([])
  const [q, setQ] = useState("")
  const [severity, setSeverity] = useState("")
  const [status, setStatus] = useState("")
  const [project, setProject] = useState("")
  const [error, setError] = useState("")

  // OWASP Top 10 breakdown over the currently shown rows (mapped rows only).
  const owaspBreakdown = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const r of rows) {
      if (r.owasp) counts[r.owasp] = (counts[r.owasp] ?? 0) + 1
    }
    return Object.entries(counts).sort(([a], [b]) => a.localeCompare(b))
  }, [rows])

  useEffect(() => {
    void api.listProjects().then((p) => setProjects(p ?? []))
  }, [])

  useEffect(() => {
    void api
      .listFindings({ q, severity, status, project })
      .then((r) => setRows(r ?? []))
      .catch((e) => setError(String(e)))
  }, [q, severity, status, project])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Findings</span>
        </h1>
        <p className="text-muted">Current findings across all projects (latest scan per service).</p>
      </div>

      <div className="glass-card flex flex-wrap gap-2">
        <input
          className="input flex-1"
          placeholder="Search title or host…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select className="input w-auto" value={project} onChange={(e) => setProject(e.target.value)}>
          <option value="">All projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <select className="input w-auto" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Any severity</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select className="input w-auto" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Any status</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="text-sev-critical">{error}</p>}

      {owaspBreakdown.length > 0 && (
        <div className="glass-card">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
            OWASP Top 10 (2021)
          </p>
          <div className="flex flex-wrap gap-2">
            {owaspBreakdown.map(([code, n]) => (
              <span
                key={code}
                title={OWASP_NAMES[code] ?? code}
                className="flex items-center gap-1.5 rounded border border-white/10 px-2 py-1 text-xs text-muted"
              >
                <span className="font-semibold text-white">{code}</span>
                <span className="truncate max-w-[14rem]">{OWASP_NAMES[code] ?? code}</span>
                <span className="rounded bg-white/10 px-1.5 font-semibold text-white">{n}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="glass-card">
        <p className="mb-3 text-xs text-muted">{rows.length} findings</p>
        <div className="space-y-2">
          {rows.map((f, i) => (
            <div
              key={f.fingerprint + i}
              className="flex items-start gap-3 border-t border-white/5 pt-2 first:border-0 first:pt-0"
            >
              <SeverityBadge severity={f.severity} />
              <div className="min-w-0 flex-1">
                <p className="flex items-center gap-2 text-white">
                  <span className="min-w-0 truncate">{f.title}</span>
                  <OwaspBadge code={f.owasp} />
                </p>
                <p className="text-xs text-muted">
                  {f.host}
                  {f.port ? ":" + f.port : ""} · {f.scanner} · {f.project_name} / {f.asset_name}
                </p>
                {f.remediation && (
                  <p className="mt-0.5 text-xs" style={{ color: "#86efac" }}>
                    Fix: {f.remediation}
                  </p>
                )}
              </div>
              {f.status !== "open" && (
                <span className="whitespace-nowrap text-xs text-muted">{f.status}</span>
              )}
            </div>
          ))}
          {rows.length === 0 && <p className="text-muted">No findings.</p>}
        </div>
      </div>
    </div>
  )
}

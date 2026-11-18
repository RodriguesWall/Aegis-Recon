import type { Stats } from "../types"
import { SeverityBadge } from "./SeverityBadge"
import { TrendChart } from "./TrendChart"

function Tile({ label, value }: { label: string; value: number }) {
  return (
    <div className="glass-card">
      <p className="text-3xl font-bold text-white">{value}</p>
      <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
    </div>
  )
}

// Dashboard shows the aggregate security posture: current exposure (latest
// completed scan per asset) by severity and per project, triage breakdown, and
// a severity trend over recent scans.
export function Dashboard({ stats }: { stats: Stats }) {
  const sev = stats.severity
  const t = stats.triage

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Overview</span>
        </h1>
        <p className="text-muted">Current exposure across all projects (latest scan per service).</p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Tile label="Projects" value={stats.totals.projects} />
        <Tile label="Services" value={stats.totals.assets} />
        <Tile label="Findings" value={stats.totals.findings} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="glass-card">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Severity (current)</p>
          <div className="flex flex-col gap-2">
            {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
              <div key={k} className="flex items-center justify-between">
                <SeverityBadge severity={k} />
                <span className="text-white">{sev[k]}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="glass-card">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Triage</p>
          <div className="flex flex-col gap-2 text-sm">
            <Row label="Open" value={t.open} color="text-muted" />
            <Row label="False positive" value={t.false_positive} color="text-sev-low" />
            <Row label="Accepted risk" value={t.accepted_risk} color="text-sev-medium" />
            <Row label="Fixed" value={t.fixed} color="text-sev-info" />
          </div>
        </div>
      </div>

      <div className="glass-card">
        <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Severity trend</p>
        <TrendChart points={stats.trend} />
      </div>

      {stats.projects.length > 0 && (
        <div className="glass-card">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">By project</p>
          <div className="space-y-2">
            {stats.projects.map((p) => (
              <div key={p.id} className="flex items-center justify-between gap-3 border-t border-white/5 pt-2 first:border-0 first:pt-0">
                <span className="truncate text-white">{p.name}</span>
                <span className="flex items-center gap-3 text-xs">
                  <Count n={p.critical} color="#f87171" title="Critical" />
                  <Count n={p.high} color="#fb923c" title="High" />
                  <Count n={p.medium} color="#facc15" title="Medium" />
                  <Count n={p.low} color="#60a5fa" title="Low" />
                  <span className="text-muted">total {p.total}</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className={color}>{label}</span>
      <span className="text-white">{value}</span>
    </div>
  )
}

function Count({ n, color, title }: { n: number; color: string; title: string }) {
  return (
    <span className="flex items-center gap-1" title={title}>
      <span style={{ width: 8, height: 8, background: color, borderRadius: 2 }} />
      <span className="text-white">{n}</span>
    </span>
  )
}

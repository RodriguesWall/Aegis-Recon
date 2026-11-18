import type { Stats } from "../types"
import { SeverityBadge } from "./SeverityBadge"
import { TrendChart } from "./TrendChart"

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-xl font-bold text-white">{value}</span>
      <span className="text-[11px] uppercase tracking-wide text-muted">{label}</span>
    </div>
  )
}

// Dashboard: a compact aggregate of the current security posture, shown above
// the project list on the home page.
export function Dashboard({ stats }: { stats: Stats }) {
  const sev = stats.severity
  const t = stats.triage

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl">
          <span className="gradient-text">Overview</span>
        </h1>
        <p className="text-sm text-muted">Current exposure across all projects (latest scan per service).</p>
      </div>

      {/* KPIs + severity on one compact band */}
      <div className="glass-card flex flex-wrap items-center gap-x-6 gap-y-3 py-4">
        <Kpi label="Projects" value={stats.totals.projects} />
        <Kpi label="Services" value={stats.totals.assets} />
        <Kpi label="Findings" value={stats.totals.findings} />
        <div className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-2">
          {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
            <span key={k} className="flex items-center gap-1.5">
              <SeverityBadge severity={k} />
              <span className="text-sm text-white">{sev[k]}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="glass-card">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Severity trend</p>
        <TrendChart points={stats.trend} />
      </div>

      <div className="glass-card">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Triage</p>
        <div className="flex flex-col gap-1.5 text-sm">
          <Row label="Open" value={t.open} color="text-muted" />
          <Row label="False positive" value={t.false_positive} color="text-sev-low" />
          <Row label="Accepted risk" value={t.accepted_risk} color="text-sev-medium" />
          <Row label="Fixed" value={t.fixed} color="text-sev-info" />
        </div>

        {stats.projects.length > 0 && (
          <>
            <p className="mb-2 mt-4 text-xs font-semibold uppercase tracking-wide text-muted">By project</p>
            <div className="space-y-1.5">
              {stats.projects.map((p) => (
                <div key={p.id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate text-white">{p.name}</span>
                  <span className="flex items-center gap-2">
                    <Count n={p.critical} color="#f87171" title="Critical" />
                    <Count n={p.high} color="#fb923c" title="High" />
                    <Count n={p.medium} color="#facc15" title="Medium" />
                    <Count n={p.low} color="#60a5fa" title="Low" />
                    <span className="text-muted">{p.total}</span>
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
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

import { useEffect, useMemo, useState } from "react"
import { useNavigate, useParams } from "react-router-dom"
import { api } from "../api/client"
import { SeverityBadge, severityRank } from "../components/SeverityBadge"
import { StatusPill } from "../components/StatusPill"
import type { Finding, Progress, ScanDiff, ScanResult } from "../types"

const POLL_MS = 1500

export function ScanDetail() {
  const { id = "" } = useParams()
  const navigate = useNavigate()
  const [data, setData] = useState<ScanResult | null>(null)
  const [progress, setProgress] = useState<Progress | null>(null)
  const [diff, setDiff] = useState<ScanDiff | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>
    let active = true

    async function tick() {
      try {
        const res = await api.getScan(id)
        if (!active) return
        setData(res)
        const st = res.scan.status
        if (st === "PENDING" || st === "PROCESSING") {
          try {
            const p = await api.getProgress(id)
            if (active) setProgress(p)
          } catch {
            /* progress is best-effort */
          }
          timer = setTimeout(tick, POLL_MS)
        } else {
          setProgress(null)
          if (st === "COMPLETED") {
            try {
              const d = await api.getScanDiff(id)
              if (active) setDiff(d)
            } catch {
              /* diff is best-effort */
            }
          }
        }
      } catch (e) {
        if (active) setError(String(e))
      }
    }
    void tick()
    return () => {
      active = false
      clearTimeout(timer)
    }
  }, [id])

  const findings = data?.findings ?? []

  // Group findings by host, hosts sorted, findings by severity desc.
  const groups = useMemo(() => {
    const byHost: Record<string, Finding[]> = {}
    for (const f of findings) {
      const host = f.target.host || f.target.domain || "—"
      ;(byHost[host] ??= []).push(f)
    }
    for (const host of Object.keys(byHost)) {
      byHost[host].sort((a, b) => severityRank[b.severity] - severityRank[a.severity])
    }
    return Object.keys(byHost)
      .sort()
      .map((host) => ({ host, items: byHost[host] }))
  }, [findings])

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1
    return c
  }, [findings])

  const back = (
    <button
      onClick={() => navigate(-1)}
      className="text-sm text-muted hover:text-white"
    >
      ← Back
    </button>
  )

  if (error)
    return (
      <div className="space-y-4">
        {back}
        <p className="text-sev-critical">{error}</p>
      </div>
    )
  if (!data)
    return (
      <div className="space-y-4">
        {back}
        <p className="text-muted">Loading…</p>
      </div>
    )

  const { scan } = data
  const running = scan.status === "PENDING" || scan.status === "PROCESSING"

  return (
    <div className="space-y-6">
      {back}
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-3xl">
            <span className="gradient-text">Scan</span>
          </h1>
          <p className="flex items-center gap-2 text-muted">
            Status: <StatusPill status={scan.status} />
            {running && <span className="animate-pulse">●</span>}
          </p>
        </div>
        <DownloadMenu scanID={scan.id} />
      </div>

      {running && progress && (
        <div className="glass-card">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted">Phase: {phaseLabel(progress.phase)}</span>
            {progress.total > 0 && (
              <span className="text-muted">
                {progress.done}/{progress.total}
              </span>
            )}
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded bg-white/10">
            <div
              className={progress.total > 0 ? "" : "animate-pulse"}
              style={{
                height: "100%",
                width: progress.total > 0 ? `${Math.round((progress.done / progress.total) * 100)}%` : "25%",
                background: "linear-gradient(90deg,#8b5cf6,#06b6d4)",
                transition: "width .3s ease",
              }}
            />
          </div>
          {progress.log && progress.log.length > 0 && (
            <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-words text-xs text-muted">
              {progress.log.join("\n")}
            </pre>
          )}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_320px] lg:items-start">
        {/* Right rail: report info (severity summary + changes). Stacks above
            the findings on narrow screens; sticks alongside them on wide ones. */}
        <aside className="space-y-4 lg:order-2 lg:sticky lg:top-20">
          <div className="glass-card flex flex-col gap-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted">
              Severity
            </p>
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
              <div key={sev} className="flex items-center justify-between gap-2">
                <SeverityBadge severity={sev} />
                <span className="text-white">{counts[sev] ?? 0}</span>
              </div>
            ))}
            <div className="mt-1 border-t border-white/10 pt-2 text-sm text-muted">
              total: {findings.length}
            </div>
          </div>

          {!running && diff && <ChangesCard diff={diff} />}
        </aside>

        <div className="min-w-0 space-y-6 lg:order-1">
          {scan.error && (
            <details className="glass-card">
              <summary className="cursor-pointer text-sm font-semibold text-muted">
                Module warnings ({scan.error.split(";").length})
              </summary>
              <p className="mt-1 text-xs text-muted">
                Non-fatal errors while probing some hosts (e.g. no service on the port).
                They do not stop the scan.
              </p>
              <p className="mt-2 break-words text-xs text-muted">{scan.error}</p>
            </details>
          )}

          {groups.map((g) => (
            <div key={g.host} className="glass-card">
              <h3 className="mb-3 text-lg">{g.host}</h3>
              <div className="space-y-2">
                {g.items.map((f, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 border-t border-white/5 pt-2 first:border-0 first:pt-0"
                  >
                    <SeverityBadge severity={f.severity} />
                    <div className="min-w-0">
                      <p className="text-white">{f.title}</p>
                      <p className="text-xs text-muted">
                        {f.scanner}
                        {f.evidence ? " · " + shortEvidence(f.evidence) : ""}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          {!running && findings.length === 0 && (
            <p className="text-muted">No findings.</p>
          )}
        </div>
      </div>
    </div>
  )
}

function ChangesCard({ diff }: { diff: ScanDiff }) {
  const first = diff.previous_scan_id === ""
  const newList = diff.new ?? []
  const resolvedList = diff.resolved ?? []

  return (
    <div className="glass-card space-y-3">
      <div className="flex flex-wrap items-center gap-4">
        <h3 className="text-lg">
          {first ? "First scan" : "Changes since last scan"}
        </h3>
        {first ? (
          <span className="text-sm text-muted">No earlier scan to compare — all findings are new.</span>
        ) : (
          <div className="flex flex-wrap gap-4 text-sm">
            <span className="text-sev-high">+{diff.counts.new} new</span>
            <span className="text-sev-low">−{diff.counts.resolved} resolved</span>
            <span className="text-muted">{diff.counts.unchanged} unchanged</span>
          </div>
        )}
      </div>

      {!first && newList.length > 0 && (
        <ChangeList label="New" color="text-sev-high" items={newList} />
      )}
      {!first && resolvedList.length > 0 && (
        <ChangeList label="Resolved" color="text-sev-low" items={resolvedList} />
      )}
    </div>
  )
}

function ChangeList({ label, color, items }: { label: string; color: string; items: Finding[] }) {
  return (
    <details>
      <summary className={`cursor-pointer text-sm font-semibold ${color}`}>
        {label} ({items.length})
      </summary>
      <div className="mt-2 space-y-1">
        {items.map((f, i) => (
          <p key={i} className="text-xs text-muted">
            {f.target.host || f.target.domain || "—"} · {f.scanner} · {f.title}
          </p>
        ))}
      </div>
    </details>
  )
}

function DownloadMenu({ scanID }: { scanID: string }) {
  const [open, setOpen] = useState(false)

  function download(format: "json" | "sarif") {
    const a = document.createElement("a")
    a.href = api.exportScanURL(scanID, format)
    a.download = `scan-${scanID}.${format === "sarif" ? "sarif" : "json"}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    setOpen(false)
  }

  return (
    <div className="relative" onBlur={() => setTimeout(() => setOpen(false), 120)}>
      <button className="btn-ghost whitespace-nowrap" onClick={() => setOpen((o) => !o)}>
        Download ▾
      </button>
      {open && (
        <div
          className="absolute right-0 z-20 mt-1 w-44 overflow-hidden rounded-lg border border-white/10 bg-[#0f0f19] shadow-lg"
        >
          <button
            className="block w-full px-4 py-2 text-left text-sm text-white hover:bg-white/10"
            onClick={() => download("json")}
          >
            JSON (Aegis)
          </button>
          <button
            className="block w-full px-4 py-2 text-left text-sm text-white hover:bg-white/10"
            onClick={() => download("sarif")}
          >
            SARIF
          </button>
        </div>
      )}
    </div>
  )
}

function phaseLabel(phase: string): string {
  switch (phase) {
    case "discovery":
      return "Discovery"
    case "probing":
      return "Probing"
    case "done":
      return "Done"
    default:
      return "Starting"
  }
}

function shortEvidence(ev: Record<string, unknown>): string {
  return Object.entries(ev)
    .filter(([k]) => k !== "name")
    .slice(0, 3)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : String(v)}`)
    .join(" · ")
    .slice(0, 160)
}

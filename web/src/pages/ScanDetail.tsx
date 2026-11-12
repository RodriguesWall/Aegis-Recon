import { useEffect, useMemo, useState } from "react"
import { useParams } from "react-router-dom"
import { api } from "../api/client"
import { SeverityBadge, severityRank } from "../components/SeverityBadge"
import { StatusPill } from "../components/StatusPill"
import type { Finding, ScanResult } from "../types"

const POLL_MS = 2000

export function ScanDetail() {
  const { id = "" } = useParams()
  const [data, setData] = useState<ScanResult | null>(null)
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
          timer = setTimeout(tick, POLL_MS)
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

  if (error) return <p className="text-sev-critical">{error}</p>
  if (!data) return <p className="text-muted">Carregando…</p>

  const { scan } = data
  const running = scan.status === "PENDING" || scan.status === "PROCESSING"

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Scan</span>
        </h1>
        <p className="flex items-center gap-2 text-muted">
          Status: <StatusPill status={scan.status} />
          {running && <span className="animate-pulse">●</span>}
        </p>
      </div>

      <div className="glass-card flex flex-wrap gap-4">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
          <div key={sev} className="flex items-center gap-2">
            <SeverityBadge severity={sev} />
            <span className="text-white">{counts[sev] ?? 0}</span>
          </div>
        ))}
        <div className="ml-auto text-muted">total: {findings.length}</div>
      </div>

      {scan.error && (
        <details className="glass-card">
          <summary className="cursor-pointer text-sm font-semibold text-muted">
            Avisos dos módulos ({scan.error.split(";").length})
          </summary>
          <p className="mt-1 text-xs text-muted">
            Erros não-fatais ao sondar alguns hosts (ex: serviço ausente na porta).
            Não impedem o scan.
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
        <p className="text-muted">Nenhum finding.</p>
      )}
    </div>
  )
}

function shortEvidence(ev: Record<string, unknown>): string {
  return Object.entries(ev)
    .filter(([k]) => k !== "name")
    .slice(0, 3)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : String(v)}`)
    .join(" · ")
    .slice(0, 160)
}

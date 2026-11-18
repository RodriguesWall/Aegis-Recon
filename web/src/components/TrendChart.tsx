import type { TrendPoint } from "../types"

// Severity series: fixed order, established risk colors (ordinal scale). Legend
// + labels provide the secondary encoding so identity is never color-alone.
const SERIES: { key: keyof Omit<TrendPoint, "scan_id" | "completed_at">; label: string; color: string }[] = [
  { key: "critical", label: "Critical", color: "#f87171" },
  { key: "high", label: "High", color: "#fb923c" },
  { key: "medium", label: "Medium", color: "#facc15" },
  { key: "low", label: "Low", color: "#60a5fa" },
  { key: "info", label: "Info", color: "#94a3b8" },
]

const H = 108 // plot height in px

// TrendChart draws one stacked bar per completed scan (oldest → newest),
// segmented by severity. Pure CSS; each segment carries a native hover tooltip.
export function TrendChart({ points }: { points: TrendPoint[] }) {
  if (!points || points.length === 0) {
    return <p className="text-sm text-muted">No scan history yet — run a few scans to see the trend.</p>
  }

  const totals = points.map((p) => p.critical + p.high + p.medium + p.low + p.info)
  const max = Math.max(1, ...totals)

  return (
    <div>
      <div className="flex items-end gap-1" style={{ height: H }}>
        {points.map((p, i) => {
          const total = totals[i]
          const date = new Date(p.completed_at).toLocaleString()
          return (
            <div key={p.scan_id + i} className="flex flex-1 flex-col-reverse" style={{ gap: 2 }}>
              {SERIES.map((s) => {
                const v = p[s.key]
                if (!v) return null
                return (
                  <div
                    key={s.key}
                    title={`${date}\n${s.label}: ${v}`}
                    style={{
                      height: `${(v / max) * H}px`,
                      background: s.color,
                      borderRadius: 2,
                    }}
                  />
                )
              })}
              {total === 0 && (
                <div title={`${date}\nClean`} style={{ height: 3, background: "#86efac", borderRadius: 2 }} />
              )}
            </div>
          )
        })}
      </div>
      <p className="mt-2 text-xs text-muted">last {points.length} scans · oldest → newest</p>

      <div className="mt-3 flex flex-wrap gap-3">
        {SERIES.map((s) => (
          <span key={s.key} className="flex items-center gap-1 text-xs text-muted">
            <span style={{ width: 10, height: 10, background: s.color, borderRadius: 2 }} />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  )
}

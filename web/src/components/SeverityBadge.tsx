import type { Severity } from "../types"

// Colors and labels ported from pentest-landing's PremiumReport.
const style: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: "#fca5a5", bg: "rgba(239,68,68,.10)", label: "Critical" },
  high: { color: "#fdba74", bg: "rgba(249,115,22,.10)", label: "High" },
  medium: { color: "#fde047", bg: "rgba(234,179,8,.10)", label: "Medium" },
  low: { color: "#93c5fd", bg: "rgba(59,130,246,.10)", label: "Low" },
  info: { color: "#94a3b8", bg: "rgba(148,163,184,.10)", label: "Info" },
}

export const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = style[severity] ?? style.info
  return (
    <span
      className="inline-block rounded-md px-2 py-0.5 text-xs font-semibold"
      style={{ color: s.color, background: s.bg, border: `1px solid ${s.color}33` }}
    >
      {s.label}
    </span>
  )
}

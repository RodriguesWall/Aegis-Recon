import type { ScanStatus } from "../types"

const style: Record<ScanStatus, { color: string; bg: string }> = {
  PENDING: { color: "#94a3b8", bg: "rgba(148,163,184,.12)" },
  PROCESSING: { color: "#fde047", bg: "rgba(234,179,8,.12)" },
  COMPLETED: { color: "#9ef01a", bg: "rgba(158,240,26,.12)" },
  FAILED: { color: "#fca5a5", bg: "rgba(239,68,68,.12)" },
}

export function StatusPill({ status }: { status: ScanStatus }) {
  const s = style[status] ?? style.PENDING
  return (
    <span
      className="inline-block rounded-md px-2 py-0.5 text-xs font-semibold"
      style={{ color: s.color, background: s.bg, border: `1px solid ${s.color}33` }}
    >
      {status}
    </span>
  )
}

import { useEffect, useState } from "react"
import { createPortal } from "react-dom"
import { api } from "../api/client"

const PRESETS: { label: string; hours: number }[] = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "12h", hours: 12 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
]

// ScheduleDialog edits an asset's automatic-scan schedule: on/off + interval in
// hours. Saves interval as minutes. Shows the next scheduled run.
export function ScheduleDialog({
  assetName,
  assetID,
  onClose,
  onSaved,
}: {
  assetName: string
  assetID: string
  onClose: () => void
  onSaved: () => void
}) {
  const [enabled, setEnabled] = useState(false)
  const [hours, setHours] = useState(24)
  const [nextRun, setNextRun] = useState("")
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void api
      .getSchedule(assetID)
      .then((s) => {
        setEnabled(s.enabled)
        if (s.interval_minutes > 0) setHours(Math.max(1, Math.round(s.interval_minutes / 60)))
        if (s.enabled) setNextRun(s.next_run)
      })
      .finally(() => setLoading(false))
  }, [assetID])

  async function save() {
    setBusy(true)
    try {
      await api.setSchedule(assetID, { enabled, interval_minutes: hours * 60 })
      onSaved()
      onClose()
    } finally {
      setBusy(false)
    }
  }

  // Portal to body: a .glass-card ancestor has backdrop-filter, which makes it
  // the containing block for position:fixed descendants. Rendered inline, the
  // overlay would be trapped inside the card instead of covering the viewport.
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="glass-card w-full max-w-md"
        style={{ background: "#0f0f19" }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="mb-1 text-lg">Schedule scans — {assetName}</h3>
        <p className="mb-3 text-sm text-muted">
          Run a scan automatically at a fixed interval. A run is skipped if a scan
          is already in progress for this service.
        </p>

        {loading ? (
          <p className="text-muted">Loading…</p>
        ) : (
          <>
            <label className="flex items-center gap-2 text-sm text-white">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              Enable automatic scans
            </label>

            <div className={enabled ? "mt-4" : "mt-4 opacity-40 pointer-events-none"}>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
                Interval
              </p>
              <div className="mb-2 flex flex-wrap gap-2">
                {PRESETS.map((p) => (
                  <button
                    key={p.hours}
                    className={`rounded-md border px-3 py-1 text-xs ${
                      hours === p.hours
                        ? "border-primary text-primary"
                        : "border-white/15 text-muted"
                    }`}
                    onClick={() => setHours(p.hours)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-sm text-muted">
                every
                <input
                  type="number"
                  min={1}
                  className="input w-20"
                  value={hours}
                  onChange={(e) => setHours(Math.max(1, Number(e.target.value) || 1))}
                />
                hour(s)
              </label>
              {enabled && nextRun && (
                <p className="mt-2 text-xs text-muted">
                  Next run: {new Date(nextRun).toLocaleString()}
                </p>
              )}
            </div>
          </>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button className="btn-ghost" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy || loading} onClick={() => void save()}>
            Save
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

import { useState } from "react"
import { api } from "../api/client"
import type { Triage, TriageStatus } from "../types"

const STATUSES: TriageStatus[] = ["open", "false-positive", "accepted-risk", "fixed"]

const LABEL: Record<TriageStatus, string> = {
  open: "Open",
  "false-positive": "False positive",
  "accepted-risk": "Accepted risk",
  fixed: "Fixed",
}

// Color per status for the select border/text.
const COLOR: Record<TriageStatus, string> = {
  open: "text-muted",
  "false-positive": "text-sev-low",
  "accepted-risk": "text-sev-medium",
  fixed: "text-sev-info",
}

// TriageControl is the per-finding status picker. Status change saves
// immediately; the note (shown for any non-open status) saves on blur/Enter.
export function TriageControl({
  assetID,
  fingerprint,
  current,
  onSaved,
}: {
  assetID: string
  fingerprint: string
  current?: Triage
  onSaved: () => void
}) {
  const status = current?.status ?? "open"
  const [note, setNote] = useState(current?.note ?? "")
  const [busy, setBusy] = useState(false)

  async function save(nextStatus: TriageStatus, nextNote: string) {
    setBusy(true)
    try {
      await api.setTriage(assetID, { fingerprint, status: nextStatus, note: nextNote })
      onSaved()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <select
        className={`rounded-md border border-white/15 bg-white/5 px-2 py-1 text-xs ${COLOR[status]}`}
        value={status}
        disabled={busy}
        onChange={(e) => void save(e.target.value as TriageStatus, note)}
      >
        {STATUSES.map((s) => (
          <option key={s} value={s} className="bg-[#0f0f19] text-white">
            {LABEL[s]}
          </option>
        ))}
      </select>
      {status !== "open" && (
        <input
          className="w-40 rounded-md border border-white/10 bg-white/5 px-2 py-1 text-xs text-muted"
          placeholder="note (optional)"
          value={note}
          disabled={busy}
          onChange={(e) => setNote(e.target.value)}
          onBlur={() => {
            if ((current?.note ?? "") !== note) void save(status, note)
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur()
          }}
        />
      )}
    </div>
  )
}

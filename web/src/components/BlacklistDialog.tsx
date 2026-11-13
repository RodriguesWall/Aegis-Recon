import { useState } from "react"

// BlacklistDialog edits an asset's scan blacklist: one host pattern per line.
// Clicking the backdrop or Cancel dismisses; Save persists the parsed lines.
export function BlacklistDialog({
  assetName,
  initial,
  onSave,
  onCancel,
}: {
  assetName: string
  initial: string[]
  onSave: (patterns: string[]) => Promise<void> | void
  onCancel: () => void
}) {
  const [text, setText] = useState(initial.join("\n"))
  const [busy, setBusy] = useState(false)

  const parse = (raw: string) =>
    raw
      .split("\n")
      .map((l) => l.trim().toLowerCase())
      .filter((l) => l !== "")

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onCancel}
    >
      <div
        className="glass-card w-full max-w-md"
        style={{ background: "#0f0f19" }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="mb-1 text-lg">Scan blacklist — {assetName}</h3>
        <p className="mb-3 text-sm text-muted">
          Hosts matched here are excluded from scans, even if in scope. One
          pattern per line.
        </p>

        <textarea
          className="input h-36 w-full font-mono text-sm"
          placeholder={"example.com\n*.staging.example.com"}
          value={text}
          autoFocus
          onChange={(e) => setText(e.target.value)}
        />

        <div className="mt-3 rounded-lg border border-white/10 bg-white/5 p-3 text-xs text-muted">
          <p className="mb-1 font-semibold text-white">How matching works</p>
          <p>
            <code className="text-primary">example.com</code> — excludes only that
            exact host.
          </p>
          <p>
            <code className="text-primary">*.example.com</code> — excludes
            example.com <em>and</em> every subdomain of it.
          </p>
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button className="btn-ghost" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onSave(parse(text))
              } finally {
                setBusy(false)
              }
            }}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  )
}

import { useState } from "react"

// ConfirmDialog is a modal overlay for destructive confirmations. Clicking the
// backdrop or Cancel dismisses; Confirm runs onConfirm (awaited, with a busy
// state).
export function ConfirmDialog({
  title,
  message,
  confirmLabel = "Delete",
  onConfirm,
  onCancel,
}: {
  title: string
  message: string
  confirmLabel?: string
  onConfirm: () => Promise<void> | void
  onCancel: () => void
}) {
  const [busy, setBusy] = useState(false)
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onCancel}
    >
      <div
        className="glass-card w-full max-w-sm"
        style={{ background: "#0f0f19" }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="mb-2 text-lg">{title}</h3>
        <p className="mb-4 text-sm text-muted">{message}</p>
        <div className="flex justify-end gap-2">
          <button className="btn-ghost" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
          <button
            className="btn text-white"
            style={{ background: "#ef4444" }}
            disabled={busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onConfirm()
              } finally {
                setBusy(false)
              }
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

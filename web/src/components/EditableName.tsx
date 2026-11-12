import { useState } from "react"
import { Link } from "react-router-dom"

// EditableName shows a name (optionally as a link) with an "editar" affordance
// that swaps to an inline input. onSave persists; on error the name is kept.
export function EditableName({
  value,
  to,
  onSave,
}: {
  value: string
  to?: string
  onSave: (name: string) => Promise<void>
}) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(value)
  const [busy, setBusy] = useState(false)

  async function save() {
    const name = draft.trim()
    if (!name || name === value) {
      setEditing(false)
      return
    }
    setBusy(true)
    try {
      await onSave(name)
      setEditing(false)
    } finally {
      setBusy(false)
    }
  }

  if (editing) {
    return (
      <div className="flex items-center gap-2">
        <input
          className="input"
          value={draft}
          autoFocus
          disabled={busy}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void save()
            if (e.key === "Escape") {
              setDraft(value)
              setEditing(false)
            }
          }}
        />
        <button className="btn-primary" disabled={busy} onClick={() => void save()}>
          Salvar
        </button>
        <button
          className="btn-ghost"
          disabled={busy}
          onClick={() => {
            setDraft(value)
            setEditing(false)
          }}
        >
          Cancelar
        </button>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2">
      {to ? (
        <Link to={to} className="text-lg hover:underline">
          {value}
        </Link>
      ) : (
        <span className="text-lg">{value}</span>
      )}
      <button
        className="text-xs text-muted hover:text-white"
        onClick={() => {
          setDraft(value)
          setEditing(true)
        }}
      >
        editar
      </button>
    </div>
  )
}

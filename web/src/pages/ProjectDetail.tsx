import { useEffect, useState } from "react"
import { Link, useNavigate, useParams } from "react-router-dom"
import { api } from "../api/client"
import { BlacklistDialog } from "../components/BlacklistDialog"
import { CardMenu } from "../components/CardMenu"
import { ConfirmDialog } from "../components/ConfirmDialog"
import { ScheduleDialog } from "../components/ScheduleDialog"
import { ScanSeverityTag } from "../components/SeverityBadge"
import { StatusPill } from "../components/StatusPill"
import type { Asset, Scan } from "../types"

const POLL_MS = 2000

export function ProjectDetail() {
  const { id = "" } = useParams()
  const [assets, setAssets] = useState<Asset[]>([])
  const [scansByAsset, setScansByAsset] = useState<Record<string, Scan[]>>({})
  const [name, setName] = useState("")
  const [error, setError] = useState("")

  async function load() {
    try {
      const as = (await api.listAssets(id)) ?? []
      setAssets(as)
      const map: Record<string, Scan[]> = {}
      for (const a of as) {
        map[a.id] = (await api.listScans(a.id)) ?? []
      }
      setScansByAsset(map)
    } catch (e) {
      setError(String(e))
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  // Scans run server-side in the background. While any is still PENDING or
  // PROCESSING, refresh the list so its status updates on its own — without this
  // the list freezes at the status it had when the page mounted (see Notes #17).
  const hasActive = Object.values(scansByAsset).some((list) =>
    list.some((s) => s.status === "PENDING" || s.status === "PROCESSING"),
  )
  useEffect(() => {
    if (!hasActive) return
    const t = setInterval(() => void load(), POLL_MS)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasActive])

  async function addAsset(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    try {
      await api.createAsset(id, name.trim())
      setName("")
      setError("")
      void load()
    } catch (err) {
      setError(String(err))
    }
  }

  return (
    <div className="space-y-6">
      <Link to="/" className="text-sm text-muted hover:text-white">
        ← Projects
      </Link>

      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Services</span>
        </h1>
        <p className="text-muted">Register domains/hosts and trigger scans.</p>
      </div>

      <form onSubmit={addAsset} className="glass-card flex gap-3">
        <input
          className="input"
          placeholder="Service domain (e.g. example.com)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button type="submit" className="btn-primary whitespace-nowrap">
          Add
        </button>
      </form>

      {error && <p className="text-sev-critical">{error}</p>}

      <div className="space-y-4">
        {assets.map((a) => (
          <AssetCard key={a.id} asset={a} scans={scansByAsset[a.id] ?? []} onChanged={load} />
        ))}
      </div>

      {assets.length === 0 && <p className="text-muted">No services yet.</p>}
    </div>
  )
}

function AssetCard({
  asset,
  scans,
  onChanged,
}: {
  asset: Asset
  scans: Scan[]
  onChanged: () => void
}) {
  const navigate = useNavigate()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(asset.name)
  const [confirm, setConfirm] = useState(false)
  const [blacklistOpen, setBlacklistOpen] = useState(false)
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [scanToDelete, setScanToDelete] = useState<string | null>(null)
  const [includeInfo, setIncludeInfo] = useState(false)

  async function save() {
    const n = draft.trim()
    if (!n || n === asset.name) {
      setEditing(false)
      return
    }
    await api.updateAsset(asset.id, n)
    setEditing(false)
    onChanged()
  }

  async function runScan() {
    const scan = await api.createScan(asset.id, includeInfo)
    navigate(`/scans/${scan.id}`)
  }

  return (
    <div className="glass-card">
      <div className="flex items-center justify-between gap-3">
        <div className="flex-1">
          {editing ? (
            <div className="flex gap-2">
              <input
                className="input"
                value={draft}
                autoFocus
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void save()
                  if (e.key === "Escape") {
                    setDraft(asset.name)
                    setEditing(false)
                  }
                }}
              />
              <button className="btn-primary" onClick={() => void save()}>
                Save
              </button>
            </div>
          ) : (
            <h3 className="text-lg">{asset.name}</h3>
          )}
          <p className="text-xs text-muted">{asset.type}</p>
        </div>
        <button className="btn-accent" onClick={() => void runScan()}>
          Run scan
        </button>
        <CardMenu
          items={[
            { label: "Edit", onClick: () => setEditing(true) },
            {
              label: `Blacklist${asset.blacklist?.length ? ` (${asset.blacklist.length})` : ""}`,
              onClick: () => setBlacklistOpen(true),
            },
            { label: "Schedule", onClick: () => setScheduleOpen(true) },
            { label: "Delete", danger: true, onClick: () => setConfirm(true) },
          ]}
        />
      </div>

      <label className="mt-3 flex items-center gap-2 text-xs text-muted">
        <input
          type="checkbox"
          checked={includeInfo}
          onChange={(e) => setIncludeInfo(e.target.checked)}
        />
        Include informational findings (Info) — dns/ports/tls inventory
      </label>

      {scans.length > 0 && (
        <div className="mt-4 border-t border-white/10 pt-3">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
            Previous scans — click to view the report
          </p>
          <div className="space-y-2">
            {scans.map((s) => (
              <div
                key={s.id}
                className="flex items-center justify-between gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm transition-colors hover:border-primary/40 hover:bg-white/10"
              >
                <Link to={`/scans/${s.id}`} className="flex flex-1 items-center justify-between gap-2">
                  <span className="flex items-center gap-2">
                    <StatusPill status={s.status} />
                    <ScanSeverityTag value={s.top_severity} />
                    <span className="text-muted">
                      {new Date(s.created_at).toLocaleString()}
                    </span>
                  </span>
                  <span className="text-primary">view report →</span>
                </Link>
                <CardMenu
                  items={[
                    {
                      label: "Delete",
                      danger: true,
                      onClick: () => setScanToDelete(s.id),
                    },
                  ]}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {blacklistOpen && (
        <BlacklistDialog
          assetName={asset.name}
          initial={asset.blacklist ?? []}
          onCancel={() => setBlacklistOpen(false)}
          onSave={async (patterns) => {
            await api.setAssetBlacklist(asset.id, patterns)
            setBlacklistOpen(false)
            onChanged()
          }}
        />
      )}

      {scheduleOpen && (
        <ScheduleDialog
          assetName={asset.name}
          assetID={asset.id}
          onClose={() => setScheduleOpen(false)}
          onSaved={onChanged}
        />
      )}

      {confirm && (
        <ConfirmDialog
          title="Delete service"
          message={`Delete "${asset.name}" and all its scans and findings? This action cannot be undone.`}
          onCancel={() => setConfirm(false)}
          onConfirm={async () => {
            await api.deleteAsset(asset.id)
            setConfirm(false)
            onChanged()
          }}
        />
      )}

      {scanToDelete && (
        <ConfirmDialog
          title="Delete scan"
          message="Delete this scan and its findings? This action cannot be undone."
          onCancel={() => setScanToDelete(null)}
          onConfirm={async () => {
            await api.deleteScan(scanToDelete)
            setScanToDelete(null)
            onChanged()
          }}
        />
      )}
    </div>
  )
}

import { useEffect, useState } from "react"
import { Link, useNavigate, useParams } from "react-router-dom"
import { api } from "../api/client"
import { CardMenu } from "../components/CardMenu"
import { ConfirmDialog } from "../components/ConfirmDialog"
import { StatusPill } from "../components/StatusPill"
import type { Asset, Scan } from "../types"

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
        ← Projetos
      </Link>

      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Serviços</span>
        </h1>
        <p className="text-muted">Cadastre domínios/hosts e dispare scans.</p>
      </div>

      <form onSubmit={addAsset} className="glass-card flex gap-3">
        <input
          className="input"
          placeholder="Domínio do serviço (ex: example.com)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button type="submit" className="btn-primary whitespace-nowrap">
          Adicionar
        </button>
      </form>

      {error && <p className="text-sev-critical">{error}</p>}

      <div className="space-y-4">
        {assets.map((a) => (
          <AssetCard key={a.id} asset={a} scans={scansByAsset[a.id] ?? []} onChanged={load} />
        ))}
      </div>

      {assets.length === 0 && <p className="text-muted">Nenhum serviço ainda.</p>}
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
  const [scanToDelete, setScanToDelete] = useState<string | null>(null)

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
    const scan = await api.createScan(asset.id)
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
                Salvar
              </button>
            </div>
          ) : (
            <h3 className="text-lg">{asset.name}</h3>
          )}
          <p className="text-xs text-muted">{asset.type}</p>
        </div>
        <button className="btn-accent" onClick={() => void runScan()}>
          Rodar scan
        </button>
        <CardMenu
          items={[
            { label: "Editar", onClick: () => setEditing(true) },
            { label: "Excluir", danger: true, onClick: () => setConfirm(true) },
          ]}
        />
      </div>

      {scans.length > 0 && (
        <div className="mt-4 border-t border-white/10 pt-3">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
            Scans anteriores — clique para ver o report
          </p>
          <div className="space-y-2">
            {scans.map((s) => (
              <Link
                key={s.id}
                to={`/scans/${s.id}`}
                className="flex items-center justify-between rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm transition-colors hover:border-primary/40 hover:bg-white/10"
              >
                <span className="flex items-center gap-2">
                  <StatusPill status={s.status} />
                  <span className="text-muted">{new Date(s.created_at).toLocaleString()}</span>
                </span>
                <span className="flex items-center gap-3">
                  <span className="text-primary">ver report →</span>
                  <button
                    className="text-xs text-muted hover:text-sev-critical"
                    onClick={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      setScanToDelete(s.id)
                    }}
                  >
                    excluir
                  </button>
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {confirm && (
        <ConfirmDialog
          title="Excluir serviço"
          message={`Excluir "${asset.name}" e todos os seus scans e findings? Esta ação não pode ser desfeita.`}
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
          title="Excluir scan"
          message="Excluir este scan e seus findings? Esta ação não pode ser desfeita."
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

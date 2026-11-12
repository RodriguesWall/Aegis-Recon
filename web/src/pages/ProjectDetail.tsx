import { useEffect, useState } from "react"
import { Link, useNavigate, useParams } from "react-router-dom"
import { api } from "../api/client"
import { EditableName } from "../components/EditableName"
import { StatusPill } from "../components/StatusPill"
import type { Asset, Scan } from "../types"

export function ProjectDetail() {
  const { id = "" } = useParams()
  const navigate = useNavigate()
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

  async function runScan(assetID: string) {
    try {
      const scan = await api.createScan(assetID)
      navigate(`/scans/${scan.id}`)
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
          <div key={a.id} className="glass-card">
            <div className="flex items-center justify-between gap-3">
              <div>
                <EditableName
                  value={a.name}
                  onSave={async (name) => {
                    await api.updateAsset(a.id, name)
                    void load()
                  }}
                />
                <p className="text-xs text-muted">{a.type}</p>
              </div>
              <button className="btn-accent" onClick={() => runScan(a.id)}>
                Rodar scan
              </button>
            </div>
            {(scansByAsset[a.id]?.length ?? 0) > 0 && (
              <div className="mt-4 border-t border-white/10 pt-3">
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                  Scans anteriores — clique para ver o report
                </p>
                <div className="space-y-2">
                  {scansByAsset[a.id].map((s) => (
                    <Link
                      key={s.id}
                      to={`/scans/${s.id}`}
                      className="flex items-center justify-between rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm transition-colors hover:border-primary/40 hover:bg-white/10"
                    >
                      <span className="flex items-center gap-2">
                        <StatusPill status={s.status} />
                        <span className="text-muted">
                          {new Date(s.created_at).toLocaleString()}
                        </span>
                      </span>
                      <span className="text-primary">ver report →</span>
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {assets.length === 0 && <p className="text-muted">Nenhum serviço ainda.</p>}
    </div>
  )
}

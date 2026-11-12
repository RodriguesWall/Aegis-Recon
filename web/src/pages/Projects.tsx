import { useEffect, useState } from "react"
import { api } from "../api/client"
import { EditableName } from "../components/EditableName"
import type { Project } from "../types"

export function Projects() {
  const [projects, setProjects] = useState<Project[]>([])
  const [name, setName] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)

  async function load() {
    try {
      setProjects((await api.listProjects()) ?? [])
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  async function create(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    try {
      await api.createProject(name.trim())
      setName("")
      setError("")
      void load()
    } catch (err) {
      setError(String(err))
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl">
          <span className="gradient-text">Projetos</span>
        </h1>
        <p className="text-muted">Cadastre um projeto e seus serviços para escanear.</p>
      </div>

      <form onSubmit={create} className="glass-card flex gap-3">
        <input
          className="input"
          placeholder="Nome do projeto (ex: Produto X)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button type="submit" className="btn-primary whitespace-nowrap">
          Criar
        </button>
      </form>

      {error && <p className="text-sev-critical">{error}</p>}
      {loading && <p className="text-muted">Carregando…</p>}

      <div className="grid gap-4 sm:grid-cols-2">
        {projects.map((p) => (
          <div key={p.id} className="glass-card">
            <EditableName
              value={p.name}
              to={`/projects/${p.id}`}
              onSave={async (name) => {
                await api.updateProject(p.id, name)
                void load()
              }}
            />
            <p className="mt-1 text-xs text-muted">
              {new Date(p.created_at).toLocaleString()}
            </p>
          </div>
        ))}
      </div>

      {!loading && projects.length === 0 && (
        <p className="text-muted">Nenhum projeto ainda.</p>
      )}
    </div>
  )
}

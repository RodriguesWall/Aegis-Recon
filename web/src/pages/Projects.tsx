import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { api } from "../api/client"
import { CardMenu } from "../components/CardMenu"
import { ConfirmDialog } from "../components/ConfirmDialog"
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
          <ProjectCard key={p.id} project={p} onChanged={load} />
        ))}
      </div>

      {!loading && projects.length === 0 && (
        <p className="text-muted">Nenhum projeto ainda.</p>
      )}
    </div>
  )
}

function ProjectCard({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const navigate = useNavigate()
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(project.name)
  const [confirm, setConfirm] = useState(false)

  async function save() {
    const n = draft.trim()
    if (!n || n === project.name) {
      setEditing(false)
      return
    }
    await api.updateProject(project.id, n)
    setEditing(false)
    onChanged()
  }

  return (
    <div
      className="glass-card cursor-pointer"
      onClick={() => !editing && navigate(`/projects/${project.id}`)}
    >
      <div className="flex items-start justify-between gap-2">
        {editing ? (
          <div className="flex flex-1 gap-2" onClick={(e) => e.stopPropagation()}>
            <input
              className="input"
              value={draft}
              autoFocus
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void save()
                if (e.key === "Escape") {
                  setDraft(project.name)
                  setEditing(false)
                }
              }}
            />
            <button className="btn-primary" onClick={() => void save()}>
              Salvar
            </button>
          </div>
        ) : (
          <h3 className="text-lg">{project.name}</h3>
        )}
        <CardMenu
          items={[
            { label: "Editar", onClick: () => setEditing(true) },
            { label: "Excluir", danger: true, onClick: () => setConfirm(true) },
          ]}
        />
      </div>
      <p className="mt-1 text-xs text-muted">
        {new Date(project.created_at).toLocaleString()}
      </p>

      {confirm && (
        <ConfirmDialog
          title="Excluir projeto"
          message={`Excluir "${project.name}" e todos os seus serviços, scans e findings? Esta ação não pode ser desfeita.`}
          onCancel={() => setConfirm(false)}
          onConfirm={async () => {
            await api.deleteProject(project.id)
            setConfirm(false)
            onChanged()
          }}
        />
      )}
    </div>
  )
}

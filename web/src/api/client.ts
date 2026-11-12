import type { Asset, Project, Scan, ScanResult } from "../types"

// Same-origin: Vite dev proxies /api to the Go API; nginx does so in prod.
const BASE = "/api"

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const body = (await res.json()) as { error?: string }
      if (body.error) msg = body.error
    } catch {
      /* ignore */
    }
    throw new Error(msg)
  }
  // 204/empty bodies
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

export const api = {
  listProjects: () => req<Project[]>("/projects"),
  createProject: (name: string) =>
    req<Project>("/projects", { method: "POST", body: JSON.stringify({ name }) }),
  updateProject: (id: string, name: string) =>
    req<Project>(`/projects/${id}`, { method: "PATCH", body: JSON.stringify({ name }) }),
  deleteProject: (id: string) => req<void>(`/projects/${id}`, { method: "DELETE" }),

  listAssets: (projectID: string) => req<Asset[]>(`/projects/${projectID}/assets`),
  createAsset: (projectID: string, name: string, type = "domain") =>
    req<Asset>(`/projects/${projectID}/assets`, {
      method: "POST",
      body: JSON.stringify({ name, type }),
    }),
  updateAsset: (id: string, name: string) =>
    req<Asset>(`/assets/${id}`, { method: "PATCH", body: JSON.stringify({ name }) }),
  deleteAsset: (id: string) => req<void>(`/assets/${id}`, { method: "DELETE" }),

  listScans: (assetID: string) => req<Scan[]>(`/assets/${assetID}/scans`),
  createScan: (assetID: string) =>
    req<Scan>(`/assets/${assetID}/scans`, { method: "POST" }),
  getScan: (scanID: string) => req<ScanResult>(`/scans/${scanID}`),
}

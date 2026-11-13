import type {
  Asset,
  Progress,
  Project,
  Scan,
  ScanDiff,
  ScanResult,
  Triage,
  TriageStatus,
} from "../types"

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
  setAssetBlacklist: (id: string, blacklist: string[]) =>
    req<Asset>(`/assets/${id}`, { method: "PATCH", body: JSON.stringify({ blacklist }) }),
  setTriage: (
    assetID: string,
    body: { fingerprint: string; status: TriageStatus; note?: string },
  ) => req<Triage>(`/assets/${assetID}/triage`, { method: "PUT", body: JSON.stringify(body) }),
  deleteAsset: (id: string) => req<void>(`/assets/${id}`, { method: "DELETE" }),

  listScans: (assetID: string) => req<Scan[]>(`/assets/${assetID}/scans`),
  createScan: (assetID: string, includeInfo = false) =>
    req<Scan>(`/assets/${assetID}/scans`, {
      method: "POST",
      body: JSON.stringify({ include_info: includeInfo }),
    }),
  getScan: (scanID: string) => req<ScanResult>(`/scans/${scanID}`),
  getProgress: (scanID: string) => req<Progress>(`/scans/${scanID}/progress`),
  getScanDiff: (scanID: string) => req<ScanDiff>(`/scans/${scanID}/diff`),
  deleteScan: (scanID: string) => req<void>(`/scans/${scanID}`, { method: "DELETE" }),

  // Download URL for a scan export; the server sets Content-Disposition so the
  // browser saves the file.
  exportScanURL: (scanID: string, format: "json" | "sarif") =>
    `${BASE}/scans/${scanID}/export?format=${format}`,

  // Health/version. /health is at the root (not under /api); best-effort.
  getHealth: async (): Promise<{ version?: string }> => {
    try {
      const res = await fetch("/health")
      return res.ok ? ((await res.json()) as { version?: string }) : {}
    } catch {
      return {}
    }
  },
}

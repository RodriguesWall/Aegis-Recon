// Mirrors the Go model types (internal/model). Only the fields the UI uses.

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type ScanStatus = "PENDING" | "PROCESSING" | "COMPLETED" | "FAILED"

export interface Project {
  id: string
  name: string
  created_at: string
}

export interface Asset {
  id: string
  project_id: string
  type: string
  name: string
  scope: string[]
  created_at: string
}

export interface Scan {
  id: string
  asset_id: string
  type: string
  status: ScanStatus
  created_at: string
  started_at?: string
  completed_at?: string
  error?: string
}

export interface Target {
  domain?: string
  host?: string
  port?: number
}

export interface Finding {
  scanner: string
  target: Target
  severity: Severity
  title: string
  evidence?: Record<string, unknown>
}

export interface ScanResult {
  scan: Scan
  findings: Finding[] | null
}

export interface ScanDiff {
  current_scan_id: string
  previous_scan_id: string // "" when there is no earlier completed scan
  counts: { new: number; resolved: number; unchanged: number }
  new: Finding[] | null
  resolved: Finding[] | null
  unchanged: Finding[] | null
}

export interface Progress {
  phase: string // discovery | probing | done | ""
  done: number
  total: number
  log: string[]
  updated_at?: string
}

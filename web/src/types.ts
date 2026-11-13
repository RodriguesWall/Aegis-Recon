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
  blacklist: string[]
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
  // Highest finding severity in the list view: a severity, "clean", or "" while
  // the scan is still running.
  top_severity?: string
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
  fingerprint: string
}

export type TriageStatus = "open" | "false-positive" | "accepted-risk" | "fixed"

export interface Triage {
  asset_id: string
  fingerprint: string
  status: TriageStatus
  note?: string
  updated_at: string
}

export interface ScanResult {
  scan: Scan
  findings: Finding[] | null
  triage?: Record<string, Triage>
}

export interface Schedule {
  asset_id: string
  interval_minutes: number
  next_run: string
  enabled: boolean
  updated_at?: string
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

// Package model holds the core domain types shared across the engine,
// scanners, store and report layers. No business logic lives here.
package model

import "time"

// Severity is the normalized finding severity. Ordered constants allow
// comparison and aggregation.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank returns a numeric weight for a severity (higher = worse). Unknown
// severities rank 0.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// ScanStatus is the lifecycle state of a scan.
type ScanStatus string

const (
	StatusPending    ScanStatus = "PENDING"
	StatusProcessing ScanStatus = "PROCESSING"
	StatusCompleted  ScanStatus = "COMPLETED"
	StatusFailed     ScanStatus = "FAILED"
)

// AssetType classifies a registered asset. In V1 it is a label only; it does
// not change scan behavior.
type AssetType string

const (
	AssetDomain AssetType = "domain"
	AssetHost   AssetType = "host"
	AssetWebApp AssetType = "web-app"
	AssetAPI    AssetType = "api"
)

// ScanType selects which pipeline runs. V1 only has surface.
type ScanType string

const (
	ScanSurface ScanType = "surface"
)

// Project groups a user's assets. owner_id is nullable in V1 (single-user);
// it exists so multi-tenant in V2 needs no migration.
type Project struct {
	ID        string    `json:"id"`
	OwnerID   *string   `json:"owner_id,omitempty"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Asset is a concrete scan target belonging to a project. Scope is the
// allowlist of hosts/domains that may be scanned.
type Asset struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Type      AssetType `json:"type"`
	Name      string    `json:"name"`
	Scope     []string  `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
}

// Scan is one execution against an asset.
type Scan struct {
	ID      string     `json:"id"`
	AssetID string     `json:"asset_id"`
	Type    ScanType   `json:"type"`
	Status  ScanStatus `json:"status"`
	// IncludeInfo keeps info-severity findings in the result. Default false:
	// scans drop Info (dns/ports/tls inventory noise) unless asked.
	IncludeInfo bool       `json:"include_info"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Target is a single thing a scanner acts on.
type Target struct {
	Domain string `json:"domain,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
}

// Finding is one result emitted by a scanner.
type Finding struct {
	Scanner  string         `json:"scanner"`
	Target   Target         `json:"target"`
	Severity Severity       `json:"severity"`
	Title    string         `json:"title"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// ScanResult aggregates everything produced by one scan run.
type ScanResult struct {
	Domain   string    `json:"domain"`
	Findings []Finding `json:"findings"`
	Meta     ScanMeta  `json:"meta"`
}

// ScanMeta holds run-level bookkeeping.
type ScanMeta struct {
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Duration  time.Duration `json:"duration_ns"`
	Scanners  []string      `json:"scanners"`
	Errors    []string      `json:"errors,omitempty"`
}

// Package store defines the persistence contract and its implementations.
// The interface lets the SQLite backend be swapped (e.g. Postgres) without
// touching callers.
package store

import (
	"context"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Store persists projects, assets, scans and findings. Implementations must be
// safe for concurrent use; the SQLite backend serializes writes internally.
type Store interface {
	// Migrate creates or upgrades the schema. Safe to call repeatedly.
	Migrate(ctx context.Context) error

	CreateProject(ctx context.Context, p *model.Project) error
	GetProject(ctx context.Context, id string) (*model.Project, error)
	ListProjects(ctx context.Context) ([]model.Project, error)
	UpdateProject(ctx context.Context, p *model.Project) error
	// DeleteProject removes the project and everything under it (assets, scans,
	// findings).
	DeleteProject(ctx context.Context, id string) error

	CreateAsset(ctx context.Context, a *model.Asset) error
	GetAsset(ctx context.Context, id string) (*model.Asset, error)
	ListAssets(ctx context.Context, projectID string) ([]model.Asset, error)
	UpdateAsset(ctx context.Context, a *model.Asset) error
	// DeleteAsset removes the asset and its scans and findings.
	DeleteAsset(ctx context.Context, id string) error

	CreateScan(ctx context.Context, s *model.Scan) error
	UpdateScan(ctx context.Context, s *model.Scan) error
	GetScan(ctx context.Context, id string) (*model.Scan, error)
	// DeleteScan removes the scan and its findings.
	DeleteScan(ctx context.Context, id string) error
	ListScans(ctx context.Context, assetID string) ([]model.Scan, error)
	ListPendingScans(ctx context.Context) ([]model.Scan, error)
	ListProcessingScans(ctx context.Context) ([]model.Scan, error)

	SaveFindings(ctx context.Context, scanID string, fs []model.Finding) error
	ListFindings(ctx context.Context, scanID string) ([]model.Finding, error)
	// TopSeverities returns the highest-severity finding per scan for an asset,
	// keyed by scan ID. Scans with no findings are absent from the map.
	TopSeverities(ctx context.Context, assetID string) (map[string]model.Severity, error)

	// SetTriage upserts the operator's verdict for one finding on one asset
	// (keyed by asset_id + fingerprint). StatusOpen deletes the record.
	SetTriage(ctx context.Context, t *model.Triage) error
	// ListTriage returns all triage records for an asset.
	ListTriage(ctx context.Context, assetID string) ([]model.Triage, error)

	// SetSchedule upserts the automatic-scan schedule for an asset.
	SetSchedule(ctx context.Context, sc *model.Schedule) error
	// GetSchedule returns an asset's schedule, or a not-found error if none.
	GetSchedule(ctx context.Context, assetID string) (*model.Schedule, error)
	// ListDueSchedules returns enabled schedules whose NextRun is at or before now.
	ListDueSchedules(ctx context.Context, now time.Time) ([]model.Schedule, error)
	// HasActiveScan reports whether the asset has a PENDING or PROCESSING scan.
	HasActiveScan(ctx context.Context, assetID string) (bool, error)

	Close() error
}

// Package sqlite is the SQLite-backed store. It opens the database in WAL mode
// and serializes all writes through a single mutex, avoiding the classic
// "database is locked" error under the engine's concurrent writers (RISKS #6).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/store"
	_ "modernc.org/sqlite"
)

// compile-time check that *Store satisfies store.Store.
var _ store.Store = (*Store)(nil)

// Store is the SQLite implementation of store.Store.
type Store struct {
	db *sql.DB
	// wmu serializes writes. SQLite allows a single writer; the engine fans
	// out many goroutines, so all mutations take this lock.
	wmu sync.Mutex
}

// Open opens (or creates) the database at dsn with WAL enabled.
// Example dsn: "/data/aegis.db" or ":memory:".
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Pragmas: WAL for concurrent readers alongside one writer; busy_timeout
	// as a safety net; foreign keys on.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS projects (
	id         TEXT PRIMARY KEY,
	owner_id   TEXT,
	name       TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
	id         TEXT PRIMARY KEY,
	project_id TEXT NOT NULL REFERENCES projects(id),
	type       TEXT NOT NULL,
	name       TEXT NOT NULL,
	scope      TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
	id           TEXT PRIMARY KEY,
	asset_id     TEXT NOT NULL REFERENCES assets(id),
	type         TEXT NOT NULL,
	status       TEXT NOT NULL,
	created_at   TIMESTAMP NOT NULL,
	started_at   TIMESTAMP,
	completed_at TIMESTAMP,
	error        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id    TEXT NOT NULL REFERENCES scans(id),
	scanner    TEXT NOT NULL,
	severity   TEXT NOT NULL,
	title      TEXT NOT NULL,
	target     TEXT NOT NULL,
	evidence   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_asset   ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
`

// Migrate creates the schema if absent.
func (s *Store) Migrate(ctx context.Context) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *Store) CreateProject(ctx context.Context, p *model.Project) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (id, owner_id, name, created_at) VALUES (?, ?, ?, ?)`,
		p.ID, p.OwnerID, p.Name, p.CreatedAt)
	return err
}

func (s *Store) GetProject(ctx context.Context, id string) (*model.Project, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, owner_id, name, created_at FROM projects WHERE id = ?`, id)
	var p model.Project
	if err := row.Scan(&p.ID, &p.OwnerID, &p.Name, &p.CreatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProjects(ctx context.Context) ([]model.Project, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner_id, name, created_at FROM projects ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Project
	for rows.Next() {
		var p model.Project
		if err := rows.Scan(&p.ID, &p.OwnerID, &p.Name, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) CreateAsset(ctx context.Context, a *model.Asset) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO assets (id, project_id, type, name, scope, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.ProjectID, a.Type, a.Name, strings.Join(a.Scope, ","), a.CreatedAt)
	return err
}

func (s *Store) GetAsset(ctx context.Context, id string) (*model.Asset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, type, name, scope, created_at FROM assets WHERE id = ?`, id)
	var a model.Asset
	var scope string
	if err := row.Scan(&a.ID, &a.ProjectID, &a.Type, &a.Name, &scope, &a.CreatedAt); err != nil {
		return nil, err
	}
	if scope != "" {
		a.Scope = strings.Split(scope, ",")
	}
	return &a, nil
}

func (s *Store) ListAssets(ctx context.Context, projectID string) ([]model.Asset, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, type, name, scope, created_at FROM assets WHERE project_id = ? ORDER BY created_at DESC`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		var a model.Asset
		var scope string
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Type, &a.Name, &scope, &a.CreatedAt); err != nil {
			return nil, err
		}
		if scope != "" {
			a.Scope = strings.Split(scope, ",")
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) CreateScan(ctx context.Context, sc *model.Scan) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (id, asset_id, type, status, created_at, started_at, completed_at, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.AssetID, sc.Type, sc.Status, sc.CreatedAt, sc.StartedAt, sc.CompletedAt, sc.Error)
	return err
}

func (s *Store) UpdateScan(ctx context.Context, sc *model.Scan) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, started_at = ?, completed_at = ?, error = ? WHERE id = ?`,
		sc.Status, sc.StartedAt, sc.CompletedAt, sc.Error, sc.ID)
	return err
}

func (s *Store) GetScan(ctx context.Context, id string) (*model.Scan, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, asset_id, type, status, created_at, started_at, completed_at, error FROM scans WHERE id = ?`, id)
	var sc model.Scan
	if err := row.Scan(&sc.ID, &sc.AssetID, &sc.Type, &sc.Status, &sc.CreatedAt, &sc.StartedAt, &sc.CompletedAt, &sc.Error); err != nil {
		return nil, err
	}
	return &sc, nil
}

func (s *Store) ListScans(ctx context.Context, assetID string) ([]model.Scan, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, asset_id, type, status, created_at, started_at, completed_at, error
		 FROM scans WHERE asset_id = ? ORDER BY created_at DESC`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *Store) ListPendingScans(ctx context.Context) ([]model.Scan, error) {
	return s.listByStatus(ctx, model.StatusPending)
}

func (s *Store) ListProcessingScans(ctx context.Context) ([]model.Scan, error) {
	return s.listByStatus(ctx, model.StatusProcessing)
}

func (s *Store) listByStatus(ctx context.Context, status model.ScanStatus) ([]model.Scan, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, asset_id, type, status, created_at, started_at, completed_at, error
		 FROM scans WHERE status = ? ORDER BY created_at`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// scanRows decodes a scans result set.
func scanRows(rows *sql.Rows) ([]model.Scan, error) {
	var out []model.Scan
	for rows.Next() {
		var sc model.Scan
		if err := rows.Scan(&sc.ID, &sc.AssetID, &sc.Type, &sc.Status, &sc.CreatedAt, &sc.StartedAt, &sc.CompletedAt, &sc.Error); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Store) SaveFindings(ctx context.Context, scanID string, fs []model.Finding) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO findings (scan_id, scanner, severity, title, target, evidence) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range fs {
		target, _ := json.Marshal(f.Target)
		evidence, _ := json.Marshal(f.Evidence)
		if _, err := stmt.ExecContext(ctx, scanID, f.Scanner, f.Severity, f.Title, string(target), string(evidence)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListFindings(ctx context.Context, scanID string) ([]model.Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT scanner, severity, title, target, evidence FROM findings WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		var f model.Finding
		var target, evidence string
		if err := rows.Scan(&f.Scanner, &f.Severity, &f.Title, &target, &evidence); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(target), &f.Target)
		_ = json.Unmarshal([]byte(evidence), &f.Evidence)
		out = append(out, f)
	}
	return out, rows.Err()
}

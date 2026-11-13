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
	blacklist  TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
	id           TEXT PRIMARY KEY,
	asset_id     TEXT NOT NULL REFERENCES assets(id),
	type         TEXT NOT NULL,
	status       TEXT NOT NULL,
	include_info INTEGER NOT NULL DEFAULT 0,
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
	title       TEXT NOT NULL,
	target      TEXT NOT NULL,
	evidence    TEXT NOT NULL DEFAULT '{}',
	fingerprint TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_asset   ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS triage (
	asset_id    TEXT NOT NULL REFERENCES assets(id),
	fingerprint TEXT NOT NULL,
	status      TEXT NOT NULL,
	note        TEXT NOT NULL DEFAULT '',
	updated_at  TIMESTAMP NOT NULL,
	PRIMARY KEY (asset_id, fingerprint)
);
`

// Migrate creates the schema if absent.
func (s *Store) Migrate(ctx context.Context) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// Best-effort add for databases created before include_info existed. A
	// duplicate-column error is expected and ignored.
	_, _ = s.db.ExecContext(ctx,
		`ALTER TABLE scans ADD COLUMN include_info INTEGER NOT NULL DEFAULT 0`)
	// Same best-effort add for the finding fingerprint (scan diffing + triage).
	// Run before the index so databases predating the column still migrate.
	// Per-asset scan blacklist (Notes #18).
	_, _ = s.db.ExecContext(ctx,
		`ALTER TABLE assets ADD COLUMN blacklist TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.ExecContext(ctx,
		`ALTER TABLE findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint)`)
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
		`INSERT INTO assets (id, project_id, type, name, scope, blacklist, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ProjectID, a.Type, a.Name, strings.Join(a.Scope, ","), strings.Join(a.Blacklist, ","), a.CreatedAt)
	return err
}

func (s *Store) UpdateProject(ctx context.Context, p *model.Project) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`UPDATE projects SET name = ? WHERE id = ?`, p.Name, p.ID)
	return err
}

// DeleteProject removes the project and all its assets, scans and findings in a
// single transaction (children first, respecting foreign keys).
func (s *Store) DeleteProject(ctx context.Context, id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM findings WHERE scan_id IN (
			SELECT s.id FROM scans s JOIN assets a ON s.asset_id = a.id WHERE a.project_id = ?)`, []any{id}},
		{`DELETE FROM scans WHERE asset_id IN (SELECT id FROM assets WHERE project_id = ?)`, []any{id}},
		{`DELETE FROM triage WHERE asset_id IN (SELECT id FROM assets WHERE project_id = ?)`, []any{id}},
		{`DELETE FROM assets WHERE project_id = ?`, []any{id}},
		{`DELETE FROM projects WHERE id = ?`, []any{id}},
	}
	for _, st := range stmts {
		if _, err := tx.ExecContext(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteAsset removes the asset and its scans and findings in one transaction.
func (s *Store) DeleteAsset(ctx context.Context, id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmts := []string{
		`DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE asset_id = ?)`,
		`DELETE FROM scans WHERE asset_id = ?`,
		`DELETE FROM triage WHERE asset_id = ?`,
		`DELETE FROM assets WHERE id = ?`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetAsset(ctx context.Context, id string) (*model.Asset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, type, name, scope, blacklist, created_at FROM assets WHERE id = ?`, id)
	var a model.Asset
	var scope, blacklist string
	if err := row.Scan(&a.ID, &a.ProjectID, &a.Type, &a.Name, &scope, &blacklist, &a.CreatedAt); err != nil {
		return nil, err
	}
	if scope != "" {
		a.Scope = strings.Split(scope, ",")
	}
	if blacklist != "" {
		a.Blacklist = strings.Split(blacklist, ",")
	}
	return &a, nil
}

func (s *Store) UpdateAsset(ctx context.Context, a *model.Asset) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`UPDATE assets SET name = ?, type = ?, scope = ?, blacklist = ? WHERE id = ?`,
		a.Name, a.Type, strings.Join(a.Scope, ","), strings.Join(a.Blacklist, ","), a.ID)
	return err
}

func (s *Store) ListAssets(ctx context.Context, projectID string) ([]model.Asset, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, type, name, scope, blacklist, created_at FROM assets WHERE project_id = ? ORDER BY created_at DESC`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		var a model.Asset
		var scope, blacklist string
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Type, &a.Name, &scope, &blacklist, &a.CreatedAt); err != nil {
			return nil, err
		}
		if scope != "" {
			a.Scope = strings.Split(scope, ",")
		}
		if blacklist != "" {
			a.Blacklist = strings.Split(blacklist, ",")
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) CreateScan(ctx context.Context, sc *model.Scan) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (id, asset_id, type, status, include_info, created_at, started_at, completed_at, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.AssetID, sc.Type, sc.Status, boolToInt(sc.IncludeInfo), sc.CreatedAt, sc.StartedAt, sc.CompletedAt, sc.Error)
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
		`SELECT id, asset_id, type, status, include_info, created_at, started_at, completed_at, error FROM scans WHERE id = ?`, id)
	var sc model.Scan
	var includeInfo int
	if err := row.Scan(&sc.ID, &sc.AssetID, &sc.Type, &sc.Status, &includeInfo, &sc.CreatedAt, &sc.StartedAt, &sc.CompletedAt, &sc.Error); err != nil {
		return nil, err
	}
	sc.IncludeInfo = includeInfo != 0
	return &sc, nil
}

func (s *Store) ListScans(ctx context.Context, assetID string) ([]model.Scan, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, asset_id, type, status, include_info, created_at, started_at, completed_at, error
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
		`SELECT id, asset_id, type, status, include_info, created_at, started_at, completed_at, error
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
		var includeInfo int
		if err := rows.Scan(&sc.ID, &sc.AssetID, &sc.Type, &sc.Status, &includeInfo, &sc.CreatedAt, &sc.StartedAt, &sc.CompletedAt, &sc.Error); err != nil {
			return nil, err
		}
		sc.IncludeInfo = includeInfo != 0
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DeleteScan removes the scan and its findings in one transaction.
func (s *Store) DeleteScan(ctx context.Context, id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE scan_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
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
		`INSERT INTO findings (scan_id, scanner, severity, title, target, evidence, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range fs {
		target, _ := json.Marshal(f.Target)
		evidence, _ := json.Marshal(f.Evidence)
		if _, err := stmt.ExecContext(ctx, scanID, f.Scanner, f.Severity, f.Title, string(target), string(evidence), f.Fingerprint()); err != nil {
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

// TopSeverities returns, for each scan of the asset that has findings, the
// highest severity present. One query: rank severities in SQL and take the max.
func (s *Store) TopSeverities(ctx context.Context, assetID string) (map[string]model.Severity, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT f.scan_id,
		        MAX(CASE f.severity
		            WHEN 'critical' THEN 5
		            WHEN 'high'     THEN 4
		            WHEN 'medium'   THEN 3
		            WHEN 'low'      THEN 2
		            WHEN 'info'     THEN 1
		            ELSE 0 END) AS rank
		 FROM findings f
		 JOIN scans sc ON sc.id = f.scan_id
		 WHERE sc.asset_id = ?
		 GROUP BY f.scan_id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.Severity{}
	for rows.Next() {
		var scanID string
		var rank int
		if err := rows.Scan(&scanID, &rank); err != nil {
			return nil, err
		}
		if sev := severityForRank(rank); sev != "" {
			out[scanID] = sev
		}
	}
	return out, rows.Err()
}

func severityForRank(rank int) model.Severity {
	switch rank {
	case 5:
		return model.SeverityCritical
	case 4:
		return model.SeverityHigh
	case 3:
		return model.SeverityMedium
	case 2:
		return model.SeverityLow
	case 1:
		return model.SeverityInfo
	}
	return ""
}

// SetTriage upserts a verdict. StatusOpen deletes the record (open is the
// absence of triage), so the table only holds active verdicts.
func (s *Store) SetTriage(ctx context.Context, t *model.Triage) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if t.Status == model.TriageOpen {
		_, err := s.db.ExecContext(ctx,
			`DELETE FROM triage WHERE asset_id = ? AND fingerprint = ?`, t.AssetID, t.Fingerprint)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO triage (asset_id, fingerprint, status, note, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(asset_id, fingerprint)
		 DO UPDATE SET status = excluded.status, note = excluded.note, updated_at = excluded.updated_at`,
		t.AssetID, t.Fingerprint, t.Status, t.Note, t.UpdatedAt)
	return err
}

func (s *Store) ListTriage(ctx context.Context, assetID string) ([]model.Triage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT asset_id, fingerprint, status, note, updated_at FROM triage WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Triage
	for rows.Next() {
		var t model.Triage
		if err := rows.Scan(&t.AssetID, &t.Fingerprint, &t.Status, &t.Note, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

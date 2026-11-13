// Package memory is an in-memory store.Store, used by tests and for ephemeral
// runs. Not durable.
package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/store"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("not found")

// Store keeps everything in maps guarded by a mutex.
type Store struct {
	mu       sync.RWMutex
	projects map[string]model.Project
	assets   map[string]model.Asset
	scans    map[string]model.Scan
	findings map[string][]model.Finding
	// triage is keyed by asset_id + "\x00" + fingerprint.
	triage map[string]model.Triage
	// schedules keyed by asset_id.
	schedules map[string]model.Schedule
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		projects: map[string]model.Project{},
		assets:   map[string]model.Asset{},
		scans:    map[string]model.Scan{},
		findings:  map[string][]model.Finding{},
		triage:    map[string]model.Triage{},
		schedules: map[string]model.Schedule{},
	}
}

func triageKey(assetID, fingerprint string) string {
	return assetID + "\x00" + fingerprint
}

func (s *Store) Migrate(context.Context) error { return nil }
func (s *Store) Close() error                  { return nil }

func (s *Store) CreateProject(_ context.Context, p *model.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projects[p.ID] = *p
	return nil
}

func (s *Store) GetProject(_ context.Context, id string) (*model.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &p, nil
}

func (s *Store) ListProjects(context.Context) ([]model.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Project, 0, len(s.projects))
	for _, p := range s.projects {
		out = append(out, p)
	}
	return out, nil
}

func (s *Store) CreateAsset(_ context.Context, a *model.Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[a.ID] = *a
	return nil
}

func (s *Store) UpdateProject(_ context.Context, p *model.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[p.ID]; !ok {
		return ErrNotFound
	}
	s.projects[p.ID] = *p
	return nil
}

func (s *Store) DeleteProject(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for aid, a := range s.assets {
		if a.ProjectID == id {
			s.deleteAssetLocked(aid)
		}
	}
	delete(s.projects, id)
	return nil
}

func (s *Store) DeleteAsset(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteAssetLocked(id)
	return nil
}

// deleteAssetLocked removes an asset plus its scans and findings. Caller holds
// the write lock.
func (s *Store) deleteAssetLocked(id string) {
	for sid, sc := range s.scans {
		if sc.AssetID == id {
			delete(s.findings, sid)
			delete(s.scans, sid)
		}
	}
	for k, t := range s.triage {
		if t.AssetID == id {
			delete(s.triage, k)
		}
	}
	delete(s.schedules, id)
	delete(s.assets, id)
}

func (s *Store) GetAsset(_ context.Context, id string) (*model.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &a, nil
}

func (s *Store) UpdateAsset(_ context.Context, a *model.Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.assets[a.ID]; !ok {
		return ErrNotFound
	}
	s.assets[a.ID] = *a
	return nil
}

func (s *Store) ListAssets(_ context.Context, projectID string) ([]model.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Asset
	for _, a := range s.assets {
		if a.ProjectID == projectID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *Store) CreateScan(_ context.Context, sc *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[sc.ID] = *sc
	return nil
}

func (s *Store) UpdateScan(_ context.Context, sc *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scans[sc.ID]; !ok {
		return ErrNotFound
	}
	s.scans[sc.ID] = *sc
	return nil
}

func (s *Store) GetScan(_ context.Context, id string) (*model.Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scans[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &sc, nil
}

func (s *Store) ListScans(_ context.Context, assetID string) ([]model.Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Scan
	for _, sc := range s.scans {
		if sc.AssetID == assetID {
			out = append(out, sc)
		}
	}
	return out, nil
}

func (s *Store) ListPendingScans(_ context.Context) ([]model.Scan, error) {
	return s.listByStatus(model.StatusPending)
}

func (s *Store) ListProcessingScans(_ context.Context) ([]model.Scan, error) {
	return s.listByStatus(model.StatusProcessing)
}

func (s *Store) listByStatus(status model.ScanStatus) ([]model.Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Scan
	for _, sc := range s.scans {
		if sc.Status == status {
			out = append(out, sc)
		}
	}
	return out, nil
}

func (s *Store) DeleteScan(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.findings, id)
	delete(s.scans, id)
	return nil
}

func (s *Store) SaveFindings(_ context.Context, scanID string, fs []model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings[scanID] = append(s.findings[scanID], fs...)
	return nil
}

func (s *Store) ListFindings(_ context.Context, scanID string) ([]model.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Finding(nil), s.findings[scanID]...), nil
}

func (s *Store) TopSeverities(_ context.Context, assetID string) (map[string]model.Severity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]model.Severity{}
	for sid, sc := range s.scans {
		if sc.AssetID != assetID {
			continue
		}
		best := model.Severity("")
		bestRank := 0
		for _, f := range s.findings[sid] {
			if r := f.Severity.Rank(); r > bestRank {
				bestRank = r
				best = f.Severity
			}
		}
		if best != "" {
			out[sid] = best
		}
	}
	return out, nil
}

func (s *Store) SetTriage(_ context.Context, t *model.Triage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := triageKey(t.AssetID, t.Fingerprint)
	if t.Status == model.TriageOpen {
		delete(s.triage, k)
		return nil
	}
	s.triage[k] = *t
	return nil
}

func (s *Store) ListTriage(_ context.Context, assetID string) ([]model.Triage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Triage
	for _, t := range s.triage {
		if t.AssetID == assetID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *Store) SetSchedule(_ context.Context, sc *model.Schedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schedules[sc.AssetID] = *sc
	return nil
}

func (s *Store) GetSchedule(_ context.Context, assetID string) (*model.Schedule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.schedules[assetID]
	if !ok {
		return nil, ErrNotFound
	}
	return &sc, nil
}

func (s *Store) ListDueSchedules(_ context.Context, now time.Time) ([]model.Schedule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Schedule
	for _, sc := range s.schedules {
		if sc.Enabled && !sc.NextRun.After(now) {
			out = append(out, sc)
		}
	}
	return out, nil
}

func (s *Store) HasActiveScan(_ context.Context, assetID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sc := range s.scans {
		if sc.AssetID == assetID && (sc.Status == model.StatusPending || sc.Status == model.StatusProcessing) {
			return true, nil
		}
	}
	return false, nil
}

// compile-time check.
var _ store.Store = (*Store)(nil)

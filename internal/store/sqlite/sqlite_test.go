package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/store/sqlite"
)

func TestSQLite_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	p := &model.Project{ID: "p1", Name: "Prod X", CreatedAt: time.Now()}
	if err := st.CreateProject(ctx, p); err != nil {
		t.Fatalf("create project: %v", err)
	}
	a := &model.Asset{ID: "a1", ProjectID: "p1", Type: model.AssetDomain, Name: "example.com", Scope: []string{"example.com"}, CreatedAt: time.Now()}
	if err := st.CreateAsset(ctx, a); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	sc := &model.Scan{ID: "s1", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusPending, CreatedAt: time.Now()}
	if err := st.CreateScan(ctx, sc); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	fs := []model.Finding{
		{Scanner: "noop", Target: model.Target{Domain: "example.com"}, Severity: model.SeverityInfo, Title: "hi", Evidence: map[string]any{"k": "v"}},
	}
	if err := st.SaveFindings(ctx, "s1", fs); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	got, err := st.ListFindings(ctx, "s1")
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(got) != 1 || got[0].Title != "hi" || got[0].Target.Domain != "example.com" {
		t.Fatalf("unexpected findings: %+v", got)
	}

	assets, err := st.ListAssets(ctx, "p1")
	if err != nil || len(assets) != 1 || assets[0].Scope[0] != "example.com" {
		t.Fatalf("list assets: %v / %+v", err, assets)
	}
}

func TestSQLite_DeleteProjectCascade(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	_ = st.CreateProject(ctx, &model.Project{ID: "pr", Name: "x", CreatedAt: time.Now()})
	_ = st.CreateAsset(ctx, &model.Asset{ID: "a", ProjectID: "pr", Type: model.AssetDomain, Name: "x.com", CreatedAt: time.Now()})
	_ = st.CreateScan(ctx, &model.Scan{ID: "s", AssetID: "a", Type: model.ScanSurface, Status: model.StatusCompleted, CreatedAt: time.Now()})
	_ = st.SaveFindings(ctx, "s", []model.Finding{{Scanner: "dns", Severity: model.SeverityInfo, Title: "t"}})

	if err := st.DeleteProject(ctx, "pr"); err != nil {
		t.Fatalf("delete project: %v", err)
	}

	if ps, _ := st.ListProjects(ctx); len(ps) != 0 {
		t.Errorf("projects not deleted: %+v", ps)
	}
	if as, _ := st.ListAssets(ctx, "pr"); len(as) != 0 {
		t.Errorf("assets not deleted: %+v", as)
	}
	if fs, _ := st.ListFindings(ctx, "s"); len(fs) != 0 {
		t.Errorf("findings not deleted: %+v", fs)
	}
	if _, err := st.GetScan(ctx, "s"); err == nil {
		t.Errorf("scan not deleted")
	}
}

func TestSQLite_ListByStatus(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// satisfy foreign keys: project -> asset -> scans
	if err := st.CreateProject(ctx, &model.Project{ID: "pr", Name: "x", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := st.CreateAsset(ctx, &model.Asset{ID: "a", ProjectID: "pr", Type: model.AssetDomain, Name: "x.com", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("asset: %v", err)
	}

	// one PENDING, one PROCESSING
	if err := st.CreateScan(ctx, &model.Scan{ID: "p", AssetID: "a", Type: model.ScanSurface, Status: model.StatusPending, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("scan p: %v", err)
	}
	if err := st.CreateScan(ctx, &model.Scan{ID: "r", AssetID: "a", Type: model.ScanSurface, Status: model.StatusProcessing, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("scan r: %v", err)
	}

	pending, err := st.ListPendingScans(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID != "p" {
		t.Fatalf("pending = %+v err=%v", pending, err)
	}
	processing, err := st.ListProcessingScans(ctx)
	if err != nil || len(processing) != 1 || processing[0].ID != "r" {
		t.Fatalf("processing = %+v err=%v", processing, err)
	}
}

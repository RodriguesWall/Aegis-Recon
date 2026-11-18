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

func TestSQLite_Triage(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "P", CreatedAt: time.Now()})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Type: model.AssetDomain, Name: "example.com", CreatedAt: time.Now()})

	// Upsert a verdict.
	if err := st.SetTriage(ctx, &model.Triage{AssetID: "a1", Fingerprint: "fp1", Status: model.TriageFalsePositive, Note: "benign", UpdatedAt: time.Now()}); err != nil {
		t.Fatalf("set triage: %v", err)
	}
	got, err := st.ListTriage(ctx, "a1")
	if err != nil || len(got) != 1 || got[0].Status != model.TriageFalsePositive || got[0].Note != "benign" {
		t.Fatalf("list triage: %v / %+v", err, got)
	}

	// Update in place (same key) must not create a second row.
	if err := st.SetTriage(ctx, &model.Triage{AssetID: "a1", Fingerprint: "fp1", Status: model.TriageAcceptedRisk, UpdatedAt: time.Now()}); err != nil {
		t.Fatalf("update triage: %v", err)
	}
	got, _ = st.ListTriage(ctx, "a1")
	if len(got) != 1 || got[0].Status != model.TriageAcceptedRisk {
		t.Fatalf("expected 1 updated row, got %+v", got)
	}

	// StatusOpen deletes the record.
	if err := st.SetTriage(ctx, &model.Triage{AssetID: "a1", Fingerprint: "fp1", Status: model.TriageOpen, UpdatedAt: time.Now()}); err != nil {
		t.Fatalf("clear triage: %v", err)
	}
	got, _ = st.ListTriage(ctx, "a1")
	if len(got) != 0 {
		t.Fatalf("expected triage cleared, got %+v", got)
	}

	// Cascade: deleting the asset removes its triage.
	st.SetTriage(ctx, &model.Triage{AssetID: "a1", Fingerprint: "fp2", Status: model.TriageFixed, UpdatedAt: time.Now()})
	if err := st.DeleteAsset(ctx, "a1"); err != nil {
		t.Fatalf("delete asset: %v", err)
	}
	got, _ = st.ListTriage(ctx, "a1")
	if len(got) != 0 {
		t.Fatalf("expected triage gone after asset delete, got %+v", got)
	}
}

func TestSQLite_StatsAggregation(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now()
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "P", CreatedAt: now})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Type: model.AssetDomain, Name: "example.com", CreatedAt: now})
	end := now.Add(10 * time.Second)
	st.CreateScan(ctx, &model.Scan{ID: "s1", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusCompleted, CreatedAt: now, CompletedAt: &end})
	st.SaveFindings(ctx, "s1", []model.Finding{
		{Scanner: "port", Target: model.Target{Host: "example.com", Port: 3306}, Severity: model.SeverityHigh, Title: "mysql"},
		{Scanner: "tls", Target: model.Target{Host: "example.com", Port: 443}, Severity: model.SeverityMedium, Title: "weak"},
	})

	// SeverityTrend must not error (regression: COALESCE broke time scanning).
	trend, err := st.SeverityTrend(ctx, 30)
	if err != nil {
		t.Fatalf("SeverityTrend: %v", err)
	}
	if len(trend) != 1 || trend[0].High != 1 || trend[0].Medium != 1 {
		t.Fatalf("trend wrong: %+v", trend)
	}
	if trend[0].CompletedAt.IsZero() {
		t.Fatalf("trend completed_at not populated")
	}

	cur, err := st.CurrentFindings(ctx)
	if err != nil {
		t.Fatalf("CurrentFindings: %v", err)
	}
	if len(cur) != 2 || cur[0].ProjectID != "p1" {
		t.Fatalf("current findings wrong: %+v", cur)
	}
}

func TestSQLite_PruneScans(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "P", CreatedAt: time.Now()})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Type: model.AssetDomain, Name: "x", CreatedAt: time.Now()})
	base := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		id := string(rune('a' + i))
		st.CreateScan(ctx, &model.Scan{ID: id, AssetID: "a1", Type: model.ScanSurface, Status: model.StatusCompleted, CreatedAt: base.Add(time.Duration(i) * time.Minute)})
		st.SaveFindings(ctx, id, []model.Finding{{Scanner: "port", Target: model.Target{Host: "x", Port: 1}, Severity: model.SeverityLow, Title: "f" + id}})
	}

	n, err := st.PruneScans(ctx, "a1", 3)
	if err != nil || n != 2 {
		t.Fatalf("prune = %d, %v; want 2, nil", n, err)
	}
	scans, _ := st.ListScans(ctx, "a1")
	if len(scans) != 3 {
		t.Fatalf("expected 3 scans kept, got %d", len(scans))
	}
	// Oldest two ("a","b") gone; newest kept ("e","d","c").
	for _, sc := range scans {
		if sc.ID == "a" || sc.ID == "b" {
			t.Fatalf("old scan %q should be pruned", sc.ID)
		}
	}
	// Findings of a pruned scan are gone.
	if fs, _ := st.ListFindings(ctx, "a"); len(fs) != 0 {
		t.Fatalf("pruned scan findings remain: %v", fs)
	}
	// keep <= 0 is a no-op.
	if n, _ := st.PruneScans(ctx, "a1", 0); n != 0 {
		t.Fatalf("keep=0 must prune nothing, got %d", n)
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

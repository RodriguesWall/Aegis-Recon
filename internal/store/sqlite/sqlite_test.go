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

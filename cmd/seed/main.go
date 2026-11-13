// Command seed populates the store with realistic demo data (fake domains) for
// screenshots and local demos. It never touches the network. Point it at the
// same database aegisd uses (AEGIS_DB) on a fresh DB, then start the app.
//
//	AEGIS_DB=db/aegis.db go run ./cmd/seed
//
// Data: one project, two assets with fake domains, two completed scans per main
// asset (so the report shows "Changes since last scan"), a mix of severities,
// a couple of triage verdicts and an enabled schedule.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/store/sqlite"
	"github.com/google/uuid"
)

func main() {
	dbPath := envOr("AEGIS_DB", filepath.Join("db", "aegis.db"))
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	ctx := context.Background()
	st, err := sqlite.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	now := time.Now().UTC()

	// Project.
	proj := &model.Project{ID: uuid.NewString(), Name: "Acme Corp", CreatedAt: now}
	must(st.CreateProject(ctx, proj))

	// Main asset: acme.example.
	web := &model.Asset{
		ID: uuid.NewString(), ProjectID: proj.ID, Type: model.AssetDomain,
		Name: "acme.example", Scope: []string{"acme.example"}, CreatedAt: now,
	}
	must(st.CreateAsset(ctx, web))

	// Second asset: shop.acme.example (single clean scan for contrast).
	shop := &model.Asset{
		ID: uuid.NewString(), ProjectID: proj.ID, Type: model.AssetDomain,
		Name: "shop.acme.example", Scope: []string{"shop.acme.example"}, CreatedAt: now,
	}
	must(st.CreateAsset(ctx, shop))

	// --- acme.example: older scan (baseline) ---
	old := completedScan(web.ID, now.Add(-26*time.Hour))
	must(st.CreateScan(ctx, old))
	must(st.SaveFindings(ctx, old.ID, []model.Finding{
		fPort("acme.example", 3306, model.SeverityHigh, "sensitive service exposed: 3306/tcp (mysql)"),
		fHTTP("acme.example", model.SeverityMedium, "missing security headers (CSP, HSTS)"),
		fTLS("www.acme.example", model.SeverityMedium, "TLS certificate expires in 18 days"),
		fPort("acme.example", 21, model.SeverityLow, "open port 21/tcp (ftp)"), // gets resolved later
		fFinger("www.acme.example", model.SeverityLow, "verbose server banner (nginx/1.21.0)"),
	}))

	// --- acme.example: latest scan (the one to screenshot) ---
	latest := completedScan(web.ID, now.Add(-2*time.Hour))
	must(st.CreateScan(ctx, latest))
	latestFindings := []model.Finding{
		fHTTP("acme.example", model.SeverityCritical, "exposed admin panel (/admin, no auth)"), // NEW
		fPort("acme.example", 3306, model.SeverityHigh, "sensitive service exposed: 3306/tcp (mysql)"),
		fPort("api.acme.example", 6379, model.SeverityHigh, "sensitive service exposed: 6379/tcp (redis)"), // NEW
		fHTTP("acme.example", model.SeverityMedium, "missing security headers (CSP, HSTS)"),
		fTLS("www.acme.example", model.SeverityMedium, "TLS certificate expires in 18 days"),
		fTLS("api.acme.example", model.SeverityMedium, "weak TLS ciphers (TLS 1.0 enabled)"), // NEW
		fHTTP("acme.example", model.SeverityLow, "directory listing enabled (/assets)"),      // NEW
		fFinger("www.acme.example", model.SeverityLow, "verbose server banner (nginx/1.21.0)"),
	}
	must(st.SaveFindings(ctx, latest.ID, latestFindings))

	// Triage on the latest scan: one false-positive, one fixed. Keyed by
	// asset + fingerprint, so these stick across re-scans.
	fp := func(f model.Finding) string { return f.Fingerprint() }
	must(st.SetTriage(ctx, &model.Triage{
		AssetID: web.ID, Fingerprint: fp(latestFindings[7]), // verbose banner
		Status: model.TriageFalsePositive, Note: "intentional; low value", UpdatedAt: now,
	}))
	must(st.SetTriage(ctx, &model.Triage{
		AssetID: web.ID, Fingerprint: fp(latestFindings[6]), // directory listing
		Status: model.TriageFixed, Note: "autoindex off deployed", UpdatedAt: now,
	}))

	// Schedule: daily automatic scans on the main asset.
	must(st.SetSchedule(ctx, &model.Schedule{
		AssetID: web.ID, IntervalMinutes: 24 * 60, Enabled: true,
		NextRun: now.Add(22 * time.Hour), UpdatedAt: now,
	}))

	// --- shop.acme.example: a single clean scan ---
	clean := completedScan(shop.ID, now.Add(-3*time.Hour))
	must(st.CreateScan(ctx, clean))
	// No findings -> shows the "Clean" tag.

	// --- Second project: Globex Industries (two assets, mixed severities) ---
	glx := &model.Project{ID: uuid.NewString(), Name: "Globex Industries", CreatedAt: now.Add(-time.Hour)}
	must(st.CreateProject(ctx, glx))
	gWeb := seedAsset(ctx, st, glx.ID, "globex.example", now)
	seedScan(ctx, st, gWeb.ID, now.Add(-5*time.Hour), []model.Finding{
		fPort("globex.example", 5432, model.SeverityHigh, "sensitive service exposed: 5432/tcp (postgres)"),
		fHTTP("globex.example", model.SeverityMedium, "missing security headers (CSP, HSTS)"),
		fFinger("globex.example", model.SeverityLow, "verbose server banner (Apache/2.4.41)"),
	})
	gMail := seedAsset(ctx, st, glx.ID, "mail.globex.example", now)
	seedScan(ctx, st, gMail.ID, now.Add(-6*time.Hour), []model.Finding{
		fTLS("mail.globex.example", model.SeverityMedium, "TLS certificate expires in 40 days"),
		fPort("mail.globex.example", 25, model.SeverityLow, "open port 25/tcp (smtp)"),
	})

	// --- Third project: Initech (one clean asset) ---
	ini := &model.Project{ID: uuid.NewString(), Name: "Initech", CreatedAt: now.Add(-2 * time.Hour)}
	must(st.CreateProject(ctx, ini))
	iWeb := seedAsset(ctx, st, ini.ID, "initech.example", now)
	seedScan(ctx, st, iWeb.ID, now.Add(-4*time.Hour), nil) // clean

	fmt.Printf("seeded %q\n  projects: %s, %s, %s\n  acme.example has diff + triage + schedule; shop/initech clean\n",
		dbPath, proj.Name, glx.Name, ini.Name)
}

// seedAsset creates an asset scoped to its own domain.
func seedAsset(ctx context.Context, st *sqlite.Store, projectID, domain string, now time.Time) *model.Asset {
	a := &model.Asset{
		ID: uuid.NewString(), ProjectID: projectID, Type: model.AssetDomain,
		Name: domain, Scope: []string{domain}, CreatedAt: now,
	}
	must(st.CreateAsset(ctx, a))
	return a
}

// seedScan creates a completed scan with the given findings (nil = clean).
func seedScan(ctx context.Context, st *sqlite.Store, assetID string, at time.Time, findings []model.Finding) {
	sc := completedScan(assetID, at)
	must(st.CreateScan(ctx, sc))
	if len(findings) > 0 {
		must(st.SaveFindings(ctx, sc.ID, findings))
	}
}

func completedScan(assetID string, at time.Time) *model.Scan {
	end := at.Add(14 * time.Second)
	return &model.Scan{
		ID: uuid.NewString(), AssetID: assetID, Type: model.ScanSurface,
		Status: model.StatusCompleted, CreatedAt: at, StartedAt: &at, CompletedAt: &end,
	}
}

func fPort(host string, port int, sev model.Severity, title string) model.Finding {
	return model.Finding{Scanner: "port", Target: model.Target{Host: host, Port: port}, Severity: sev, Title: title,
		Evidence: map[string]any{"port": port, "state": "open"}}
}

func fHTTP(host string, sev model.Severity, title string) model.Finding {
	return model.Finding{Scanner: "httpprobe", Target: model.Target{Host: host, Port: 443}, Severity: sev, Title: title,
		Evidence: map[string]any{"status": 200}}
}

func fTLS(host string, sev model.Severity, title string) model.Finding {
	return model.Finding{Scanner: "tls", Target: model.Target{Host: host, Port: 443}, Severity: sev, Title: title,
		Evidence: map[string]any{"protocol": "TLS 1.2"}}
}

func fFinger(host string, sev model.Severity, title string) model.Finding {
	return model.Finding{Scanner: "fingerprint", Target: model.Target{Host: host, Port: 443}, Severity: sev, Title: title,
		Evidence: map[string]any{"server": "nginx"}}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/api"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/progress"
	"github.com/RodriguesWall/aegis-recon/internal/queue"
	"github.com/RodriguesWall/aegis-recon/internal/secret"
	"github.com/RodriguesWall/aegis-recon/internal/store/memory"
)

// newServer wires the API over an in-memory store and a queue with a no-op
// handler, so no real scanning happens during the test.
func newServer() http.Handler {
	st := memory.New()
	q := queue.New(func(context.Context, string) error { return nil })
	return api.New(st, q, progress.New()).Routes()
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func idOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatalf("no id in %s", w.Body.String())
	}
	return id
}

func TestFullFlow(t *testing.T) {
	h := newServer()

	// create project
	w := do(t, h, "POST", "/api/projects", `{"name":"Prod X"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", w.Code, w.Body)
	}
	pid := idOf(t, w)

	// create asset
	w = do(t, h, "POST", "/api/projects/"+pid+"/assets", `{"name":"example.com"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create asset: %d %s", w.Code, w.Body)
	}
	aid := idOf(t, w)

	// trigger scan -> 202 PENDING
	w = do(t, h, "POST", "/api/assets/"+aid+"/scans", "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("create scan: %d %s", w.Code, w.Body)
	}
	sid := idOf(t, w)

	// get scan
	w = do(t, h, "GET", "/api/scans/"+sid, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get scan: %d %s", w.Code, w.Body)
	}
	var got struct {
		Scan struct {
			Status string `json:"status"`
		} `json:"scan"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Scan.Status != "PENDING" {
		t.Errorf("status = %q, want PENDING", got.Scan.Status)
	}
}

func TestUpdateProjectAndAsset(t *testing.T) {
	h := newServer()

	pid := idOf(t, do(t, h, "POST", "/api/projects", `{"name":"old"}`))
	aid := idOf(t, do(t, h, "POST", "/api/projects/"+pid+"/assets", `{"name":"a.com"}`))

	// rename project
	w := do(t, h, "PATCH", "/api/projects/"+pid, `{"name":"new name"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("patch project: %d %s", w.Code, w.Body)
	}
	// rename asset
	w = do(t, h, "PATCH", "/api/assets/"+aid, `{"name":"b.com"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("patch asset: %d %s", w.Code, w.Body)
	}

	// verify project name persisted
	w = do(t, h, "GET", "/api/projects", "")
	var ps []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ps)
	if len(ps) != 1 || ps[0]["name"] != "new name" {
		t.Fatalf("project not renamed: %s", w.Body)
	}

	// verify asset name persisted
	w = do(t, h, "GET", "/api/projects/"+pid+"/assets", "")
	var as []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &as)
	if len(as) != 1 || as[0]["name"] != "b.com" {
		t.Fatalf("asset not renamed: %s", w.Body)
	}
}

func TestDeleteProjectAndAsset(t *testing.T) {
	h := newServer()
	pid := idOf(t, do(t, h, "POST", "/api/projects", `{"name":"p"}`))
	aid := idOf(t, do(t, h, "POST", "/api/projects/"+pid+"/assets", `{"name":"a.com"}`))

	// delete asset -> 204, list empty
	if w := do(t, h, "DELETE", "/api/assets/"+aid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete asset: %d", w.Code)
	}
	w := do(t, h, "GET", "/api/projects/"+pid+"/assets", "")
	var as []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &as)
	if len(as) != 0 {
		t.Fatalf("asset not deleted: %s", w.Body)
	}

	// delete project -> 204, list empty
	if w := do(t, h, "DELETE", "/api/projects/"+pid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete project: %d", w.Code)
	}
	w = do(t, h, "GET", "/api/projects", "")
	var ps []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ps)
	if len(ps) != 0 {
		t.Fatalf("project not deleted: %s", w.Body)
	}
}

func TestDeleteScan(t *testing.T) {
	h := newServer()
	pid := idOf(t, do(t, h, "POST", "/api/projects", `{"name":"p"}`))
	aid := idOf(t, do(t, h, "POST", "/api/projects/"+pid+"/assets", `{"name":"a.com"}`))
	sid := idOf(t, do(t, h, "POST", "/api/assets/"+aid+"/scans", ""))

	if w := do(t, h, "DELETE", "/api/scans/"+sid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete scan: %d", w.Code)
	}
	if w := do(t, h, "GET", "/api/scans/"+sid, ""); w.Code != http.StatusNotFound {
		t.Fatalf("scan still present: %d", w.Code)
	}
}

func TestDeleteMissing(t *testing.T) {
	h := newServer()
	if w := do(t, h, "DELETE", "/api/projects/nope", ""); w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestUpdateMissingProject(t *testing.T) {
	h := newServer()
	w := do(t, h, "PATCH", "/api/projects/nope", `{"name":"x"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestExportScan(t *testing.T) {
	st := memory.New()
	q := queue.New(func(context.Context, string) error { return nil })
	h := api.New(st, q, progress.New()).Routes()
	ctx := context.Background()

	// Seed a completed scan with findings directly in the store.
	_ = st.CreateProject(ctx, &model.Project{ID: "p1", Name: "p"})
	_ = st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Name: "example.com", Type: model.AssetDomain})
	_ = st.CreateScan(ctx, &model.Scan{ID: "s1", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusCompleted})
	_ = st.SaveFindings(ctx, "s1", []model.Finding{
		{Scanner: "port", Target: model.Target{Host: "example.com", Port: 22}, Severity: model.SeverityCritical, Title: "open port: 22/tcp"},
	})

	// SARIF export.
	w := do(t, h, "GET", "/api/scans/s1/export?format=sarif", "")
	if w.Code != http.StatusOK {
		t.Fatalf("sarif export: %d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/sarif+json" {
		t.Errorf("sarif content-type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "scan-s1.sarif") {
		t.Errorf("sarif disposition = %q", cd)
	}
	if !strings.Contains(w.Body.String(), `"version": "2.1.0"`) {
		t.Errorf("sarif body missing version:\n%s", w.Body)
	}

	// JSON export (default).
	w = do(t, h, "GET", "/api/scans/s1/export", "")
	if w.Code != http.StatusOK {
		t.Fatalf("json export: %d %s", w.Code, w.Body)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "scan-s1.json") {
		t.Errorf("json disposition = %q", cd)
	}

	// Unknown format -> 400.
	if w := do(t, h, "GET", "/api/scans/s1/export?format=xml", ""); w.Code != http.StatusBadRequest {
		t.Errorf("unknown format: want 400, got %d", w.Code)
	}

	// Missing scan -> 404.
	if w := do(t, h, "GET", "/api/scans/nope/export?format=sarif", ""); w.Code != http.StatusNotFound {
		t.Errorf("missing scan: want 404, got %d", w.Code)
	}
}

func TestStats(t *testing.T) {
	st := memory.New()
	q := queue.New(func(context.Context, string) error { return nil })
	h := api.New(st, q, progress.New()).Routes()
	ctx := context.Background()

	_ = st.CreateProject(ctx, &model.Project{ID: "p1", Name: "Acme"})
	_ = st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Name: "acme.example", Type: model.AssetDomain})
	// Older completed scan — must be ignored (only the latest per asset counts).
	_ = st.CreateScan(ctx, &model.Scan{ID: "old", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusCompleted, CreatedAt: time.Unix(100, 0)})
	_ = st.SaveFindings(ctx, "old", []model.Finding{
		{Scanner: "port", Target: model.Target{Host: "acme.example", Port: 21}, Severity: model.SeverityHigh, Title: "old"},
	})
	// Latest completed scan — the snapshot.
	_ = st.CreateScan(ctx, &model.Scan{ID: "s1", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusCompleted, CreatedAt: time.Unix(200, 0)})
	fs := []model.Finding{
		{Scanner: "httpprobe", Target: model.Target{Host: "acme.example", Port: 443}, Severity: model.SeverityCritical, Title: "admin exposed"},
		{Scanner: "port", Target: model.Target{Host: "acme.example", Port: 3306}, Severity: model.SeverityHigh, Title: "mysql"},
		{Scanner: "tls", Target: model.Target{Host: "acme.example", Port: 443}, Severity: model.SeverityMedium, Title: "weak tls"},
	}
	_ = st.SaveFindings(ctx, "s1", fs)
	// Mark the mysql finding false-positive.
	_ = st.SetTriage(ctx, &model.Triage{AssetID: "a1", Fingerprint: fs[1].Fingerprint(), Status: model.TriageFalsePositive})

	w := do(t, h, "GET", "/api/stats", "")
	if w.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", w.Code, w.Body)
	}
	var got struct {
		Totals   map[string]int `json:"totals"`
		Severity sevStub        `json:"severity"`
		Triage struct {
			Open          int `json:"open"`
			FalsePositive int `json:"false_positive"`
		} `json:"triage"`
		BreakdownBy string `json:"breakdown_by"`
		Breakdown   []struct {
			Name  string `json:"name"`
			Total int    `json:"total"`
		} `json:"breakdown"`
		Trend []struct {
			ScanID string `json:"scan_id"`
		} `json:"trend"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body)
	}
	// Snapshot = latest scan only: 3 findings (not the old one).
	if got.Totals["findings"] != 3 || got.Totals["projects"] != 1 || got.Totals["assets"] != 1 {
		t.Fatalf("totals wrong: %+v", got.Totals)
	}
	if got.Severity.Critical != 1 || got.Severity.High != 1 || got.Severity.Medium != 1 {
		t.Fatalf("severity wrong: %+v", got.Severity)
	}
	if got.Triage.FalsePositive != 1 || got.Triage.Open != 2 {
		t.Fatalf("triage wrong: %+v", got.Triage)
	}
	if got.BreakdownBy != "project" || len(got.Breakdown) != 1 || got.Breakdown[0].Total != 3 {
		t.Fatalf("breakdown wrong: by=%q %+v", got.BreakdownBy, got.Breakdown)
	}
	// Trend has both completed scans, oldest first.
	if len(got.Trend) != 2 || got.Trend[0].ScanID != "old" || got.Trend[1].ScanID != "s1" {
		t.Fatalf("trend wrong: %+v", got.Trend)
	}
}

type sevStub struct {
	Critical, High, Medium, Low, Info, Total int
}

func TestFindingsList(t *testing.T) {
	st := memory.New()
	q := queue.New(func(context.Context, string) error { return nil })
	h := api.New(st, q, progress.New()).Routes()
	ctx := context.Background()
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "Acme"})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Name: "acme.example", Type: model.AssetDomain})
	st.CreateScan(ctx, &model.Scan{ID: "s1", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusCompleted, CreatedAt: time.Unix(10, 0)})
	fs := []model.Finding{
		{Scanner: "httpprobe", Target: model.Target{Host: "acme.example", Port: 443}, Severity: model.SeverityCritical, Title: "admin exposed"},
		{Scanner: "port", Target: model.Target{Host: "acme.example", Port: 3306}, Severity: model.SeverityHigh, Title: "mysql open"},
	}
	st.SaveFindings(ctx, "s1", fs)
	st.SetTriage(ctx, &model.Triage{AssetID: "a1", Fingerprint: fs[1].Fingerprint(), Status: model.TriageFalsePositive})

	decode := func(body []byte) []map[string]any {
		var v []map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatalf("decode: %v\n%s", err, body)
		}
		return v
	}

	// All: 2 findings, enriched + status.
	all := decode(do(t, h, "GET", "/api/findings", "").Body.Bytes())
	if len(all) != 2 {
		t.Fatalf("want 2 findings, got %d", len(all))
	}
	if all[0]["severity"] != "critical" || all[0]["project_name"] != "Acme" || all[0]["asset_name"] != "acme.example" {
		t.Fatalf("enrichment/order wrong: %+v", all[0])
	}

	// Filter by severity.
	if got := decode(do(t, h, "GET", "/api/findings?severity=high", "").Body.Bytes()); len(got) != 1 || got[0]["title"] != "mysql open" {
		t.Fatalf("severity filter wrong: %+v", got)
	}
	// Filter by status (false-positive -> the mysql finding).
	if got := decode(do(t, h, "GET", "/api/findings?status=false-positive", "").Body.Bytes()); len(got) != 1 || got[0]["scanner"] != "port" {
		t.Fatalf("status filter wrong: %+v", got)
	}
	// Text search on title.
	if got := decode(do(t, h, "GET", "/api/findings?q=admin", "").Body.Bytes()); len(got) != 1 || got[0]["title"] != "admin exposed" {
		t.Fatalf("q filter wrong: %+v", got)
	}
}

func TestSettings(t *testing.T) {
	st := memory.New()
	q := queue.New(func(context.Context, string) error { return nil })
	h := api.New(st, q, progress.New()).Routes()

	// PUT a visible setting and a secret.
	w := do(t, h, "PUT", "/api/settings", `{"smtp_host":"mail.example.com","smtp_pass":"hunter2"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("put settings: %d %s", w.Code, w.Body)
	}

	// GET must expose smtp_host but never the password; secrets_set reports it.
	w = do(t, h, "GET", "/api/settings", "")
	var got struct {
		Settings   map[string]string `json:"settings"`
		SecretsSet map[string]bool   `json:"secrets_set"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body)
	}
	if got.Settings["smtp_host"] != "mail.example.com" {
		t.Fatalf("smtp_host wrong: %+v", got.Settings)
	}
	if _, leaked := got.Settings["smtp_pass"]; leaked {
		t.Fatal("smtp_pass must not be returned in plaintext")
	}
	if !got.SecretsSet["smtp_pass"] {
		t.Fatalf("secrets_set should report smtp_pass set: %+v", got.SecretsSet)
	}

	// The stored value must be encrypted, and decrypt back to the original.
	raw, _, _ := st.GetSetting(context.Background(), "smtp_pass")
	if raw == "hunter2" {
		t.Fatal("password stored in plaintext")
	}
	if dec, err := secret.Decrypt(raw); err != nil || dec != "hunter2" {
		t.Fatalf("stored secret did not decrypt: dec=%q err=%v", dec, err)
	}

	// Empty secret on PUT keeps the existing one.
	do(t, h, "PUT", "/api/settings", `{"smtp_pass":""}`)
	raw2, _, _ := st.GetSetting(context.Background(), "smtp_pass")
	if raw2 != raw {
		t.Fatal("empty secret value should not overwrite the stored password")
	}
}

func TestScanOnMissingAsset(t *testing.T) {
	h := newServer()
	w := do(t, h, "POST", "/api/assets/nope/scans", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestCreateProjectValidation(t *testing.T) {
	h := newServer()
	w := do(t, h, "POST", "/api/projects", `{"name":""}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

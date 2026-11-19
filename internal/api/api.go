// Package api exposes the HTTP API for projects, assets and scans. It is a thin
// layer over the store and the queue: handlers validate input, persist, and (for
// scans) enqueue background work. Routing uses the stdlib ServeMux method+path
// patterns (Go 1.22+), so no router dependency.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/auth"
	"github.com/RodriguesWall/aegis-recon/internal/diff"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/progress"
	"github.com/RodriguesWall/aegis-recon/internal/queue"
	"github.com/RodriguesWall/aegis-recon/internal/report"
	"github.com/RodriguesWall/aegis-recon/internal/secret"
	"github.com/RodriguesWall/aegis-recon/internal/store"
	"github.com/RodriguesWall/aegis-recon/internal/version"
	"github.com/google/uuid"
)

// Server wires the store, queue and progress tracker into HTTP handlers.
type Server struct {
	store    store.Store
	queue    *queue.Queue
	progress *progress.Tracker
}

// New builds the API server.
func New(st store.Store, q *queue.Queue, tracker *progress.Tracker) *Server {
	return &Server{store: st, queue: q, progress: tracker}
}

// Routes returns the HTTP handler with all routes and CORS applied.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /api/auth", s.authStatus)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/findings", s.findings)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("POST /api/projects", s.createProject)
	mux.HandleFunc("GET /api/projects", s.listProjects)
	mux.HandleFunc("PATCH /api/projects/{id}", s.updateProject)
	mux.HandleFunc("DELETE /api/projects/{id}", s.deleteProject)
	mux.HandleFunc("POST /api/projects/{id}/assets", s.createAsset)
	mux.HandleFunc("GET /api/projects/{id}/assets", s.listAssets)
	mux.HandleFunc("PATCH /api/assets/{id}", s.updateAsset)
	mux.HandleFunc("DELETE /api/assets/{id}", s.deleteAsset)
	mux.HandleFunc("POST /api/assets/{id}/scans", s.createScan)
	mux.HandleFunc("GET /api/assets/{id}/scans", s.listScans)
	mux.HandleFunc("GET /api/scans/{id}", s.getScan)
	mux.HandleFunc("GET /api/scans/{id}/progress", s.getProgress)
	mux.HandleFunc("GET /api/scans/{id}/export", s.exportScan)
	mux.HandleFunc("GET /api/scans/{id}/diff", s.diffScan)
	mux.HandleFunc("PUT /api/assets/{id}/triage", s.setTriage)
	mux.HandleFunc("GET /api/assets/{id}/schedule", s.getSchedule)
	mux.HandleFunc("PUT /api/assets/{id}/schedule", s.setSchedule)
	mux.HandleFunc("DELETE /api/scans/{id}", s.deleteScan)
	return cors(auth.Middleware(mux))
}

// authStatus reports whether auth is enabled and the caller is authenticated.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"enabled":       auth.Enabled(),
		"authenticated": !auth.Enabled() || auth.Valid(r),
	})
}

// login verifies the admin password and issues a session cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !auth.CheckPassword(in.Password) {
		writeErr(w, http.StatusUnauthorized, "invalid password")
		return
	}
	auth.IssueCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// logout clears the session cookie.
func (s *Server) logout(w http.ResponseWriter, _ *http.Request) {
	auth.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// ---- handlers ----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "aegis-recon",
		"status":  "ok",
		"version": version.Version,
		"queue":   s.queue.Stats(),
		"time":    time.Now().UTC(),
	})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p := &model.Project{ID: uuid.NewString(), Name: in.Name, CreatedAt: time.Now().UTC()}
	if err := s.store.CreateProject(r.Context(), p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListProjects(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProject(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "project not found")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p.Name = in.Name
	if err := s.store.UpdateProject(r.Context(), p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetProject(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "project not found")
		return
	}
	if err := s.store.DeleteProject(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createAsset(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	if _, err := s.store.GetProject(r.Context(), projectID); err != nil {
		writeErr(w, http.StatusNotFound, "project not found")
		return
	}
	var in struct {
		Type  string   `json:"type"`
		Name  string   `json:"name"`
		Scope []string `json:"scope"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	at := model.AssetType(in.Type)
	if at == "" {
		at = model.AssetDomain
	}
	scopeList := in.Scope
	if len(scopeList) == 0 {
		scopeList = []string{in.Name} // default scope = the asset's own domain
	}
	a := &model.Asset{
		ID:        uuid.NewString(),
		ProjectID: projectID,
		Type:      at,
		Name:      in.Name,
		Scope:     scopeList,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateAsset(r.Context(), a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	as, err := s.store.ListAssets(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, as)
}

func (s *Server) updateAsset(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAsset(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	var in struct {
		Name      string    `json:"name"`
		Type      string    `json:"type"`
		Scope     []string  `json:"scope"`
		Blacklist *[]string `json:"blacklist"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) != "" {
		a.Name = in.Name
	}
	if in.Type != "" {
		a.Type = model.AssetType(in.Type)
	}
	if len(in.Scope) > 0 {
		a.Scope = in.Scope
	}
	// Pointer so an explicit [] clears the blacklist, while omitting the field
	// leaves it unchanged.
	if in.Blacklist != nil {
		a.Blacklist = cleanPatterns(*in.Blacklist)
	}
	if err := s.store.UpdateAsset(r.Context(), a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) deleteAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetAsset(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	if err := s.store.DeleteAsset(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if _, err := s.store.GetAsset(r.Context(), assetID); err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	// Options are optional; default (no body) means exclude Info findings and
	// run nuclei. use_nuclei is a pointer so an omitted field defaults to true.
	var in struct {
		IncludeInfo bool  `json:"include_info"`
		UseNuclei   *bool `json:"use_nuclei"`
	}
	if r.ContentLength != 0 && r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	}
	useNuclei := true
	if in.UseNuclei != nil {
		useNuclei = *in.UseNuclei
	}
	scan := &model.Scan{
		ID:          uuid.NewString(),
		AssetID:     assetID,
		Type:        model.ScanSurface,
		Status:      model.StatusPending,
		IncludeInfo: in.IncludeInfo,
		UseNuclei:   useNuclei,
		Trigger:     model.TriggerManual,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateScan(r.Context(), scan); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.queue.Enqueue(scan.ID)
	writeJSON(w, http.StatusAccepted, scan)
}

// scanListDTO is a Scan plus the highest severity among its findings, so the
// project list can show a severity tag per scan. "clean" means no findings.
type scanListDTO struct {
	model.Scan
	TopSeverity string `json:"top_severity"`
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	scans, err := s.store.ListScans(r.Context(), assetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tops, err := s.store.TopSeverities(r.Context(), assetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]scanListDTO, len(scans))
	for i, sc := range scans {
		top := "clean"
		if sev, ok := tops[sc.ID]; ok {
			top = string(sev)
		}
		// A scan still running has no verdict yet.
		if sc.Status != model.StatusCompleted {
			top = ""
		}
		out[i] = scanListDTO{Scan: sc, TopSeverity: top}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	findings, err := s.store.ListFindings(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Attach the per-asset triage verdicts, keyed by fingerprint so the UI can
	// show each finding's current status. Absent fingerprint = open.
	triage, err := s.store.ListTriage(r.Context(), scan.AssetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmap := make(map[string]model.Triage, len(triage))
	for _, t := range triage {
		tmap[t.Fingerprint] = t
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan, "findings": withFingerprints(findings), "triage": tmap})
}

// findingDTO is a Finding plus its fingerprint, so the client can look each one
// up in the triage map without recomputing the hash itself.
type findingDTO struct {
	model.Finding
	Fingerprint string `json:"fingerprint"`
	Remediation string `json:"remediation,omitempty"`
}

func withFingerprints(fs []model.Finding) []findingDTO {
	out := make([]findingDTO, len(fs))
	for i, f := range fs {
		out[i] = findingDTO{Finding: f, Fingerprint: f.Fingerprint(), Remediation: report.Remediation(f)}
	}
	return out
}

// setTriage upserts the operator's verdict for one finding on an asset. Body:
// {fingerprint, status, note}. status "open" clears the record.
func (s *Server) setTriage(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if _, err := s.store.GetAsset(r.Context(), assetID); err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
		Note        string `json:"note"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Fingerprint) == "" {
		writeErr(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	status := model.TriageStatus(in.Status)
	if !model.ValidTriageStatus(status) {
		writeErr(w, http.StatusBadRequest, "invalid status (open|false-positive|accepted-risk|fixed)")
		return
	}
	t := &model.Triage{
		AssetID:     assetID,
		Fingerprint: in.Fingerprint,
		Status:      status,
		Note:        strings.TrimSpace(in.Note),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := s.store.SetTriage(r.Context(), t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// getSchedule returns the asset's scan schedule. When none exists it returns a
// default disabled schedule rather than 404, so the UI always has a shape.
func (s *Server) getSchedule(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if _, err := s.store.GetAsset(r.Context(), assetID); err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	sc, err := s.store.GetSchedule(r.Context(), assetID)
	if err != nil {
		// No schedule yet: hand back a disabled default.
		writeJSON(w, http.StatusOK, &model.Schedule{AssetID: assetID, Enabled: false})
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

// setSchedule upserts the asset's scan schedule. Body: {enabled, interval_minutes}.
// When enabled, interval_minutes must be > 0 and next_run is set to now+interval.
func (s *Server) setSchedule(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if _, err := s.store.GetAsset(r.Context(), assetID); err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	var in struct {
		Enabled         bool `json:"enabled"`
		IntervalMinutes int  `json:"interval_minutes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Enabled && in.IntervalMinutes <= 0 {
		writeErr(w, http.StatusBadRequest, "interval_minutes must be > 0 when enabled")
		return
	}
	now := time.Now().UTC()
	sc := &model.Schedule{
		AssetID:         assetID,
		IntervalMinutes: in.IntervalMinutes,
		Enabled:         in.Enabled,
		NextRun:         now.Add(time.Duration(in.IntervalMinutes) * time.Minute),
		UpdatedAt:       now,
	}
	if err := s.store.SetSchedule(r.Context(), sc); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

// diffScan compares a scan against the previous COMPLETED scan of the same
// asset, matching findings by fingerprint. The response carries the counts
// (new/resolved/unchanged), the two scan ids, and the classified findings. When
// there is no earlier completed scan, previous_scan_id is empty and every
// current finding is reported as new.
func (s *Server) diffScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	curr, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	currFindings, err := s.store.ListFindings(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Scans come back newest-first. The previous scan is the first COMPLETED one
	// created strictly before this scan.
	scans, err := s.store.ListScans(r.Context(), curr.AssetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var prevID string
	for _, sc := range scans {
		if sc.ID == id || sc.Status != model.StatusCompleted {
			continue
		}
		if sc.CreatedAt.Before(curr.CreatedAt) {
			prevID = sc.ID
			break
		}
	}

	var prevFindings []model.Finding
	if prevID != "" {
		prevFindings, err = s.store.ListFindings(r.Context(), prevID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// Suppress NEW for findings the operator already judged (false-positive /
	// accepted-risk), so a known finding never resurfaces as new.
	triage, err := s.store.ListTriage(r.Context(), curr.AssetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	suppressed := make(map[string]bool, len(triage))
	for _, t := range triage {
		if t.Status.SuppressesNew() {
			suppressed[t.Fingerprint] = true
		}
	}

	result := diff.Scans(currFindings, prevFindings).SuppressNew(suppressed)
	writeJSON(w, http.StatusOK, map[string]any{
		"current_scan_id":  id,
		"previous_scan_id": prevID,
		"counts":           result.Counts(),
		"new":              result.New,
		"resolved":         result.Resolved,
		"unchanged":        result.Unchanged,
	})
}

// exportScan returns the scan's findings as a downloadable file. ?format=sarif
// yields SARIF 2.1.0; ?format=json (default) yields the native Aegis payload.
func (s *Server) exportScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	findings, err := s.store.ListFindings(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	asset := scan.AssetID
	if a, err := s.store.GetAsset(r.Context(), scan.AssetID); err == nil {
		asset = a.Name
	}
	disp := func(ext string) string {
		return `attachment; filename="` + exportFilename(asset, scan, ext) + `"`
	}

	switch r.URL.Query().Get("format") {
	case "sarif":
		b, err := report.SARIF(findings)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Header().Set("Content-Disposition", disp("sarif"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	case "csv":
		b, err := report.CSV(findings)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", disp("csv"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	case "pdf":
		b, err := report.PDF(asset, *scan, findings)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", disp("pdf"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	case "", "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", disp("json"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"scan": scan, "findings": findings})
	default:
		writeErr(w, http.StatusBadRequest, "unknown format (use json, sarif, csv or pdf)")
	}
}

// exportFilename builds "<asset>-<YYYY-MM-DD>.<ext>" from the asset name and the
// scan's completion date, sanitizing the asset to filename-safe characters.
func exportFilename(asset string, scan *model.Scan, ext string) string {
	when := scan.CreatedAt
	if scan.CompletedAt != nil {
		when = *scan.CompletedAt
	}
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, asset)
	if safe == "" {
		safe = "scan"
	}
	return safe + "-" + when.UTC().Format("2006-01-02") + "." + ext
}

func (s *Server) getProgress(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.progress.Get(r.PathValue("id"))
	if !ok {
		// No live progress (scan not started yet or already evicted).
		writeJSON(w, http.StatusOK, map[string]any{"phase": "", "done": 0, "total": 0, "log": []string{}})
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) deleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetScan(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	if err := s.store.DeleteScan(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type sevCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func (c *sevCounts) add(sev model.Severity) {
	switch sev {
	case model.SeverityCritical:
		c.Critical++
	case model.SeverityHigh:
		c.High++
	case model.SeverityMedium:
		c.Medium++
	case model.SeverityLow:
		c.Low++
	case model.SeverityInfo:
		c.Info++
	}
	c.Total++
}

// grpItem is one breakdown row (a project or a service) with its severity counts.
type grpItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	sevCounts
}

// stats builds the aggregate dashboard. Optional query params scope it:
// ?project=<id> drills into one project (breakdown becomes per-service), and
// ?asset=<id> drills into one service. Snapshot, triage and trend all honor the
// scope.
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projectID := r.URL.Query().Get("project")
	assetID := r.URL.Query().Get("asset")

	projects, err := s.store.ListProjects(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	current, err := s.store.CurrentFindings(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	triage, err := s.store.ListAllTriage(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	trend, err := s.store.SeverityTrend(ctx, projectID, assetID, 30)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	tri := make(map[string]model.TriageStatus, len(triage))
	for _, t := range triage {
		tri[t.AssetID+"\x00"+t.Fingerprint] = t.Status
	}

	// Breakdown dimension: no project → per project; a project → per service; a
	// single service → no breakdown.
	breakdownBy := "project"
	if projectID != "" {
		breakdownBy = "asset"
	}
	if assetID != "" {
		breakdownBy = ""
	}

	groups := map[string]*grpItem{}
	if breakdownBy == "project" {
		for _, p := range projects {
			groups[p.ID] = &grpItem{ID: p.ID, Name: p.Name}
		}
	} else if breakdownBy == "asset" {
		if as, err := s.store.ListAssets(ctx, projectID); err == nil {
			for _, a := range as {
				groups[a.ID] = &grpItem{ID: a.ID, Name: a.Name}
			}
		}
	}

	var overall sevCounts
	triageCounts := struct {
		Open          int `json:"open"`
		FalsePositive int `json:"false_positive"`
		AcceptedRisk  int `json:"accepted_risk"`
		Fixed         int `json:"fixed"`
	}{}

	for _, cf := range current {
		if projectID != "" && cf.ProjectID != projectID {
			continue
		}
		if assetID != "" && cf.AssetID != assetID {
			continue
		}
		overall.add(cf.Severity)
		if breakdownBy == "project" {
			if g := groups[cf.ProjectID]; g != nil {
				g.add(cf.Severity)
			}
		} else if breakdownBy == "asset" {
			if g := groups[cf.AssetID]; g != nil {
				g.add(cf.Severity)
			}
		}
		switch tri[cf.AssetID+"\x00"+cf.Fingerprint] {
		case model.TriageFalsePositive:
			triageCounts.FalsePositive++
		case model.TriageAcceptedRisk:
			triageCounts.AcceptedRisk++
		case model.TriageFixed:
			triageCounts.Fixed++
		default:
			triageCounts.Open++
		}
	}

	breakdown := make([]*grpItem, 0, len(groups))
	for _, g := range groups {
		breakdown = append(breakdown, g)
	}
	sort.Slice(breakdown, func(i, j int) bool { return breakdown[i].Name < breakdown[j].Name })

	// Assets in scope.
	assetCount := 0
	switch {
	case assetID != "":
		assetCount = 1
	case projectID != "":
		if as, err := s.store.ListAssets(ctx, projectID); err == nil {
			assetCount = len(as)
		}
	default:
		for _, p := range projects {
			if as, err := s.store.ListAssets(ctx, p.ID); err == nil {
				assetCount += len(as)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"totals": map[string]int{
			"projects": len(projects),
			"assets":   assetCount,
			"findings": overall.Total,
		},
		"severity":     overall,
		"triage":       triageCounts,
		"breakdown_by": breakdownBy,
		"breakdown":    breakdown,
		"trend":        trend,
	})
}

// findingRow is a current finding enriched for the global findings view.
type findingRow struct {
	ProjectID   string         `json:"project_id"`
	ProjectName string         `json:"project_name"`
	AssetID     string         `json:"asset_id"`
	AssetName   string         `json:"asset_name"`
	Scanner     string         `json:"scanner"`
	Severity    model.Severity `json:"severity"`
	Title       string         `json:"title"`
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Fingerprint string         `json:"fingerprint"`
	Status      string         `json:"status"`
	Remediation string         `json:"remediation,omitempty"`
}

// findings is the global, filterable list of current findings (latest completed
// scan per asset). Query params: project, asset, severity, scanner, status, q.
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cur, err := s.store.CurrentFindings(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	triage, err := s.store.ListAllTriage(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tri := make(map[string]model.TriageStatus, len(triage))
	for _, t := range triage {
		tri[t.AssetID+"\x00"+t.Fingerprint] = t.Status
	}

	q := r.URL.Query()
	fProject := q.Get("project")
	fAsset := q.Get("asset")
	fSeverity := q.Get("severity")
	fScanner := q.Get("scanner")
	fStatus := q.Get("status")
	fText := strings.ToLower(strings.TrimSpace(q.Get("q")))

	out := make([]findingRow, 0, len(cur))
	for _, cf := range cur {
		status := string(model.TriageOpen)
		if st, ok := tri[cf.AssetID+"\x00"+cf.Fingerprint]; ok {
			status = string(st)
		}
		if fProject != "" && cf.ProjectID != fProject {
			continue
		}
		if fAsset != "" && cf.AssetID != fAsset {
			continue
		}
		if fSeverity != "" && string(cf.Severity) != fSeverity {
			continue
		}
		if fScanner != "" && cf.Scanner != fScanner {
			continue
		}
		if fStatus != "" && status != fStatus {
			continue
		}
		if fText != "" && !strings.Contains(strings.ToLower(cf.Title), fText) &&
			!strings.Contains(strings.ToLower(cf.Host), fText) {
			continue
		}
		out = append(out, findingRow{
			ProjectID: cf.ProjectID, ProjectName: cf.ProjectName,
			AssetID: cf.AssetID, AssetName: cf.AssetName,
			Scanner: cf.Scanner, Severity: cf.Severity, Title: cf.Title,
			Host: cf.Host, Port: cf.Port, Fingerprint: cf.Fingerprint, Status: status,
			Remediation: report.Remediation(model.Finding{Scanner: cf.Scanner, Severity: cf.Severity, Title: cf.Title}),
		})
	}
	// Severity desc, then title.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].Title < out[j].Title
	})
	writeJSON(w, http.StatusOK, out)
}

// secretSettings holds the setting keys whose values are encrypted at rest and
// never returned in plaintext by the API.
var secretSettings = map[string]bool{
	"smtp_pass": true,
}

// settingsResponse is the masked view of the settings: non-secret values inline,
// secrets reported only as present/absent.
func settingsResponse(all map[string]string) map[string]any {
	values := map[string]string{}
	secretsSet := map[string]bool{}
	for k, v := range all {
		if secretSettings[k] {
			secretsSet[k] = v != ""
		} else {
			values[k] = v
		}
	}
	return map[string]any{"settings": values, "secrets_set": secretsSet}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.AllSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse(all))
}

// putSettings upserts a flat {key: value} map. Secret keys are encrypted before
// storage; an empty value for a secret leaves the existing one unchanged (so the
// UI can submit without re-entering the password).
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if !readJSON(w, r, &in) {
		return
	}
	for k, v := range in {
		if secretSettings[k] {
			if v == "" {
				continue // keep the stored secret
			}
			enc, err := secret.Encrypt(v)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			v = enc
		}
		if err := s.store.SetSetting(r.Context(), k, v); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	all, err := s.store.AllSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse(all))
}

// ---- helpers ----

// cleanPatterns trims, lowercases, drops blanks and de-duplicates blacklist
// entries so the stored list is tidy. Order is preserved.
func cleanPatterns(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// readJSON decodes the request body into v, writing a 400 on failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, http.ErrBodyReadAfterClose) {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// cors allows the React dev server and same-origin requests to call the API.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

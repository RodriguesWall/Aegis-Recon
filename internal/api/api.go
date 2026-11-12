// Package api exposes the HTTP API for projects, assets and scans. It is a thin
// layer over the store and the queue: handlers validate input, persist, and (for
// scans) enqueue background work. Routing uses the stdlib ServeMux method+path
// patterns (Go 1.22+), so no router dependency.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/progress"
	"github.com/RodriguesWall/aegis-recon/internal/queue"
	"github.com/RodriguesWall/aegis-recon/internal/store"
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
	mux.HandleFunc("DELETE /api/scans/{id}", s.deleteScan)
	return cors(mux)
}

// ---- handlers ----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "aegis-recon",
		"status":  "ok",
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
		Name  string   `json:"name"`
		Type  string   `json:"type"`
		Scope []string `json:"scope"`
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
	// Options are optional; default (no body) means exclude Info findings.
	var in struct {
		IncludeInfo bool `json:"include_info"`
	}
	if r.ContentLength != 0 && r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	}
	scan := &model.Scan{
		ID:          uuid.NewString(),
		AssetID:     assetID,
		Type:        model.ScanSurface,
		Status:      model.StatusPending,
		IncludeInfo: in.IncludeInfo,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateScan(r.Context(), scan); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.queue.Enqueue(scan.ID)
	writeJSON(w, http.StatusAccepted, scan)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scans)
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
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan, "findings": findings})
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

// ---- helpers ----

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

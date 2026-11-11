package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/api"
	"github.com/RodriguesWall/aegis-recon/internal/queue"
	"github.com/RodriguesWall/aegis-recon/internal/store/memory"
)

// newServer wires the API over an in-memory store and a queue with a no-op
// handler, so no real scanning happens during the test.
func newServer() http.Handler {
	st := memory.New()
	q := queue.New(func(context.Context, string) error { return nil })
	return api.New(st, q).Routes()
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

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

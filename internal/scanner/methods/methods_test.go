package methods

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func scan(t *testing.T, h http.HandlerFunc) []model.Finding {
	t.Helper()
	ts := httptest.NewServer(h)
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	s := New(WithClient(ts.Client()), WithScheme("http"))
	var out []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: host}, func(f model.Finding) { out = append(out, f) }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func titles(fs []model.Finding) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		m[f.Title] = f.Severity
	}
	return m
}

func TestWriteMethodsAndTrace(t *testing.T) {
	got := scan(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
			w.WriteHeader(204)
			return
		}
		if r.Method == http.MethodTrace {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	})
	ts := titles(got)
	wm := "write methods enabled: PUT, DELETE"
	if ts[wm] != model.SeverityMedium {
		t.Fatalf("want write-methods medium, got %+v", ts)
	}
	if ts["TRACE method enabled (cross-site tracing)"] != model.SeverityLow {
		t.Fatalf("want TRACE low, got %+v", ts)
	}
}

func TestSafeServerNoFindings(t *testing.T) {
	got := scan(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			w.WriteHeader(204)
			return
		}
		if r.Method == http.MethodTrace {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
	})
	if len(got) != 0 {
		t.Fatalf("safe server should yield nothing, got %+v", titles(got))
	}
}

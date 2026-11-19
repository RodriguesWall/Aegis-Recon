package cors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func scanWith(t *testing.T, h http.HandlerFunc) []model.Finding {
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

func TestReflectWithCredentials(t *testing.T) {
	got := scanWith(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	})
	if len(got) != 1 || got[0].Severity != model.SeverityHigh {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

func TestReflectNoCredentials(t *testing.T) {
	got := scanWith(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("want 1 medium, got %+v", got)
	}
}

func TestWildcard(t *testing.T) {
	got := scanWith(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	})
	if len(got) != 1 || got[0].Severity != model.SeverityInfo {
		t.Fatalf("want 1 info, got %+v", got)
	}
}

func TestSameOriginNoFinding(t *testing.T) {
	// ACAO fixed to the site's own origin (not reflected, not *) -> no finding.
	got := scanWith(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
	})
	if len(got) != 0 {
		t.Fatalf("fixed allow-origin should not flag, got %+v", got)
	}
}

func TestNoCORSHeader(t *testing.T) {
	got := scanWith(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	if len(got) != 0 {
		t.Fatalf("no CORS header should yield nothing, got %+v", got)
	}
}

package openredirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func run(t *testing.T, h http.HandlerFunc) []model.Finding {
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

func TestOpenRedirect(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		if n := r.URL.Query().Get("next"); n != "" {
			http.Redirect(w, r, n, http.StatusFound) // reflects param into Location
			return
		}
		w.WriteHeader(200)
	})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("want 1 medium open-redirect, got %+v", got)
	}
	if got[0].Evidence["param"] != "next" {
		t.Fatalf("wrong param: %+v", got[0].Evidence)
	}
}

func TestSafeRedirectInternal(t *testing.T) {
	// Always redirects to a fixed internal path, ignoring the param -> safe.
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") != "" {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	})
	if len(got) != 0 {
		t.Fatalf("internal redirect must not flag, got %+v", got)
	}
}

func TestNoRedirect(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	if len(got) != 0 {
		t.Fatalf("no redirect should yield nothing, got %+v", got)
	}
}

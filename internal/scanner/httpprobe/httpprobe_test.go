package httpprobe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/httpprobe"
)

func targetFor(t *testing.T, rawURL string) model.Target {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())
	return model.Target{Host: u.Hostname(), Port: port}
}

func TestScan_FlagsMissingSecurityHeaders(t *testing.T) {
	// Server sends only HSTS; the other three headers are missing.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Server", "test-server")
		_, _ = w.Write([]byte("<html><head><title>Hello</title></head></html>"))
	}))
	defer ts.Close()

	s := httpprobe.New(httpprobe.WithScheme("http"), httpprobe.WithClient(ts.Client()))

	var got []model.Finding
	if err := s.Scan(context.Background(), targetFor(t, ts.URL), func(f model.Finding) {
		got = append(got, f)
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	titles := map[string]model.Severity{}
	for _, f := range got {
		titles[f.Title] = f.Severity
	}

	if _, ok := titles["HTTP response"]; !ok {
		t.Fatalf("missing HTTP response finding: %v", titles)
	}
	// HSTS present -> not flagged. The other three -> flagged.
	if _, ok := titles["missing HSTS header"]; ok {
		t.Errorf("HSTS present but flagged missing")
	}
	for _, want := range []string{
		"missing Content-Security-Policy header",
		"missing X-Frame-Options header",
		"missing X-Content-Type-Options header",
	} {
		if sev := titles[want]; sev != model.SeverityLow {
			t.Errorf("want %q as low, got %q", want, sev)
		}
	}
}

func TestScan_ExtractsTitleAndStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title> My Site </title>"))
	}))
	defer ts.Close()

	s := httpprobe.New(httpprobe.WithScheme("http"), httpprobe.WithClient(ts.Client()))

	var info model.Finding
	_ = s.Scan(context.Background(), targetFor(t, ts.URL), func(f model.Finding) {
		if f.Title == "HTTP response" {
			info = f
		}
	})
	if info.Evidence["status"] != 200 {
		t.Errorf("status = %v, want 200", info.Evidence["status"])
	}
	if info.Evidence["title"] != "My Site" {
		t.Errorf("title = %q, want %q", info.Evidence["title"], "My Site")
	}
}

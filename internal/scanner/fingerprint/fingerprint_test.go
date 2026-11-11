package fingerprint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/fingerprint"
)

func TestScan_DetectsHeaderAndBodySignatures(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.1")
		_, _ = w.Write([]byte(`<html><body><link href="/wp-content/themes/x.css"></body></html>`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	portNum, _ := strconv.Atoi(u.Port())

	s := fingerprint.New(fingerprint.WithScheme("http"), fingerprint.WithClient(ts.Client()))

	detected := map[string]bool{}
	if err := s.Scan(context.Background(), model.Target{Host: u.Hostname(), Port: portNum}, func(f model.Finding) {
		if tech, ok := f.Evidence["technology"].(string); ok {
			detected[tech] = true
		}
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, want := range []string{"nginx", "WordPress"} {
		if !detected[want] {
			t.Errorf("missing detection %q (got %v)", want, detected)
		}
	}
}

func TestScan_NoSignaturesNoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	portNum, _ := strconv.Atoi(u.Port())

	s := fingerprint.New(fingerprint.WithScheme("http"), fingerprint.WithClient(ts.Client()))

	n := 0
	_ = s.Scan(context.Background(), model.Target{Host: u.Hostname(), Port: portNum}, func(model.Finding) { n++ })
	if n != 0 {
		t.Fatalf("expected 0 findings, got %d", n)
	}
}

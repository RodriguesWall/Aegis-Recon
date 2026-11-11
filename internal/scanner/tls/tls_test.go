package tls_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	tlsscan "github.com/RodriguesWall/aegis-recon/internal/scanner/tls"
)

func TestScan_InspectsCertificate(t *testing.T) {
	// httptest TLS server serves a freshly generated, currently-valid cert.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())

	s := tlsscan.New()

	var got []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: u.Hostname(), Port: port}, func(f model.Finding) {
		got = append(got, f)
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var info *model.Finding
	for i := range got {
		if got[i].Title == "TLS certificate" {
			info = &got[i]
		}
		// A fresh test cert must not be reported expired.
		if got[i].Title == "TLS certificate expired" {
			t.Errorf("fresh cert reported expired")
		}
	}
	if info == nil {
		t.Fatalf("missing TLS certificate finding: %+v", got)
	}
	if info.Evidence["not_after"] == "" {
		t.Errorf("not_after missing: %+v", info.Evidence)
	}
}

func TestScan_DialError(t *testing.T) {
	s := tlsscan.New()
	// Nothing listening on this port -> dial error.
	err := s.Scan(context.Background(), model.Target{Host: "127.0.0.1", Port: 1}, func(model.Finding) {})
	if err == nil {
		t.Fatal("expected dial error")
	}
}

package cdn

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// fakeResolver returns a fixed CNAME for every host.
type fakeResolver struct{ cname string }

func (f fakeResolver) LookupCNAME(context.Context, string) (string, error) { return f.cname, nil }
func (fakeResolver) LookupHost(context.Context, string) ([]string, error)  { return nil, nil }
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error)   { return nil, nil }
func (fakeResolver) LookupTXT(context.Context, string) ([]string, error)   { return nil, nil }
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error)   { return nil, nil }

func run(t *testing.T, s *Scanner, host string) []model.Finding {
	t.Helper()
	var out []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: host}, func(f model.Finding) { out = append(out, f) }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func serverWith(h map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range h {
			w.Header().Set(k, v)
		}
		w.WriteHeader(200)
	}))
}

func TestDetectByHeader(t *testing.T) {
	ts := serverWith(map[string]string{"CF-Ray": "abc123-GRU"})
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")

	s := New(fakeResolver{}, WithClient(ts.Client()), WithScheme("http"))
	got := run(t, s, host)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Severity != model.SeverityInfo || got[0].Evidence["provider"] != "Cloudflare" {
		t.Fatalf("wrong finding: %+v", got[0])
	}
	if got[0].Evidence["signal"] != "header:CF-Ray" {
		t.Fatalf("wrong signal: %+v", got[0].Evidence)
	}
}

func TestDetectWAFKind(t *testing.T) {
	ts := serverWith(map[string]string{"X-Sucuri-ID": "17001"})
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")

	s := New(fakeResolver{}, WithClient(ts.Client()), WithScheme("http"))
	got := run(t, s, host)
	if len(got) != 1 || got[0].Title != "behind WAF: Sucuri" {
		t.Fatalf("want WAF Sucuri, got %+v", got)
	}
}

func TestDetectByCNAME(t *testing.T) {
	ts := serverWith(nil) // no CDN headers
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")

	s := New(fakeResolver{cname: "e1234.x.akamaiedge.net."}, WithClient(ts.Client()), WithScheme("http"))
	got := run(t, s, host)
	if len(got) != 1 || got[0].Evidence["provider"] != "Akamai" {
		t.Fatalf("want Akamai via cname, got %+v", got)
	}
	if got[0].Evidence["signal"] != "cname:akamaiedge.net" {
		t.Fatalf("wrong signal: %+v", got[0].Evidence)
	}
}

func TestNoMatch(t *testing.T) {
	ts := serverWith(map[string]string{"Server": "nginx"})
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")

	s := New(fakeResolver{cname: "host.example.com."}, WithClient(ts.Client()), WithScheme("http"))
	if got := run(t, s, host); len(got) != 0 {
		t.Fatalf("expected no finding, got %+v", got)
	}
}

func TestHeaderBeatsCNAME(t *testing.T) {
	// Header evidence is checked before the CNAME fallback.
	ts := serverWith(map[string]string{"CF-Ray": "x"})
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")

	s := New(fakeResolver{cname: "x.akamaiedge.net."}, WithClient(ts.Client()), WithScheme("http"))
	got := run(t, s, host)
	if len(got) != 1 || got[0].Evidence["provider"] != "Cloudflare" {
		t.Fatalf("header should win over cname, got %+v", got)
	}
}

package exposedfiles

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func scan(t *testing.T, ts *httptest.Server) []model.Finding {
	t.Helper()
	host := strings.TrimPrefix(ts.URL, "http://")
	s := New(WithClient(ts.Client()), WithScheme("http"))
	var out []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: host}, func(f model.Finding) { out = append(out, f) }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func titles(fs []model.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Title] = true
	}
	return m
}

func TestDetectsExposed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
		case "/.env":
			w.Write([]byte("DB_HOST=localhost\nSECRET=abc\n"))
		case "/swagger.json":
			w.Write([]byte(`{"swagger":"2.0","info":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ts_ := titles(scan(t, ts))
	for _, want := range []string{
		"exposed .git/config (source disclosure)",
		"exposed .env file",
		"API docs exposed (swagger.json)",
	} {
		if !ts_[want] {
			t.Errorf("missing finding %q (got %v)", want, ts_)
		}
	}
}

func TestSoft404Suppresses(t *testing.T) {
	// Server answers 200 to everything -> baseline trips -> nothing reported.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<!doctype html><html>ok</html>"))
	}))
	defer ts.Close()
	if got := scan(t, ts); len(got) != 0 {
		t.Fatalf("soft-404 server must yield nothing, got %v", titles(got))
	}
}

func TestSignatureAndHTMLGuard(t *testing.T) {
	// .git/config without the [core] signature, and .env that returns HTML:
	// both must be suppressed. Random baseline 404s so the host is scanned.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			w.Write([]byte("not a git config"))
		case "/.env":
			w.Write([]byte("<!doctype html><html>login</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	if got := scan(t, ts); len(got) != 0 {
		t.Fatalf("unconfirmed hits must be suppressed, got %v", titles(got))
	}
}

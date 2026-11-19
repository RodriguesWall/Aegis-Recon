package hostheader

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

func TestHostReflectedInLocation(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		// Reflects the request Host into an absolute redirect.
		w.Header().Set("Location", "https://"+r.Host+"/next")
		w.WriteHeader(http.StatusFound)
	})
	if len(got) != 1 || got[0].Severity != model.SeverityHigh || got[0].Evidence["vector"] != "Host" {
		t.Fatalf("want 1 high via Host, got %+v", got)
	}
}

func TestXFHReflectedInBody(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, r *http.Request) {
		// Reflects X-Forwarded-Host into the body; ignores Host.
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			_, _ = w.Write([]byte(`<a href="https://` + xfh + `/reset">reset</a>`))
			return
		}
		w.WriteHeader(200)
	})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Evidence["vector"] != "X-Forwarded-Host" {
		t.Fatalf("want 1 medium via XFH, got %+v", got)
	}
}

func TestNoReflection(t *testing.T) {
	got := run(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	})
	if len(got) != 0 {
		t.Fatalf("no reflection should yield nothing, got %+v", got)
	}
}

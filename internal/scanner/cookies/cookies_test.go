package cookies

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func scan(t *testing.T, setCookies []string) []model.Finding {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for _, sc := range setCookies {
			w.Header().Add("Set-Cookie", sc)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	s := New(WithClient(ts.Client()), WithScheme("http"))
	var out []model.Finding
	if err := s.Scan(context.Background(), model.Target{Host: host}, func(f model.Finding) { out = append(out, f) }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func TestNoFlagsMedium(t *testing.T) {
	got := scan(t, []string{"sid=abc"})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("want 1 medium, got %+v", got)
	}
	if !strings.Contains(got[0].Title, "HttpOnly") || !strings.Contains(got[0].Title, "Secure") {
		t.Fatalf("title missing flags: %q", got[0].Title)
	}
}

func TestOnlySameSiteLow(t *testing.T) {
	got := scan(t, []string{"x=1; HttpOnly; Secure"})
	if len(got) != 1 || got[0].Severity != model.SeverityLow {
		t.Fatalf("want 1 low (only SameSite), got %+v", got)
	}
}

func TestFullySecureNoFinding(t *testing.T) {
	if got := scan(t, []string{"x=1; HttpOnly; Secure; SameSite=Strict"}); len(got) != 0 {
		t.Fatalf("secure cookie should not flag, got %+v", got)
	}
}

func TestMultipleCookies(t *testing.T) {
	got := scan(t, []string{"a=1", "b=2; HttpOnly; Secure; SameSite=Lax"})
	if len(got) != 1 || got[0].Evidence["cookie"] != "a" {
		t.Fatalf("expected only the insecure cookie flagged, got %+v", got)
	}
}

package report

import (
	"strings"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func TestRemediationSkipsInfo(t *testing.T) {
	f := model.Finding{Scanner: "cors", Severity: model.SeverityInfo, Title: "CORS allows any origin (*)"}
	if r := Remediation(f); r != "" {
		t.Fatalf("info severity must have no remediation, got %q", r)
	}
}

func TestRemediationBySubtype(t *testing.T) {
	cases := []struct {
		scanner, title string
		sev            model.Severity
		want           string
	}{
		{"emailposture", "no SPF record (email spoofing risk)", model.SeverityMedium, "spf"},
		{"emailposture", "no DMARC record (email spoofing risk)", model.SeverityMedium, "dmarc"},
		{"cors", "CORS reflects arbitrary origin with credentials", model.SeverityHigh, "origin"},
		{"cookies", "insecure cookie: sid (missing HttpOnly)", model.SeverityMedium, "samesite"},
		{"methods", "TRACE method enabled (cross-site tracing)", model.SeverityLow, "trace"},
		{"graphql", "GraphQL introspection enabled", model.SeverityMedium, "introspection"},
	}
	for _, c := range cases {
		r := strings.ToLower(Remediation(model.Finding{Scanner: c.scanner, Severity: c.sev, Title: c.title}))
		if r == "" || !strings.Contains(r, c.want) {
			t.Errorf("%s/%q: remediation %q missing %q", c.scanner, c.title, r, c.want)
		}
	}
}

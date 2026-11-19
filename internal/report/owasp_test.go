package report

import (
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func TestOWASP(t *testing.T) {
	cases := map[string]string{
		"tls":          "A02",
		"openredirect": "A01",
		"openapi":      "A01",
		"cors":         "A05",
		"cookies":      "A05",
		"dnssec":       "A05",
		"httpprobe":    "A05",
		// unmapped:
		"emailposture": "",
		"nuclei":       "",
		"dns":          "",
		"cdn":          "",
		"fingerprint":  "",
		"whatever":     "",
	}
	for scanner, want := range cases {
		got := OWASP(model.Finding{Scanner: scanner})
		if got != want {
			t.Errorf("OWASP(%s) = %q, want %q", scanner, got, want)
		}
	}
}

func TestOWASPName(t *testing.T) {
	if OWASPName("A05") != "Security Misconfiguration" {
		t.Errorf("A05 name wrong: %q", OWASPName("A05"))
	}
	if OWASPName("A99") != "" {
		t.Errorf("unknown code must be empty, got %q", OWASPName("A99"))
	}
}

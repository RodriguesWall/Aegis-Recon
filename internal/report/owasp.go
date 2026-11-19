package report

import "github.com/RodriguesWall/aegis-recon/internal/model"

// OWASP maps a finding to its OWASP Top 10 (2021) category code (e.g. "A05"),
// or "" when the finding does not cleanly fit a web Top-10 category. The mapping
// is static, keyed by scanner and refined by title; it carries no CVSS score.
//
// Deliberately honest about gaps: email-authentication posture is not a web
// Top-10 category, DNS/CDN/fingerprint findings are inventory, and nuclei
// results vary per template, so all of these stay unmapped rather than being
// forced into a catch-all bucket.
func OWASP(f model.Finding) string {
	switch f.Scanner {
	case "tls":
		return "A02" // Cryptographic Failures
	case "openredirect", "openapi":
		return "A01" // Broken Access Control
	case "cors", "cookies", "methods", "hostheader", "infoleak",
		"graphql", "httpprobe", "exposedfiles", "port", "dnssec":
		return "A05" // Security Misconfiguration
	default:
		return "" // emailposture, dns, cdn, fingerprint, nuclei, unknown
	}
}

// owaspNames is the human label per code (used by reports; the web UI has its
// own copy).
var owaspNames = map[string]string{
	"A01": "Broken Access Control",
	"A02": "Cryptographic Failures",
	"A03": "Injection",
	"A04": "Insecure Design",
	"A05": "Security Misconfiguration",
	"A06": "Vulnerable and Outdated Components",
	"A07": "Identification and Authentication Failures",
	"A08": "Software and Data Integrity Failures",
	"A09": "Security Logging and Monitoring Failures",
	"A10": "Server-Side Request Forgery",
}

// OWASPName returns the full category name for a code, or "" if unknown.
func OWASPName(code string) string { return owaspNames[code] }

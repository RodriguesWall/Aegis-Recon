package report

import (
	"strings"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Remediation returns a short fix hint for a finding, or "" when none applies.
// Info-severity findings get no remediation (keeps reports focused on what
// matters); the text is picked per scanner, refined by the title where useful.
func Remediation(f model.Finding) string {
	if f.Severity == model.SeverityInfo {
		return ""
	}
	t := strings.ToLower(f.Title)
	switch f.Scanner {
	case "emailposture":
		switch {
		case strings.Contains(t, "spf"):
			return "Publish a strict SPF TXT record ending in -all; avoid +all/?all."
		case strings.Contains(t, "dmarc"):
			return "Publish a DMARC record with p=quarantine or p=reject (not none)."
		}
	case "cors":
		return "Allow only trusted origins; never reflect an arbitrary Origin, and never combine Allow-Origin: * with credentials."
	case "cookies":
		return "Set Secure, HttpOnly and SameSite on session cookies."
	case "methods":
		if strings.Contains(t, "trace") {
			return "Disable the TRACE method on the web server."
		}
		return "Disable unused write methods (PUT/DELETE/PATCH) or require authentication."
	case "openredirect":
		return "Validate redirect targets against an allowlist; never redirect to user-supplied absolute URLs."
	case "hostheader":
		return "Do not build URLs from the Host/X-Forwarded-Host header; use a fixed canonical hostname."
	case "infoleak":
		if strings.Contains(t, "stack trace") {
			return "Disable debug/verbose error pages in production; return generic errors."
		}
	case "openapi":
		return "Require authentication on write operations and restrict the exposed API spec."
	case "graphql":
		return "Disable GraphQL introspection in production."
	case "dnssec":
		if strings.Contains(t, "zone transfer") {
			return "Restrict AXFR to authorized secondary nameserver IPs (allow-transfer); do not allow public zone transfers."
		}
	case "exposedfiles":
		return "Remove or block public access to the exposed file/path."
	case "port":
		return "Restrict the exposed service with a firewall/VPN; do not expose database/admin ports publicly."
	case "tls":
		return "Use TLS 1.2+ with strong ciphers and renew certificates before expiry."
	case "httpprobe":
		if strings.Contains(t, "header") {
			return "Add the missing security header to all responses."
		}
	}
	return ""
}

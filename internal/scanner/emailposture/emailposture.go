// Package emailposture checks a domain's email-authentication posture (SPF,
// DMARC, DKIM) from its DNS TXT records. These are organization/domain-level
// controls, so it runs once per scan against the asset's root domain rather than
// per host. It is pure stdlib (model.Resolver), so it is testable without a
// network. DNSSEC and zone-transfer checks need raw DNS queries and are deferred.
package emailposture

import (
	"context"
	"strings"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// commonDKIMSelectors is a small best-effort list; DKIM selectors are arbitrary,
// so a miss is low-confidence, not proof of absence.
var commonDKIMSelectors = []string{"default", "google", "selector1", "selector2", "k1", "mail", "dkim"}

// Check returns the email-posture findings for a domain.
func Check(ctx context.Context, domain string, r model.Resolver) []model.Finding {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	var out []model.Finding
	out = append(out, checkSPF(ctx, domain, r)...)
	out = append(out, checkDMARC(ctx, domain, r)...)
	out = append(out, checkDKIM(ctx, domain, r)...)
	return out
}

func finding(domain string, sev model.Severity, title string, ev map[string]any) model.Finding {
	return model.Finding{
		Scanner:  "emailposture",
		Target:   model.Target{Domain: domain},
		Severity: sev,
		Title:    title,
		Evidence: ev,
	}
}

func checkSPF(ctx context.Context, domain string, r model.Resolver) []model.Finding {
	txt, err := r.LookupTXT(ctx, domain)
	var spf []string
	if err == nil {
		for _, t := range txt {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
				spf = append(spf, t)
			}
		}
	}
	switch {
	case len(spf) == 0:
		return []model.Finding{finding(domain, model.SeverityMedium,
			"no SPF record (email spoofing risk)", map[string]any{"record": "none"})}
	case len(spf) > 1:
		return []model.Finding{finding(domain, model.SeverityMedium,
			"multiple SPF records (invalid)", map[string]any{"count": len(spf)})}
	}

	rec := strings.ToLower(spf[0])
	switch {
	case strings.Contains(rec, "+all"):
		return []model.Finding{finding(domain, model.SeverityHigh,
			"SPF allows any sender (+all)", map[string]any{"record": spf[0]})}
	case strings.Contains(rec, "?all"):
		return []model.Finding{finding(domain, model.SeverityMedium,
			"SPF neutral policy (?all)", map[string]any{"record": spf[0]})}
	}
	return nil // -all / ~all: acceptable
}

func checkDMARC(ctx context.Context, domain string, r model.Resolver) []model.Finding {
	txt, err := r.LookupTXT(ctx, "_dmarc."+domain)
	var rec string
	if err == nil {
		for _, t := range txt {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
				rec = t
				break
			}
		}
	}
	if rec == "" {
		return []model.Finding{finding(domain, model.SeverityMedium,
			"no DMARC record (email spoofing risk)", map[string]any{"record": "none"})}
	}
	if policy := dmarcPolicy(rec); policy == "none" {
		return []model.Finding{finding(domain, model.SeverityLow,
			"DMARC policy is p=none (monitoring only)", map[string]any{"record": rec})}
	}
	return nil
}

// dmarcPolicy extracts the p= tag value (lowercased), or "" if absent.
func dmarcPolicy(rec string) string {
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "p=") {
			return strings.TrimSpace(strings.TrimPrefix(part, "p="))
		}
	}
	return ""
}

func checkDKIM(ctx context.Context, domain string, r model.Resolver) []model.Finding {
	for _, sel := range commonDKIMSelectors {
		txt, err := r.LookupTXT(ctx, sel+"._domainkey."+domain)
		if err != nil {
			continue
		}
		for _, t := range txt {
			lt := strings.ToLower(t)
			if strings.Contains(lt, "v=dkim1") || strings.Contains(lt, "k=") || strings.Contains(lt, "p=") {
				return nil // a DKIM key exists on a common selector
			}
		}
	}
	return []model.Finding{finding(domain, model.SeverityInfo,
		"no DKIM key found on common selectors (low confidence)",
		map[string]any{"selectors": strings.Join(commonDKIMSelectors, ",")})}
}

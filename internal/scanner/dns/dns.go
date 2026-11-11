// Package dns resolves DNS records for a target domain. It is the simplest
// real scanner and demonstrates the payoff of the injectable model.Resolver:
// production passes *net.Resolver, tests pass a fake — no network needed.
package dns

import (
	"context"
	"fmt"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Scanner resolves A/AAAA, MX, NS, TXT and CNAME records.
type Scanner struct {
	r model.Resolver
}

// New builds a dns scanner using the given resolver. In production pass
// &net.Resolver{}; in tests pass a fake implementing model.Resolver.
func New(r model.Resolver) *Scanner { return &Scanner{r: r} }

// Name implements model.Scanner.
func (s *Scanner) Name() string { return "dns" }

// Scan implements model.Scanner. Each lookup is independent: a missing record
// (e.g. no MX) is normal and simply yields no finding, not an error.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	name := t.Domain
	if name == "" {
		name = t.Host
	}
	if name == "" {
		return fmt.Errorf("dns: empty target")
	}

	// A / AAAA — the addresses the name resolves to.
	if ips, err := s.r.LookupHost(ctx, name); err == nil && len(ips) > 0 {
		emit(model.Finding{
			Scanner:  s.Name(),
			Target:   t,
			Severity: model.SeverityInfo,
			Title:    "resolved addresses",
			Evidence: map[string]any{"name": name, "addresses": ips},
		})
	}

	// MX — mail exchangers.
	if mx, err := s.r.LookupMX(ctx, name); err == nil && len(mx) > 0 {
		hosts := make([]string, 0, len(mx))
		for _, m := range mx {
			hosts = append(hosts, m.Host)
		}
		emit(model.Finding{
			Scanner:  s.Name(),
			Target:   t,
			Severity: model.SeverityInfo,
			Title:    "MX records",
			Evidence: map[string]any{"name": name, "mx": hosts},
		})
	}

	// NS — authoritative nameservers.
	if ns, err := s.r.LookupNS(ctx, name); err == nil && len(ns) > 0 {
		hosts := make([]string, 0, len(ns))
		for _, n := range ns {
			hosts = append(hosts, n.Host)
		}
		emit(model.Finding{
			Scanner:  s.Name(),
			Target:   t,
			Severity: model.SeverityInfo,
			Title:    "NS records",
			Evidence: map[string]any{"name": name, "ns": hosts},
		})
	}

	// TXT — SPF/DKIM/verification strings.
	if txt, err := s.r.LookupTXT(ctx, name); err == nil && len(txt) > 0 {
		emit(model.Finding{
			Scanner:  s.Name(),
			Target:   t,
			Severity: model.SeverityInfo,
			Title:    "TXT records",
			Evidence: map[string]any{"name": name, "txt": txt},
		})
	}

	// CNAME — canonical name, when the host is an alias.
	if cname, err := s.r.LookupCNAME(ctx, name); err == nil && cname != "" && cname != name+"." {
		emit(model.Finding{
			Scanner:  s.Name(),
			Target:   t,
			Severity: model.SeverityInfo,
			Title:    "CNAME record",
			Evidence: map[string]any{"name": name, "cname": cname},
		})
	}

	return nil
}

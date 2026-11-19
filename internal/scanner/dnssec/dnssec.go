// Package dnssec runs raw-DNS posture checks that the stdlib resolver cannot do:
// a zone-transfer (AXFR) attempt against every authoritative nameserver, and a
// DNSSEC signed-zone check. Like emailposture these are domain-level, so Check
// runs once per scan against the asset's root domain rather than per host. The
// raw queries sit behind the queryer interface so the logic is testable without
// a network.
package dnssec

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// queryer is the raw-DNS surface Check needs; the default impl is miekg/dns.
type queryer interface {
	// NS returns the authoritative nameserver hostnames of domain.
	NS(ctx context.Context, domain string) ([]string, error)
	// Signed reports whether domain publishes a DNSKEY (zone is DNSSEC-signed).
	Signed(ctx context.Context, domain string) (bool, error)
	// AXFR attempts a full zone transfer of domain from ns and returns the
	// number of records the nameserver handed over (0 = refused/empty).
	AXFR(ctx context.Context, ns, domain string) (int, error)
}

// Check returns the DNSSEC/AXFR findings for a domain, using live DNS.
func Check(ctx context.Context, domain string) []model.Finding {
	return check(ctx, domain, newDNSQueryer())
}

func check(ctx context.Context, domain string, q queryer) []model.Finding {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if domain == "" {
		return nil
	}
	var out []model.Finding

	// DNSSEC: only report the positive (signed) as info. Absence is common and,
	// per scope, not worth a finding.
	if signed, err := q.Signed(ctx, domain); err == nil && signed {
		out = append(out, finding(domain, model.SeverityInfo,
			"DNSSEC enabled (zone signed)", map[string]any{"dnssec": true}))
	}

	// AXFR: try every nameserver; one misconfigured secondary is enough to leak
	// the whole zone.
	if nss, err := q.NS(ctx, domain); err == nil {
		seen := map[string]bool{}
		for _, ns := range nss {
			ns = strings.ToLower(strings.TrimSuffix(ns, "."))
			if ns == "" || seen[ns] {
				continue
			}
			seen[ns] = true
			if n, err := q.AXFR(ctx, ns, domain); err == nil && n > 0 {
				out = append(out, finding(domain, model.SeverityHigh,
					"DNS zone transfer (AXFR) allowed",
					map[string]any{"nameserver": ns, "records": n}))
			}
		}
	}
	return out
}

func finding(domain string, sev model.Severity, title string, ev map[string]any) model.Finding {
	return model.Finding{
		Scanner:  "dnssec",
		Target:   model.Target{Domain: domain},
		Severity: sev,
		Title:    title,
		Evidence: ev,
	}
}

// dnsQueryer is the live, miekg/dns-backed queryer.
type dnsQueryer struct {
	server  string // resolver address host:port for NS/DNSKEY lookups
	timeout time.Duration
}

func newDNSQueryer() *dnsQueryer {
	server := "8.8.8.8:53"
	if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
		server = net.JoinHostPort(cc.Servers[0], cc.Port)
	}
	return &dnsQueryer{server: server, timeout: 3 * time.Second}
}

func (q *dnsQueryer) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Timeout: q.timeout}
	resp, _, err := c.ExchangeContext(ctx, m, q.server)
	return resp, err
}

func (q *dnsQueryer) NS(ctx context.Context, domain string) ([]string, error) {
	resp, err := q.exchange(ctx, domain, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, ns.Ns)
		}
	}
	return out, nil
}

func (q *dnsQueryer) Signed(ctx context.Context, domain string) (bool, error) {
	resp, err := q.exchange(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		return false, err
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			return true, nil
		}
	}
	return false, nil
}

func (q *dnsQueryer) AXFR(_ context.Context, ns, domain string) (int, error) {
	t := &dns.Transfer{DialTimeout: q.timeout, ReadTimeout: q.timeout}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	env, err := t.In(m, net.JoinHostPort(ns, "53"))
	if err != nil {
		return 0, err
	}
	n := 0
	for e := range env {
		if e.Error != nil {
			return n, e.Error
		}
		n += len(e.RR)
	}
	return n, nil
}

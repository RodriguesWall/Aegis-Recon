// Package scope enforces the spy-bot safety rules as code: a discovered host is
// only probed if it belongs to the authorized domain (no pivot off-scope), and
// repeated hosts are de-duplicated. It also offers a simple per-host rate
// limiter for the probe phase.
package scope

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Scope is the allowlist for one engagement: the root domain and its
// subdomains. An optional denylist subtracts specific hosts that must never be
// probed even when they are in scope.
type Scope struct {
	root string
	deny []denyRule
}

// denyRule is one parsed blacklist entry. wildcard means the pattern was
// "*.base" and matches the base plus any subdomain of it; otherwise it matches
// the host exactly.
type denyRule struct {
	base     string
	wildcard bool
}

// New builds a scope for a root domain (case/space normalized).
func New(domain string) *Scope {
	return &Scope{root: normalize(domain)}
}

// Deny adds blacklist patterns to the scope and returns it (chainable). Each
// pattern is either an exact host ("example.com") or a wildcard ("*.example.com"
// — matches example.com and every subdomain). Empty/blank patterns are ignored.
func (s *Scope) Deny(patterns []string) *Scope {
	for _, p := range patterns {
		raw := strings.ToLower(strings.TrimSpace(p))
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "*.") {
			if base := normalize(raw); base != "" {
				s.deny = append(s.deny, denyRule{base: base, wildcard: true})
			}
			continue
		}
		if base := normalize(raw); base != "" {
			s.deny = append(s.deny, denyRule{base: base})
		}
	}
	return s
}

// denied reports whether host matches any blacklist rule.
func (s *Scope) denied(host string) bool {
	for _, d := range s.deny {
		if host == d.base {
			return true
		}
		if d.wildcard && strings.HasSuffix(host, "."+d.base) {
			return true
		}
	}
	return false
}

// InScope reports whether host is the root domain or a subdomain of it.
func (s *Scope) InScope(host string) bool {
	h := normalize(host)
	if h == "" || s.root == "" {
		return false
	}
	return h == s.root || strings.HasSuffix(h, "."+s.root)
}

// Filter normalizes, de-duplicates and keeps only in-scope hosts. This is the
// gate applied to discovery output before the probe phase.
func (s *Scope) Filter(hosts []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		n := normalize(h)
		if n == "" || seen[n] || !s.InScope(n) || s.denied(n) {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func normalize(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "*.") // wildcard certs
	h = strings.TrimSuffix(h, ".")  // trailing dot from DNS
	return h
}

// RateLimiter throttles probes per host to a minimum interval between calls.
// Zero interval disables throttling.
type RateLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	last     map[string]time.Time
}

// NewRateLimiter builds a limiter enforcing at most one call per interval per
// host.
func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{interval: interval, last: map[string]time.Time{}}
}

// Wait blocks until the host is allowed to be probed again, or ctx is done.
func (r *RateLimiter) Wait(ctx context.Context, host string) error {
	if r == nil || r.interval <= 0 {
		return nil
	}
	r.mu.Lock()
	now := time.Now()
	next := r.last[host]
	if next.Before(now) {
		next = now
	}
	r.last[host] = next.Add(r.interval)
	delay := time.Until(next)
	r.mu.Unlock()

	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Package subdomain discovers subdomains of a domain. It combines a passive
// source (crt.sh Certificate Transparency logs, no traffic to the target) with
// a capped, bounded-concurrency dictionary bruteforce via the injectable
// resolver. It implements model.Discoverer, not model.Scanner.
package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// defaultWords is a tiny built-in bruteforce list so the discoverer is
// self-contained. Override with WithWordlist for a real list.
var defaultWords = []string{
	"www", "api", "app", "dev", "staging", "stage", "test", "admin", "mail",
	"smtp", "webmail", "vpn", "ns1", "ns2", "cdn", "static", "assets", "img",
	"blog", "shop", "store", "portal", "dashboard", "auth", "login", "docs",
	"git", "gitlab", "jenkins", "grafana", "status", "beta", "demo",
}

// Discoverer finds subdomains.
type Discoverer struct {
	resolver    model.Resolver
	client      *http.Client
	words       []string
	bruteConc   int
	bruteCap    int
	passiveOnly bool

	// passive retry (crt.sh is slow and flaky).
	attempts int
	backoff  time.Duration

	// last-good passive cache, keyed by domain. crt.sh returns nothing often
	// enough that caching the last successful result keeps discovery stable
	// across scans instead of collapsing to brute-only when crt.sh is down.
	cacheMu  sync.Mutex
	cache    map[string]cacheEntry
	cacheTTL time.Duration
}

type cacheEntry struct {
	hosts []string
	at    time.Time
}

// Option configures the discoverer.
type Option func(*Discoverer)

// WithClient injects an HTTP client (tests pass httptest's client).
func WithClient(c *http.Client) Option { return func(d *Discoverer) { d.client = c } }

// WithWordlist overrides the bruteforce wordlist.
func WithWordlist(words []string) Option { return func(d *Discoverer) { d.words = words } }

// WithBruteConcurrency bounds concurrent brute resolutions.
func WithBruteConcurrency(n int) Option { return func(d *Discoverer) { d.bruteConc = n } }

// WithPassiveOnly disables the bruteforce pass.
func WithPassiveOnly() Option { return func(d *Discoverer) { d.passiveOnly = true } }

// WithRetries sets how many times the passive (crt.sh) fetch is attempted
// before giving up (default 3). Values < 1 are ignored.
func WithRetries(n int) Option {
	return func(d *Discoverer) {
		if n >= 1 {
			d.attempts = n
		}
	}
}

// WithBackoff sets the delay between passive attempts (default 2s). Tests set 0.
func WithBackoff(dly time.Duration) Option {
	return func(d *Discoverer) {
		if dly >= 0 {
			d.backoff = dly
		}
	}
}

// crtShURL is a variable so tests can point it at a fake server.
var crtShURL = "https://crt.sh/"

// New builds a subdomain discoverer using the given resolver.
func New(r model.Resolver, opts ...Option) *Discoverer {
	d := &Discoverer{
		resolver:  r,
		words:     defaultWords,
		bruteConc: 20,
		bruteCap:  2000,
		attempts:  3,
		backoff:   2 * time.Second,
		cache:     map[string]cacheEntry{},
		cacheTTL:  7 * 24 * time.Hour,
	}
	for _, o := range opts {
		o(d)
	}
	if d.client == nil {
		// crt.sh is slow; 30s per attempt, retried a few times (see passive).
		d.client = &http.Client{Timeout: 30 * time.Second}
	}
	return d
}

// Name implements model.Discoverer.
func (d *Discoverer) Name() string { return "subdomain" }

// Discover implements model.Discoverer: passive crt.sh plus optional brute.
// Sources are merged into a de-duplicated set. A failed passive source does not
// abort brute, and vice versa; an error is returned only if everything failed.
func (d *Discoverer) Discover(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("subdomain: empty domain")
	}

	set := map[string]bool{}
	var mu sync.Mutex
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimPrefix(h, "*.")
		if h == "" {
			return
		}
		mu.Lock()
		set[h] = true
		mu.Unlock()
	}

	names, passiveErr := d.passiveWithRetry(ctx, domain)
	if passiveErr == nil && len(names) > 0 {
		d.cacheStore(domain, names)
	} else if cached := d.cacheGet(domain); len(cached) > 0 {
		// crt.sh failed or returned nothing: fall back to the last good set so
		// discovery doesn't collapse to brute-only (which drops most hosts).
		names = cached
	}
	for _, n := range names {
		add(n)
	}

	if !d.passiveOnly {
		d.brute(ctx, domain, add)
	}

	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}

	if len(out) == 0 && passiveErr != nil {
		return nil, passiveErr
	}
	return out, nil
}

// passiveWithRetry runs passive up to d.attempts times with d.backoff between
// tries, since crt.sh is slow and intermittently unavailable.
func (d *Discoverer) passiveWithRetry(ctx context.Context, domain string) ([]string, error) {
	var lastErr error
	for i := 0; i < d.attempts; i++ {
		if i > 0 && d.backoff > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d.backoff):
			}
		}
		names, err := d.passive(ctx, domain)
		if err == nil {
			return names, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (d *Discoverer) cacheStore(domain string, hosts []string) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	d.cache[domain] = cacheEntry{hosts: append([]string(nil), hosts...), at: time.Now()}
}

func (d *Discoverer) cacheGet(domain string) []string {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	e, ok := d.cache[domain]
	if !ok || (d.cacheTTL > 0 && time.Since(e.at) > d.cacheTTL) {
		return nil
	}
	return append([]string(nil), e.hosts...)
}

// crtEntry is one record from the crt.sh JSON output.
type crtEntry struct {
	NameValue string `json:"name_value"`
}

// passive queries crt.sh Certificate Transparency logs. It touches crt.sh, not
// the target.
func (d *Discoverer) passive(ctx context.Context, domain string) ([]string, error) {
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	reqURL := strings.TrimRight(crtShURL, "/") + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("subdomain: build crt.sh request: %w", err)
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("subdomain: crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subdomain: crt.sh status %d", resp.StatusCode)
	}

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("subdomain: decode crt.sh: %w", err)
	}
	var names []string
	for _, e := range entries {
		// name_value may hold several names separated by newlines.
		names = append(names, strings.Split(e.NameValue, "\n")...)
	}
	return names, nil
}

// brute resolves word.domain for each word, keeping only names that resolve.
// Concurrency and list size are capped (anti-DoS, spy-bot rules).
func (d *Discoverer) brute(ctx context.Context, domain string, add func(string)) {
	words := d.words
	if len(words) > d.bruteCap {
		words = words[:d.bruteCap]
	}

	sem := make(chan struct{}, d.bruteConc)
	var wg sync.WaitGroup
	for _, w := range words {
		host := strings.ToLower(w) + "." + domain
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if addrs, err := d.resolver.LookupHost(ctx, host); err == nil && len(addrs) > 0 {
				add(host)
			}
		}(host)
	}
	wg.Wait()
}

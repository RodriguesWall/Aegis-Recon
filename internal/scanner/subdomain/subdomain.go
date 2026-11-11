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

// crtShURL is a variable so tests can point it at a fake server.
var crtShURL = "https://crt.sh/"

// New builds a subdomain discoverer using the given resolver.
func New(r model.Resolver, opts ...Option) *Discoverer {
	d := &Discoverer{
		resolver:  r,
		words:     defaultWords,
		bruteConc: 20,
		bruteCap:  2000,
	}
	for _, o := range opts {
		o(d)
	}
	if d.client == nil {
		d.client = &http.Client{Timeout: 15 * time.Second}
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

	passiveErr := d.passive(ctx, domain, add)
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

// crtEntry is one record from the crt.sh JSON output.
type crtEntry struct {
	NameValue string `json:"name_value"`
}

// passive queries crt.sh Certificate Transparency logs. It touches crt.sh, not
// the target.
func (d *Discoverer) passive(ctx context.Context, domain string, add func(string)) error {
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	reqURL := strings.TrimRight(crtShURL, "/") + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("subdomain: build crt.sh request: %w", err)
	}
	req.Header.Set("User-Agent", "Aegis-Recon/0.1 (+authorized-use-only)")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("subdomain: crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subdomain: crt.sh status %d", resp.StatusCode)
	}

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return fmt.Errorf("subdomain: decode crt.sh: %w", err)
	}
	for _, e := range entries {
		// name_value may hold several names separated by newlines.
		for _, name := range strings.Split(e.NameValue, "\n") {
			add(name)
		}
	}
	return nil
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

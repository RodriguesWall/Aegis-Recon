// Package engine orchestrates scanners over targets with bounded concurrency.
// F0 ships the minimal version: fan out (scanner x target) across a worker
// pool, collect findings safely, aggregate into a ScanResult.
package engine

import (
	"context"
	"sync"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// HostGate is called before each probe with the target host. It can block
// (rate limit) or return an error to skip that probe. scope.RateLimiter.Wait
// satisfies it. Kept as a func so the engine stays decoupled from the scope
// package.
type HostGate func(ctx context.Context, host string) error

// Reachable reports whether a host currently resolves. The pipeline uses it to
// drop dead discovery results (e.g. historical crt.sh subdomains) before the
// probe phase, so scanners are not run against non-resolving hosts.
type Reachable func(ctx context.Context, host string) bool

// Engine runs a set of scanners against a set of targets.
type Engine struct {
	scanners    []model.Scanner
	concurrency int
	gate        HostGate
	reachable   Reachable
}

// Option configures an Engine.
type Option func(*Engine)

// WithConcurrency bounds how many scanner/target jobs run at once. Values < 1
// fall back to 1.
func WithConcurrency(n int) Option {
	return func(e *Engine) {
		if n < 1 {
			n = 1
		}
		e.concurrency = n
	}
}

// WithHostGate installs a gate called before every probe (e.g. a per-host rate
// limiter). A gate error skips that probe and is recorded.
func WithHostGate(g HostGate) Option {
	return func(e *Engine) { e.gate = g }
}

// WithReachable installs a reachability check. In RunPipeline, discovered hosts
// that do not resolve are dropped before probing.
func WithReachable(r Reachable) Option {
	return func(e *Engine) { e.reachable = r }
}

// New builds an Engine from the given scanners.
func New(scanners []model.Scanner, opts ...Option) *Engine {
	e := &Engine{scanners: scanners, concurrency: 8}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Run executes every scanner against every target, bounded by concurrency.
// A scanner error is recorded in the result meta; it does not abort the others.
func (e *Engine) Run(ctx context.Context, domain string, targets []model.Target) model.ScanResult {
	start := time.Now()

	var (
		mu       sync.Mutex
		findings []model.Finding
	)
	emit := func(f model.Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	errs := e.fanout(ctx, targets, emit)

	end := time.Now()
	return model.ScanResult{
		Domain:   domain,
		Findings: findings,
		Meta: model.ScanMeta{
			StartedAt: start,
			EndedAt:   end,
			Duration:  end.Sub(start),
			Scanners:  scannerNames(e.scanners),
			Errors:    errs,
		},
	}
}

// HostFilter optionally normalizes and filters discovered hosts before the
// probe phase (e.g. scope.Filter — drops off-scope/duplicate hosts).
type HostFilter func([]string) []string

// RunPipeline runs discovery (phase 1) then probing (phase 2). Discoverers
// expand the domain into hosts; filter trims them to scope; then every scanner
// runs against every in-scope host. The root domain is always included.
func (e *Engine) RunPipeline(ctx context.Context, domain string, discoverers []model.Discoverer, filter HostFilter) model.ScanResult {
	start := time.Now()

	var (
		mu       sync.Mutex
		findings []model.Finding
		errs     []string
	)
	emit := func(f model.Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	// Phase 1: discovery (sequential; usually a single discoverer).
	hostSet := map[string]bool{domain: true}
	for _, d := range discoverers {
		hosts, err := d.Discover(ctx, domain)
		if err != nil {
			errs = append(errs, d.Name()+": "+err.Error())
			continue
		}
		for _, h := range hosts {
			hostSet[h] = true
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	if filter != nil {
		hosts = filter(hosts)
	}

	// Drop hosts that do not resolve (dead crt.sh entries), so the probe phase
	// is not run against them (avoids a flood of "no such host" errors).
	if e.reachable != nil {
		live, skipped := e.keepReachable(ctx, hosts)
		hosts = live
		if skipped > 0 {
			emit(model.Finding{
				Scanner:  "discovery",
				Target:   model.Target{Domain: domain},
				Severity: model.SeverityInfo,
				Title:    "skipped non-resolving hosts",
				Evidence: map[string]any{"count": skipped},
			})
		}
	}

	// Record each in-scope host and build the probe targets.
	targets := make([]model.Target, 0, len(hosts))
	for _, h := range hosts {
		emit(model.Finding{
			Scanner:  "discovery",
			Target:   model.Target{Domain: domain, Host: h},
			Severity: model.SeverityInfo,
			Title:    "host in scope",
			Evidence: map[string]any{"host": h},
		})
		targets = append(targets, model.Target{Domain: domain, Host: h, Port: 443})
	}

	// Phase 2: probe every host with every scanner.
	errs = append(errs, e.fanout(ctx, targets, emit)...)

	end := time.Now()
	return model.ScanResult{
		Domain:   domain,
		Findings: findings,
		Meta: model.ScanMeta{
			StartedAt: start,
			EndedAt:   end,
			Duration:  end.Sub(start),
			Scanners:  scannerNames(e.scanners),
			Errors:    errs,
		},
	}
}

// keepReachable concurrently checks each host and returns the resolving ones
// (sorted) plus the count dropped.
func (e *Engine) keepReachable(ctx context.Context, hosts []string) (live []string, skipped int) {
	type result struct {
		host string
		ok   bool
	}
	results := make([]result, len(hosts))

	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = result{host: h, ok: e.reachable(ctx, h)}
		}(i, h)
	}
	wg.Wait()

	for _, r := range results {
		if r.ok {
			live = append(live, r.host)
		} else {
			skipped++
		}
	}
	return live, skipped
}

// fanout runs every scanner against every target with bounded concurrency,
// emitting findings through emit. It returns the collected scanner errors.
// Shared by Run (single-phase) and RunPipeline (phase 2).
func (e *Engine) fanout(ctx context.Context, targets []model.Target, emit model.EmitFunc) []string {
	var (
		mu   sync.Mutex
		errs []string
	)
	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup

	for _, sc := range e.scanners {
		for _, t := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func(sc model.Scanner, t model.Target) {
				defer wg.Done()
				defer func() { <-sem }()
				// Rate-limit gate per host (anti-DoS). A gate error skips the probe.
				if e.gate != nil {
					host := t.Host
					if host == "" {
						host = t.Domain
					}
					if err := e.gate(ctx, host); err != nil {
						mu.Lock()
						errs = append(errs, sc.Name()+": gate: "+err.Error())
						mu.Unlock()
						return
					}
				}
				if err := sc.Scan(ctx, t, emit); err != nil {
					mu.Lock()
					errs = append(errs, sc.Name()+": "+err.Error())
					mu.Unlock()
				}
			}(sc, t)
		}
	}
	wg.Wait()
	return errs
}

func scannerNames(ss []model.Scanner) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Name())
	}
	return out
}

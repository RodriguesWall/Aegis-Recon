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

// Engine runs a set of scanners against a set of targets.
type Engine struct {
	scanners    []model.Scanner
	concurrency int
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
		errs     []string
	)
	emit := func(f model.Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup

	for _, sc := range e.scanners {
		for _, t := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func(sc model.Scanner, t model.Target) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := sc.Scan(ctx, t, emit); err != nil {
					mu.Lock()
					errs = append(errs, sc.Name()+": "+err.Error())
					mu.Unlock()
				}
			}(sc, t)
		}
	}
	wg.Wait()

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

func scannerNames(ss []model.Scanner) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Name())
	}
	return out
}

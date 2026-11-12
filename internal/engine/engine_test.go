package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/engine"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/noop"
)

// fakeScanner emits n findings and optionally returns an error.
type fakeScanner struct {
	name string
	n    int
	err  error
}

func (f fakeScanner) Name() string { return f.name }
func (f fakeScanner) Scan(_ context.Context, t model.Target, emit model.EmitFunc) error {
	for i := 0; i < f.n; i++ {
		emit(model.Finding{Scanner: f.name, Target: t, Severity: model.SeverityInfo, Title: "x"})
	}
	return f.err
}

func TestRun_AggregatesFindings(t *testing.T) {
	eng := engine.New([]model.Scanner{
		fakeScanner{name: "a", n: 2},
		fakeScanner{name: "b", n: 3},
	}, engine.WithConcurrency(4))

	targets := []model.Target{{Domain: "example.com"}, {Domain: "foo.com"}}
	res := eng.Run(context.Background(), "example.com", targets)

	// 2 scanners x 2 targets, emitting 2 and 3 => (2+3)*2 = 10
	if got, want := len(res.Findings), 10; got != want {
		t.Fatalf("findings = %d, want %d", got, want)
	}
	if len(res.Meta.Scanners) != 2 {
		t.Fatalf("meta scanners = %v", res.Meta.Scanners)
	}
	if len(res.Meta.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Meta.Errors)
	}
}

func TestRun_RecordsScannerError(t *testing.T) {
	eng := engine.New([]model.Scanner{
		fakeScanner{name: "ok", n: 1},
		fakeScanner{name: "bad", n: 0, err: errors.New("boom")},
	})
	res := eng.Run(context.Background(), "example.com", []model.Target{{Domain: "example.com"}})

	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if len(res.Meta.Errors) != 1 {
		t.Fatalf("errors = %v, want 1", res.Meta.Errors)
	}
}

func TestRun_HostGateSkipsBlockedHost(t *testing.T) {
	eng := engine.New([]model.Scanner{fakeScanner{name: "a", n: 1}},
		engine.WithHostGate(func(_ context.Context, host string) error {
			if host == "blocked.com" {
				return errors.New("rate limited")
			}
			return nil
		}))

	res := eng.Run(context.Background(), "x", []model.Target{
		{Host: "ok.com"},
		{Host: "blocked.com"},
	})

	// ok.com passes the gate and emits 1 finding; blocked.com is skipped.
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if len(res.Meta.Errors) != 1 {
		t.Fatalf("errors = %v, want 1 (gate)", res.Meta.Errors)
	}
}

func TestRun_NoopScanner(t *testing.T) {
	eng := engine.New([]model.Scanner{noop.New()})
	res := eng.Run(context.Background(), "example.com", []model.Target{{Domain: "example.com", Host: "example.com"}})
	if len(res.Findings) != 1 {
		t.Fatalf("noop findings = %d, want 1", len(res.Findings))
	}
	if res.Findings[0].Severity != model.SeverityInfo {
		t.Fatalf("severity = %q", res.Findings[0].Severity)
	}
}

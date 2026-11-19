package nuclei

import (
	"context"
	"os/exec"
	"testing"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

func collect(t *testing.T, s *Scanner, target model.Target) []model.Finding {
	t.Helper()
	var out []model.Finding
	if err := s.Scan(context.Background(), target, func(f model.Finding) { out = append(out, f) }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func TestScanParsesJSONL(t *testing.T) {
	const jsonl = `{"template-id":"tls-version","type":"ssl","host":"acme.example","matched-at":"acme.example:443","info":{"name":"TLS 1.0 enabled","severity":"medium","tags":["ssl","tls"]}}
not-json-skip-me
{"template-id":"exposed-panel","type":"http","host":"acme.example","matched-at":"https://acme.example/admin","info":{"name":"Admin panel exposed","severity":"high","tags":["panel"]}}`

	s := New(WithRunner(func(_ context.Context, _ string, _ []string) ([]byte, error) {
		return []byte(jsonl), nil
	}))
	got := collect(t, s, model.Target{Host: "acme.example", Port: 443})

	if len(got) != 2 {
		t.Fatalf("want 2 findings (bad line skipped), got %d: %+v", len(got), got)
	}
	if got[0].Scanner != "nuclei" || got[0].Severity != model.SeverityMedium || got[0].Title != "TLS 1.0 enabled" {
		t.Fatalf("finding 0 wrong: %+v", got[0])
	}
	if got[0].Evidence["template"] != "tls-version" || got[0].Evidence["matched_at"] != "acme.example:443" {
		t.Fatalf("evidence 0 wrong: %+v", got[0].Evidence)
	}
	if got[1].Severity != model.SeverityHigh {
		t.Fatalf("finding 1 severity wrong: %+v", got[1])
	}
}

func TestScanDegradesWhenBinaryMissing(t *testing.T) {
	s := New(WithRunner(func(_ context.Context, _ string, _ []string) ([]byte, error) {
		return nil, exec.ErrNotFound
	}))
	got := collect(t, s, model.Target{Host: "acme.example"})
	if len(got) != 0 {
		t.Fatalf("missing binary must yield no findings, got %+v", got)
	}
}

func TestScanNonZeroExitWithOutputStillParses(t *testing.T) {
	const jsonl = `{"template-id":"x","host":"h","info":{"name":"Something","severity":"low"}}`
	s := New(WithRunner(func(_ context.Context, _ string, _ []string) ([]byte, error) {
		return []byte(jsonl), &exec.ExitError{} // non-zero exit but produced output
	}))
	got := collect(t, s, model.Target{Host: "h"})
	if len(got) != 1 || got[0].Severity != model.SeverityLow {
		t.Fatalf("want 1 low finding, got %+v", got)
	}
}

func TestScanNoHostNoop(t *testing.T) {
	s := New(WithRunner(func(_ context.Context, _ string, _ []string) ([]byte, error) {
		t.Fatal("runner must not be called without a host")
		return nil, nil
	}))
	if got := collect(t, s, model.Target{}); len(got) != 0 {
		t.Fatalf("empty target must be a no-op, got %+v", got)
	}
}

func TestArgsLocked(t *testing.T) {
	args := New().args("acme.example")
	for _, want := range []string{"-jsonl", "dos,intrusive,fuzzing", "-rate-limit", "150", "-duc"} {
		if !contains(args, want) {
			t.Fatalf("args missing %q: %v", want, args)
		}
	}
	if contains(args, "-t") {
		t.Fatalf("templates dir should be absent by default: %v", args)
	}
}

func TestArgsIntrusive(t *testing.T) {
	args := New(WithIntrusive(true)).args("acme.example")
	// intrusive/fuzzing allowed, but DoS still excluded, and DAST enabled.
	if !contains(args, "dos") || contains(args, "dos,intrusive,fuzzing") {
		t.Fatalf("intrusive must exclude only dos: %v", args)
	}
	if !contains(args, "-dast") {
		t.Fatalf("intrusive must enable -dast: %v", args)
	}
	// Non-intrusive keeps the locked exclusion and no -dast.
	normal := New().args("acme.example")
	if contains(normal, "-dast") || !contains(normal, "dos,intrusive,fuzzing") {
		t.Fatalf("non-intrusive must keep locked profile: %v", normal)
	}
}

func TestArgsWithTemplates(t *testing.T) {
	args := New(WithTemplates("/opt/nuclei-templates")).args("h")
	if !contains(args, "-t") || !contains(args, "/opt/nuclei-templates") {
		t.Fatalf("templates dir not passed: %v", args)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

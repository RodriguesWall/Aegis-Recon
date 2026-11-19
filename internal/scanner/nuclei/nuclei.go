// Package nuclei adapts the external `nuclei` engine (ProjectDiscovery) into a
// model.Scanner. It shells out to the nuclei binary, parses its JSONL output and
// maps each result to a model.Finding.
//
// This is the one deliberate exception to the project's pure-Go recon rule: it
// runs an external binary and performs active vulnerability checks. It stays
// bounded by a locked safety profile (no dos/intrusive/fuzzing templates, a
// rate limit and a per-host timeout) and degrades to a no-op when the binary is
// absent, so a scan never fails just because nuclei is not installed.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Runner executes the nuclei binary and returns its stdout. Injected in tests.
type Runner func(ctx context.Context, bin string, args []string) ([]byte, error)

// Scanner runs nuclei against a single host.
type Scanner struct {
	bin       string
	templates string // optional -templates-directory (e.g. a baked image path)
	intrusive bool   // relax the safety profile (authorized-use only)
	runner    Runner
}

// Option configures the scanner.
type Option func(*Scanner)

// WithBin overrides the binary name/path (default "nuclei").
func WithBin(bin string) Option {
	return func(s *Scanner) {
		if bin != "" {
			s.bin = bin
		}
	}
}

// WithTemplates sets an explicit templates directory (passed as
// -templates-directory). Useful when templates are baked into an image and the
// process runs without network access to fetch them.
func WithTemplates(dir string) Option {
	return func(s *Scanner) {
		if dir != "" {
			s.templates = dir
		}
	}
}

// WithIntrusive relaxes the safety profile: it allows the intrusive/fuzzing
// template classes and enables DAST fuzzing. DoS templates stay excluded.
// Authorized-use only; off by default.
func WithIntrusive(on bool) Option { return func(s *Scanner) { s.intrusive = on } }

// WithRunner injects a custom runner (tests pass canned JSONL).
func WithRunner(r Runner) Option { return func(s *Scanner) { s.runner = r } }

// New builds a nuclei scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{bin: "nuclei", runner: execRunner}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Scanner) Name() string { return "nuclei" }

// Available reports whether the nuclei binary can be found on PATH. scansvc uses
// it to decide whether to include the scanner in a run.
func Available(bin string) bool {
	if bin == "" {
		bin = "nuclei"
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// args is the locked safety profile: skip destructive/noisy template classes,
// floor the severity at low, rate-limit, and cap per-host time. Active checks,
// but bounded — in the spirit of the project's no-DoS rules.
//
// In intrusive mode the intrusive/fuzzing classes are allowed and DAST fuzzing
// is enabled (-dast), so active checks like user enumeration can run. DoS
// templates stay excluded either way (anti-DoS rule); the rate limit and
// per-host timeout are unchanged.
func (s *Scanner) args(target string) []string {
	excludeTags := "dos,intrusive,fuzzing"
	if s.intrusive {
		excludeTags = "dos"
	}
	a := []string{
		"-u", target,
		"-jsonl",  // one JSON object per line
		"-silent", // results only, no banner
		"-nc",     // no color
		"-duc",    // disable auto-update check (no surprise network/templates fetch)
		"-exclude-tags", excludeTags,
		"-severity", "low,medium,high,critical",
		"-rate-limit", "150",
		"-timeout", "10",
	}
	if s.intrusive {
		a = append(a, "-dast") // enable DAST/fuzzing templates (user-enum etc.)
	}
	if s.templates != "" {
		a = append(a, "-t", s.templates) // run templates from this directory
	}
	return a
}

// Scan runs nuclei against the target host and emits a finding per result. A
// missing binary (or a fatal launch error) degrades to no findings and no error,
// so the overall scan still completes.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	host := t.Host
	if host == "" {
		host = t.Domain
	}
	if host == "" {
		return nil
	}

	out, err := s.runner(ctx, s.bin, s.args(host))
	if err != nil {
		// Binary not installed: degrade silently (feature is optional).
		if errors.Is(err, exec.ErrNotFound) {
			return nil
		}
		// A non-zero exit can still carry useful stdout (parsed below). Only bail
		// when nothing was produced.
		if len(bytes.TrimSpace(out)) == 0 {
			return nil
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r result
		if json.Unmarshal(line, &r) != nil {
			continue // skip non-JSON / malformed lines
		}
		if f, ok := r.toFinding(t); ok {
			emit(f)
		}
	}
	return nil
}

func execRunner(ctx context.Context, bin string, args []string) ([]byte, error) {
	// Output() returns stdout; on a non-zero exit it still returns what was
	// written, with the error carrying stderr.
	return exec.CommandContext(ctx, bin, args...).Output()
}

// result is the subset of nuclei's JSONL record this adapter consumes.
type result struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
}

func (r result) toFinding(t model.Target) (model.Finding, bool) {
	title := strings.TrimSpace(r.Info.Name)
	if title == "" {
		title = r.TemplateID
	}
	if title == "" {
		return model.Finding{}, false
	}
	ev := map[string]any{"template": r.TemplateID}
	if r.MatchedAt != "" {
		ev["matched_at"] = r.MatchedAt
	}
	if r.Type != "" {
		ev["type"] = r.Type
	}
	if len(r.Info.Tags) > 0 {
		ev["tags"] = strings.Join(r.Info.Tags, ",")
	}
	return model.Finding{
		Scanner:  "nuclei",
		Target:   t,
		Severity: mapSeverity(r.Info.Severity),
		Title:    title,
		Evidence: ev,
	}, true
}

func mapSeverity(s string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

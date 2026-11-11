// Package noop provides a trivial Scanner used to prove the engine end-to-end
// in F0. It performs no network I/O.
package noop

import (
	"context"

	"github.com/RodriguesWall/aegis-recon/internal/model"
)

// Scanner emits a single info finding for the target. It exists only to
// validate the engine contract before real modules land in F1.
type Scanner struct{}

// New returns a noop scanner.
func New() *Scanner { return &Scanner{} }

// Name implements model.Scanner.
func (s *Scanner) Name() string { return "noop" }

// Scan implements model.Scanner.
func (s *Scanner) Scan(ctx context.Context, t model.Target, emit model.EmitFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	emit(model.Finding{
		Scanner:  s.Name(),
		Target:   t,
		Severity: model.SeverityInfo,
		Title:    "noop scanner reached target",
		Evidence: map[string]any{"domain": t.Domain, "host": t.Host},
	})
	return nil
}

package model

import "context"

// Discoverer finds hosts belonging to a domain (e.g. subdomain enumeration).
// It is a different role from Scanner: a Scanner analyzes one target and emits
// findings, while a Discoverer expands a domain into the targets that scanners
// will later probe. The engine runs discoverers in phase 1 and scanners in
// phase 2 (see Engine.RunPipeline).
type Discoverer interface {
	// Name is a stable identifier used in logs and findings.
	Name() string
	// Discover returns the hosts found for the domain. An empty result is not
	// an error; a failed source is.
	Discover(ctx context.Context, domain string) ([]string, error)
}

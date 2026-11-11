package model

import (
	"context"
	"net"
)

// EmitFunc receives findings as a scanner produces them. Implementations must
// be safe to call from multiple goroutines; the engine provides a safe emitter.
type EmitFunc func(Finding)

// Scanner is the single contract every scan module implements — native modules
// and (in V2) external-engine adapters alike. The engine does not know or care
// which kind it is running.
type Scanner interface {
	// Name is a stable identifier used in findings and logs.
	Name() string
	// Scan runs against one target, emitting findings as they are found.
	// It must honor ctx for cancellation/timeout and must not panic.
	Scan(ctx context.Context, t Target, emit EmitFunc) error
}

// Resolver abstracts DNS lookups so scanners can be tested without a network.
// Production uses the stdlib net.Resolver; tests inject a fake.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Dialer abstracts outbound TCP so port/tls scanners can be tested without a
// network. Production uses net.Dialer; tests inject a fake.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Deps bundles the injectable dependencies handed to scanners.
type Deps struct {
	Resolver Resolver
	Dialer   Dialer
}

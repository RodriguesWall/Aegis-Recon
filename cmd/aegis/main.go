// Command aegis is the Aegis-Recon CLI. F0 ships a single `scan` subcommand
// wired to the noop scanner to prove the engine end-to-end. Real modules and
// cobra-based flags arrive in F1.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/engine"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/dns"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/fingerprint"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/httpprobe"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/port"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/subdomain"
	tlsscan "github.com/RodriguesWall/aegis-recon/internal/scanner/tls"
	"github.com/RodriguesWall/aegis-recon/internal/scope"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: aegis scan <domain>")
		os.Exit(2)
	}
	domain := os.Args[2]

	// PreferGo uses the pure-Go resolver instead of the system cgo resolver,
	// which can crash on macOS under many concurrent lookups.
	resolver := &net.Resolver{PreferGo: true}
	dialer := &net.Dialer{}

	// Phase 1 discoverers.
	discoverers := []model.Discoverer{
		subdomain.New(resolver),
	}
	// Same safety rules as the API: per-host rate limit (anti-DoS).
	limiter := scope.NewRateLimiter(200 * time.Millisecond)
	// Phase 2 scanners.
	eng := engine.New([]model.Scanner{
		dns.New(resolver),
		port.New(dialer),
		tlsscan.New(),
		httpprobe.New(),
		fingerprint.New(),
	}, engine.WithHostGate(limiter.Wait))
	// Safety gate: only probe hosts within the domain's scope.
	sc := scope.New(domain)

	result := eng.RunPipeline(context.Background(), domain, discoverers, sc.Filter)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

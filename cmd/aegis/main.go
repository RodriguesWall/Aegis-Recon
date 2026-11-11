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

	"github.com/RodriguesWall/aegis-recon/internal/engine"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/dns"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/fingerprint"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/httpprobe"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/port"
	tlsscan "github.com/RodriguesWall/aegis-recon/internal/scanner/tls"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: aegis scan <domain>")
		os.Exit(2)
	}
	domain := os.Args[2]

	resolver := &net.Resolver{}
	dialer := &net.Dialer{}
	eng := engine.New([]model.Scanner{
		dns.New(resolver),
		port.New(dialer),
		tlsscan.New(),
		httpprobe.New(),
		fingerprint.New(),
	})
	targets := []model.Target{{Domain: domain, Host: domain, Port: 443}}

	result := eng.Run(context.Background(), domain, targets)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

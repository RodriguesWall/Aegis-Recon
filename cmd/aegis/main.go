// Command aegis is the Aegis-Recon CLI. F0 ships a single `scan` subcommand
// wired to the noop scanner to prove the engine end-to-end. Real modules and
// cobra-based flags arrive in F1.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/RodriguesWall/aegis-recon/internal/engine"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/noop"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: aegis scan <domain>")
		os.Exit(2)
	}
	domain := os.Args[2]

	eng := engine.New([]model.Scanner{noop.New()})
	targets := []model.Target{{Domain: domain, Host: domain}}

	result := eng.Run(context.Background(), domain, targets)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

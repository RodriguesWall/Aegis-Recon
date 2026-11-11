// Package scansvc runs the full lifecycle of one scan: load it, move it through
// the state machine (PENDING -> PROCESSING -> COMPLETED/FAILED), run the engine
// pipeline and persist the findings. It is the handler the queue workers call.
package scansvc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
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
	"github.com/RodriguesWall/aegis-recon/internal/store"
)

// Service owns the (stateless) scanners and discoverers and runs scans.
type Service struct {
	store       store.Store
	scanners    []model.Scanner
	discoverers []model.Discoverer
	logger      *slog.Logger
}

// New builds the service with the F1 surface scanners and the subdomain
// discoverer. The pure-Go resolver avoids the macOS cgo resolver crash.
func New(st store.Store, logger *slog.Logger) *Service {
	resolver := &net.Resolver{PreferGo: true}
	dialer := &net.Dialer{}
	return &Service{
		store: st,
		scanners: []model.Scanner{
			dns.New(resolver),
			port.New(dialer),
			tlsscan.New(),
			httpprobe.New(),
			fingerprint.New(),
		},
		discoverers: []model.Discoverer{subdomain.New(resolver)},
		logger:      logger,
	}
}

// Run executes the scan identified by scanID. It is safe to call from a worker
// goroutine and never panics out (a panic is converted to a FAILED scan).
func (s *Service) Run(ctx context.Context, scanID string) (err error) {
	scan, err := s.store.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("scansvc: load scan %s: %w", scanID, err)
	}
	asset, err := s.store.GetAsset(ctx, scan.AssetID)
	if err != nil {
		s.fail(ctx, scan, fmt.Errorf("load asset: %w", err))
		return err
	}

	// Guard against a scanner/discoverer panic taking down the worker.
	defer func() {
		if r := recover(); r != nil {
			s.fail(ctx, scan, fmt.Errorf("panic: %v", r))
			err = fmt.Errorf("scansvc: panic in scan %s: %v", scanID, r)
		}
	}()

	// PENDING -> PROCESSING.
	now := time.Now()
	scan.Status = model.StatusProcessing
	scan.StartedAt = &now
	if e := s.store.UpdateScan(ctx, scan); e != nil {
		return fmt.Errorf("scansvc: mark processing: %w", e)
	}

	domain := asset.Name
	eng := engine.New(s.scanners)
	sc := scope.New(domain)
	result := eng.RunPipeline(ctx, domain, s.discoverers, sc.Filter)

	if e := s.store.SaveFindings(ctx, scanID, result.Findings); e != nil {
		s.fail(ctx, scan, fmt.Errorf("save findings: %w", e))
		return e
	}

	// -> COMPLETED (scanner errors are recorded but do not fail the scan).
	done := time.Now()
	scan.Status = model.StatusCompleted
	scan.CompletedAt = &done
	if len(result.Meta.Errors) > 0 {
		scan.Error = strings.Join(result.Meta.Errors, "; ")
	}
	if e := s.store.UpdateScan(ctx, scan); e != nil {
		return fmt.Errorf("scansvc: mark completed: %w", e)
	}

	if s.logger != nil {
		s.logger.Info("scan completed", "scan", scanID, "domain", domain,
			"findings", len(result.Findings), "errors", len(result.Meta.Errors))
	}
	return nil
}

// fail transitions the scan to FAILED with the error message. Best effort.
func (s *Service) fail(ctx context.Context, scan *model.Scan, cause error) {
	done := time.Now()
	scan.Status = model.StatusFailed
	scan.CompletedAt = &done
	scan.Error = cause.Error()
	if e := s.store.UpdateScan(ctx, scan); e != nil && s.logger != nil {
		s.logger.Error("mark failed", "scan", scan.ID, "err", e)
	}
}

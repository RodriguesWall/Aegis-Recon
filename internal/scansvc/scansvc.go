// Package scansvc runs the full lifecycle of one scan: load it, move it through
// the state machine (PENDING -> PROCESSING -> COMPLETED/FAILED), run the engine
// pipeline and persist the findings. It is the handler the queue workers call.
package scansvc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/engine"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/notify"
	"github.com/RodriguesWall/aegis-recon/internal/progress"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/cdn"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/cors"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/dns"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/emailposture"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/exposedfiles"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/fingerprint"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/httpprobe"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/nuclei"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/port"
	"github.com/RodriguesWall/aegis-recon/internal/scanner/subdomain"
	tlsscan "github.com/RodriguesWall/aegis-recon/internal/scanner/tls"
	"github.com/RodriguesWall/aegis-recon/internal/scope"
	"github.com/RodriguesWall/aegis-recon/internal/store"
)

// Service owns the (stateless) scanners and discoverers and runs scans.
type Service struct {
	store           store.Store
	tracker         *progress.Tracker
	resolver        *net.Resolver
	scanners        []model.Scanner
	discoverers     []model.Discoverer
	nucleiBin       string
	nucleiTemplates string
	notifier        *notify.Service
	logger          *slog.Logger
}

// New builds the service with the F1 surface scanners and the subdomain
// discoverer. The pure-Go resolver avoids the macOS cgo resolver crash.
func New(st store.Store, tracker *progress.Tracker, logger *slog.Logger) *Service {
	resolver := &net.Resolver{PreferGo: true}
	dialer := &net.Dialer{}
	return &Service{
		store:    st,
		tracker:  tracker,
		resolver: resolver,
		scanners: []model.Scanner{
			dns.New(resolver),
			port.New(dialer),
			tlsscan.New(),
			httpprobe.New(),
			fingerprint.New(),
			cdn.New(resolver),
			exposedfiles.New(),
			cors.New(),
		},
		discoverers:     []model.Discoverer{subdomain.New(resolver)},
		nucleiBin:       envOr("AEGIS_NUCLEI_BIN", "nuclei"),
		nucleiTemplates: os.Getenv("AEGIS_NUCLEI_TEMPLATES"),
		notifier:        notify.New(st, logger),
		logger:          logger,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// reachable reports whether a host resolves to at least one address.
func (s *Service) reachable(ctx context.Context, host string) bool {
	addrs, err := s.resolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
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
	// Live progress for the dashboard to poll.
	if s.tracker != nil {
		s.tracker.Start(scanID)
	}
	prog := func(ev engine.ProgressEvent) {
		if s.tracker == nil {
			return
		}
		s.tracker.SetProgress(scanID, ev.Phase, ev.Done, ev.Total)
		if ev.Msg != "" {
			s.tracker.Log(scanID, ev.Msg)
		}
	}
	// Build the scanner set for this run. Nuclei is opt-in per scan (default on)
	// and only added when its binary is present, so it degrades cleanly.
	scanners := s.scanners
	if scan.UseNuclei && nuclei.Available(s.nucleiBin) {
		scanners = append(append([]model.Scanner{}, s.scanners...),
			nuclei.New(nuclei.WithBin(s.nucleiBin), nuclei.WithTemplates(s.nucleiTemplates)))
		if s.logger != nil {
			s.logger.Info("nuclei enabled for scan", "scan", scanID)
		}
	}

	// Per-host rate limit (anti-DoS): at most one probe per host every 200ms.
	limiter := scope.NewRateLimiter(200 * time.Millisecond)
	eng := engine.New(scanners,
		engine.WithHostGate(limiter.Wait),
		engine.WithReachable(s.reachable),
		engine.WithProgress(prog),
	)
	sc := scope.New(domain).Deny(asset.Blacklist)
	result := eng.RunPipeline(ctx, domain, s.discoverers, sc.Filter)

	findings := result.Findings
	// Domain-level email posture (SPF/DMARC/DKIM): checked once on the root
	// domain, not per host.
	findings = append(findings, emailposture.Check(ctx, domain, s.resolver)...)
	if !scan.IncludeInfo {
		findings = dropInfo(findings)
	}
	if e := s.store.SaveFindings(ctx, scanID, findings); e != nil {
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
	if s.tracker != nil {
		s.tracker.Done(scanID)
	}

	// Retention: keep the newest N scans per asset (default 30; 0 = unlimited).
	keep := 30
	if v, ok, _ := s.store.GetSetting(ctx, "retention_keep"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			keep = n
		}
	}
	if keep > 0 {
		if n, err := s.store.PruneScans(ctx, scan.AssetID, keep); err != nil {
			if s.logger != nil {
				s.logger.Error("prune scans", "asset", scan.AssetID, "err", err)
			}
		} else if n > 0 && s.logger != nil {
			s.logger.Info("pruned old scans", "asset", scan.AssetID, "deleted", n, "keep", keep)
		}
	}

	if s.logger != nil {
		s.logger.Info("scan completed", "scan", scanID, "domain", domain,
			"findings", len(result.Findings), "errors", len(result.Meta.Errors))
	}

	// Best-effort notification (email/webhook), decoupled from the scan result.
	// Uses a background context so it is not cancelled when this job's ctx ends.
	if s.notifier != nil {
		completed := *scan
		notifyFindings := append([]model.Finding(nil), findings...)
		go s.notifier.ScanComplete(context.Background(), &completed, notifyFindings)
	}
	return nil
}

// dropInfo returns only findings above info severity.
func dropInfo(fs []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Severity != model.SeverityInfo {
			out = append(out, f)
		}
	}
	return out
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
	if s.tracker != nil {
		s.tracker.Done(scan.ID)
	}
}

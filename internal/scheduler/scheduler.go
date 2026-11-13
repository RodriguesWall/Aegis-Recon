// Package scheduler runs automatic scans at each asset's configured interval.
// A ticker wakes periodically, finds due schedules and enqueues a scan for each
// (the same path as the "Run scan" button), then advances next_run.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/store"
	"github.com/google/uuid"
)

// Enqueuer accepts a scan ID for background processing (satisfied by queue.Queue).
type Enqueuer interface {
	Enqueue(scanID string)
}

// Scheduler enqueues due scheduled scans.
type Scheduler struct {
	store  store.Store
	q      Enqueuer
	logger *slog.Logger
	tick   time.Duration
	now    func() time.Time
}

// Option configures the scheduler.
type Option func(*Scheduler)

// WithTick sets how often the scheduler checks for due schedules (default 30s).
func WithTick(d time.Duration) Option {
	return func(s *Scheduler) {
		if d > 0 {
			s.tick = d
		}
	}
}

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Scheduler) {
		if now != nil {
			s.now = now
		}
	}
}

// New builds a scheduler.
func New(st store.Store, q Enqueuer, logger *slog.Logger, opts ...Option) *Scheduler {
	s := &Scheduler{store: st, q: q, logger: logger, tick: 30 * time.Second, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Run blocks, checking for due schedules every tick until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.RunDue(ctx, s.now()); err != nil && s.logger != nil {
				s.logger.Error("scheduler tick failed", "err", err)
			}
		}
	}
}

// RunDue enqueues a scan for every schedule due at now and advances each
// next_run by its interval. If the asset already has an active scan the round is
// skipped (no new scan) but next_run still advances, so schedules do not pile up.
// Returns the number of scans enqueued.
func (s *Scheduler) RunDue(ctx context.Context, now time.Time) (int, error) {
	due, err := s.store.ListDueSchedules(ctx, now)
	if err != nil {
		return 0, err
	}
	enqueued := 0
	for _, sc := range due {
		active, err := s.store.HasActiveScan(ctx, sc.AssetID)
		if err != nil {
			return enqueued, err
		}
		if !active {
			scan := &model.Scan{
				ID:        uuid.NewString(),
				AssetID:   sc.AssetID,
				Type:      model.ScanSurface,
				Status:    model.StatusPending,
				CreatedAt: now.UTC(),
			}
			if err := s.store.CreateScan(ctx, scan); err != nil {
				return enqueued, err
			}
			s.q.Enqueue(scan.ID)
			enqueued++
			if s.logger != nil {
				s.logger.Info("scheduled scan enqueued", "asset", sc.AssetID, "scan", scan.ID)
			}
		} else if s.logger != nil {
			s.logger.Info("scheduled scan skipped (asset busy)", "asset", sc.AssetID)
		}

		sc.NextRun = now.Add(time.Duration(sc.IntervalMinutes) * time.Minute)
		sc.UpdatedAt = now.UTC()
		if err := s.store.SetSchedule(ctx, &sc); err != nil {
			return enqueued, err
		}
	}
	return enqueued, nil
}

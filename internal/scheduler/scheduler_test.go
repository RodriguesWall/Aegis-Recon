package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/store/memory"
)

type fakeQueue struct{ ids []string }

func (f *fakeQueue) Enqueue(id string) { f.ids = append(f.ids, id) }

func setup(t *testing.T) (*memory.Store, *fakeQueue) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	st.CreateProject(ctx, &model.Project{ID: "p1", Name: "P", CreatedAt: time.Now()})
	st.CreateAsset(ctx, &model.Asset{ID: "a1", ProjectID: "p1", Type: model.AssetDomain, Name: "example.com", CreatedAt: time.Now()})
	return st, &fakeQueue{}
}

func TestRunDue_EnqueuesAndAdvances(t *testing.T) {
	ctx := context.Background()
	st, q := setup(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Due 1 minute ago, 60-minute interval.
	st.SetSchedule(ctx, &model.Schedule{AssetID: "a1", IntervalMinutes: 60, NextRun: now.Add(-time.Minute), Enabled: true, UpdatedAt: now})

	s := New(st, q, nil, WithClock(func() time.Time { return now }))
	n, err := s.RunDue(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("RunDue = %d, %v; want 1, nil", n, err)
	}
	if len(q.ids) != 1 {
		t.Fatalf("expected 1 enqueued, got %v", q.ids)
	}
	got, _ := st.GetSchedule(ctx, "a1")
	if !got.NextRun.Equal(now.Add(60 * time.Minute)) {
		t.Fatalf("next_run not advanced: %v", got.NextRun)
	}
}

func TestRunDue_SkipsWhenActiveScan(t *testing.T) {
	ctx := context.Background()
	st, q := setup(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	st.CreateScan(ctx, &model.Scan{ID: "s-active", AssetID: "a1", Type: model.ScanSurface, Status: model.StatusProcessing, CreatedAt: now})
	st.SetSchedule(ctx, &model.Schedule{AssetID: "a1", IntervalMinutes: 60, NextRun: now.Add(-time.Minute), Enabled: true, UpdatedAt: now})

	s := New(st, q, nil, WithClock(func() time.Time { return now }))
	n, err := s.RunDue(ctx, now)
	if err != nil || n != 0 {
		t.Fatalf("RunDue = %d, %v; want 0, nil (skipped)", n, err)
	}
	if len(q.ids) != 0 {
		t.Fatalf("expected nothing enqueued, got %v", q.ids)
	}
	// next_run still advances so it does not retry every tick.
	got, _ := st.GetSchedule(ctx, "a1")
	if !got.NextRun.Equal(now.Add(60 * time.Minute)) {
		t.Fatalf("next_run should advance even when skipped: %v", got.NextRun)
	}
}

func TestRunDue_IgnoresDisabledAndFuture(t *testing.T) {
	ctx := context.Background()
	st, q := setup(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// Disabled.
	st.SetSchedule(ctx, &model.Schedule{AssetID: "a1", IntervalMinutes: 60, NextRun: now.Add(-time.Hour), Enabled: false, UpdatedAt: now})

	s := New(st, q, nil, WithClock(func() time.Time { return now }))
	n, _ := s.RunDue(ctx, now)
	if n != 0 || len(q.ids) != 0 {
		t.Fatalf("disabled schedule must not run: n=%d ids=%v", n, q.ids)
	}
}

package queue_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/queue"
)

func TestQueue_ProcessesJobs(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	done := make(chan struct{}, 3)

	q := queue.New(func(_ context.Context, id string) error {
		mu.Lock()
		seen[id] = true
		mu.Unlock()
		done <- struct{}{}
		return nil
	}, queue.WithWorkers(2))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	for _, id := range []string{"a", "b", "c"} {
		q.Enqueue(id)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for jobs")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, id := range []string{"a", "b", "c"} {
		if !seen[id] {
			t.Errorf("job %q not processed", id)
		}
	}
	if got := q.Stats()["completed"].(int64); got != 3 {
		t.Errorf("completed = %d, want 3", got)
	}
}

func TestQueue_CountsFailures(t *testing.T) {
	done := make(chan struct{}, 1)
	q := queue.New(func(context.Context, string) error {
		defer func() { done <- struct{}{} }()
		return errors.New("boom")
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q.Start(ctx)

	q.Enqueue("x")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	// Give the worker a moment to record the counter after the handler returns.
	time.Sleep(50 * time.Millisecond)
	if got := q.Stats()["failed"].(int64); got != 1 {
		t.Errorf("failed = %d, want 1", got)
	}
}

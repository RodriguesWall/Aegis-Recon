// Package queue is an in-memory job queue: a buffered channel of scan IDs drained
// by a fixed set of worker goroutines, each calling a Handler. It is not durable
// (jobs live only in memory); aegisd re-enqueues PENDING scans on boot to recover
// from a restart.
package queue

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// Handler processes one scan ID. Returning an error is logged; the worker keeps
// running.
type Handler func(ctx context.Context, scanID string) error

// Queue holds the channel, workers and counters.
type Queue struct {
	ch      chan string
	handler Handler
	workers int
	logger  *slog.Logger

	enqueued  atomic.Int64
	completed atomic.Int64
	failed    atomic.Int64
}

// Option configures the queue.
type Option func(*Queue)

// WithWorkers sets how many worker goroutines drain the queue.
func WithWorkers(n int) Option {
	return func(q *Queue) {
		if n > 0 {
			q.workers = n
		}
	}
}

// WithBuffer sets the channel buffer size.
func WithBuffer(n int) Option {
	return func(q *Queue) {
		if n > 0 {
			q.ch = make(chan string, n)
		}
	}
}

// WithLogger attaches a logger.
func WithLogger(l *slog.Logger) Option { return func(q *Queue) { q.logger = l } }

// New builds a queue with one worker and a 256-slot buffer by default.
func New(h Handler, opts ...Option) *Queue {
	q := &Queue{ch: make(chan string, 256), handler: h, workers: 1}
	for _, o := range opts {
		o(q)
	}
	return q
}

// Start launches the worker goroutines. They stop when ctx is cancelled.
func (q *Queue) Start(ctx context.Context) {
	for i := 0; i < q.workers; i++ {
		go q.worker(ctx)
	}
}

func (q *Queue) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-q.ch:
			if err := q.handler(ctx, id); err != nil {
				q.failed.Add(1)
				if q.logger != nil {
					q.logger.Error("scan job failed", "scan", id, "err", err)
				}
				continue
			}
			q.completed.Add(1)
		}
	}
}

// Enqueue adds a scan ID without blocking the caller (e.g. an HTTP handler). If
// the buffer is full the send happens in a goroutine.
func (q *Queue) Enqueue(scanID string) {
	q.enqueued.Add(1)
	select {
	case q.ch <- scanID:
	default:
		go func() { q.ch <- scanID }()
	}
}

// Stats returns counters for the health endpoint.
func (q *Queue) Stats() map[string]any {
	return map[string]any{
		"workers":   q.workers,
		"pending":   len(q.ch),
		"enqueued":  q.enqueued.Load(),
		"completed": q.completed.Load(),
		"failed":    q.failed.Load(),
	}
}

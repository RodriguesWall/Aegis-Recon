// Command aegisd is the Aegis-Recon HTTP API daemon. It wires the SQLite store,
// the scan service, an in-memory job queue and the HTTP API, then serves them.
// On boot it re-enqueues any scans left PENDING by a previous run.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/RodriguesWall/aegis-recon/internal/api"
	"github.com/RodriguesWall/aegis-recon/internal/model"
	"github.com/RodriguesWall/aegis-recon/internal/queue"
	"github.com/RodriguesWall/aegis-recon/internal/scansvc"
	"github.com/RodriguesWall/aegis-recon/internal/store/sqlite"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	addr := envOr("AEGIS_ADDR", "127.0.0.1:8080")
	dbPath := envOr("AEGIS_DB", filepath.Join("db", "aegis.db"))

	// Keep the SQLite files in their own directory instead of the project root.
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			logger.Error("create db dir", "dir", dir, "err", err)
			os.Exit(1)
		}
	}

	// Root context cancelled on SIGINT/SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Store.
	st, err := sqlite.Open(dbPath)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		logger.Error("migrate", "err", err)
		os.Exit(1)
	}

	// Scan service + queue (workers run the scan lifecycle).
	svc := scansvc.New(st, logger)
	q := queue.New(svc.Run, queue.WithWorkers(2), queue.WithLogger(logger))
	q.Start(ctx)

	// Crash recovery. Scans left PROCESSING (crash mid-run) are reset to PENDING
	// first, then every PENDING scan is re-enqueued.
	if stuck, err := st.ListProcessingScans(ctx); err == nil {
		for _, sc := range stuck {
			sc.Status = model.StatusPending
			sc.StartedAt = nil
			if e := st.UpdateScan(ctx, &sc); e != nil {
				logger.Error("reset stuck scan", "scan", sc.ID, "err", e)
			}
		}
		if len(stuck) > 0 {
			logger.Info("reset stuck PROCESSING scans", "count", len(stuck))
		}
	}
	if pending, err := st.ListPendingScans(ctx); err == nil {
		for _, sc := range pending {
			q.Enqueue(sc.ID)
		}
		if len(pending) > 0 {
			logger.Info("re-enqueued pending scans", "count", len(pending))
		}
	}

	// HTTP server.
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(st, q).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("aegisd starting", "addr", addr, "db", dbPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
	logger.Info("aegisd stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

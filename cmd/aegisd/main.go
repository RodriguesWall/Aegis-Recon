// Command aegisd is the Aegis-Recon HTTP API daemon. F0 ships only a health
// endpoint; project/asset/scan routes and the static dashboard land in F2.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	addr := os.Getenv("AEGIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "aegis-recon",
			"status":  "ok",
			"time":    time.Now().UTC(),
		})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("aegisd starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

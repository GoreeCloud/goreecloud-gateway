package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/publication"
	"github.com/GoreeCloud/goreecloud-gateway/internal/status"
)

const defaultListenAddress = "127.0.0.1:9080"

func main() {
	listenAddress := os.Getenv("GOREECLOUD_GATEWAY_LISTEN")
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}

	if path := os.Getenv("GOREECLOUD_GATEWAY_PUBLICATION_FILE"); path != "" {
		plan, err := publication.LoadPlanFile(path)
		if err != nil {
			log.Fatalf("publication policy rejected: %v", err)
		}
		log.Printf(
			"validated publication policy: routes=%d authority=%s; data-plane mutation disabled",
			len(plan.Routes),
			plan.DataPlaneAuthority,
		)
	}

	if path := os.Getenv("GOREECLOUD_GATEWAY_STATUS_FILE"); path != "" {
		if err := status.WriteFile(path, status.DevelopmentSnapshot(time.Now())); err != nil {
			log.Fatalf("write status file: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "service": "goreecloud-gateway"})
	})
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, status.DevelopmentSnapshot(time.Now()))
	})

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("GoreeCloud Gateway development control plane listening on %s", listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

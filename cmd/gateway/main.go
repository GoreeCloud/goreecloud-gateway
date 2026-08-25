package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
	gatewayproxy "github.com/GoreeCloud/goreecloud-gateway/internal/proxy"
)

func main() {
	configPath := flag.String("config", "config/example.json", "Gateway configuration path")
	httpAddr := flag.String("http", "127.0.0.1:18080", "isolated HTTP development listener")
	httpsAddr := flag.String("https", "", "optional isolated HTTPS listener")
	certFile := flag.String("tls-cert", "", "TLS certificate for isolated HTTPS listener")
	keyFile := flag.String("tls-key", "", "TLS private key for isolated HTTPS listener")
	flag.Parse()

	cfg, err := config.Load(*configPath); if err != nil { slog.Error("configuration rejected", "error", err); os.Exit(1) }
	handler := gatewayproxy.New(cfg)
	server := &http.Server{Addr:*httpAddr, Handler:handler, ReadHeaderTimeout:10*time.Second, IdleTimeout:90*time.Second}

	errCh := make(chan error, 2)
	go func() { slog.Info("Gateway isolated HTTP listener starting", "address", *httpAddr); errCh <- server.ListenAndServe() }()
	var tlsServer *http.Server
	if *httpsAddr != "" {
		if *certFile == "" || *keyFile == "" { slog.Error("HTTPS listener requires both -tls-cert and -tls-key"); os.Exit(2) }
		tlsServer = &http.Server{Addr:*httpsAddr, Handler:handler, ReadHeaderTimeout:10*time.Second, IdleTimeout:90*time.Second}
		go func() { slog.Info("Gateway isolated HTTPS listener starting", "address", *httpsAddr); errCh <- tlsServer.ListenAndServeTLS(*certFile, *keyFile) }()
	}

	signals := make(chan os.Signal, 2); signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				next, loadErr := config.Load(*configPath); if loadErr != nil { slog.Warn("reload rejected; retaining last known-good configuration", "error", loadErr); continue }
				handler.Reload(next); slog.Info("configuration reloaded"); continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second); defer cancel(); _ = server.Shutdown(ctx); if tlsServer != nil { _ = tlsServer.Shutdown(ctx) }; return
		case serveErr := <-errCh:
			if serveErr != nil && serveErr != http.ErrServerClosed { slog.Error("listener failed", "error", serveErr); os.Exit(1) }
		}
	}
}

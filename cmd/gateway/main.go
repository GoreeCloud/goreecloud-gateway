package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
	gatewayproxy "github.com/GoreeCloud/goreecloud-gateway/internal/proxy"
	"github.com/GoreeCloud/goreecloud-gateway/internal/tlsconfig"
)

func main() {
	configPath := flag.String("config", "config/example.json", "Gateway configuration path")
	httpAddr := flag.String("http", "127.0.0.1:18080", "isolated HTTP development listener")
	httpsAddr := flag.String("https", "", "optional isolated HTTPS listener")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("configuration rejected", "error", err)
		os.Exit(1)
	}
	handler := gatewayproxy.New(cfg)
	defer handler.Close()
	server := &http.Server{Addr: *httpAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}

	errCh := make(chan error, 2)
	go func() {
		slog.Info("Gateway isolated HTTP listener starting", "address", *httpAddr)
		errCh <- server.ListenAndServe()
	}()

	var tlsServer *http.Server
	var tlsListener net.Listener
	var tlsReloader *tlsconfig.Reloader
	if *httpsAddr != "" {
		tlsReloader, err = tlsconfig.NewReloader(cfg)
		if err != nil {
			slog.Error("HTTPS listener certificate runtime rejected", "error", err)
			os.Exit(2)
		}
		baseListener, listenErr := net.Listen("tcp", *httpsAddr)
		if listenErr != nil {
			slog.Error("HTTPS listener bind failed", "error", listenErr)
			os.Exit(2)
		}
		tlsListener = tls.NewListener(baseListener, tlsReloader.TLSConfig())
		tlsServer = &http.Server{Addr: *httpsAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
		go func() {
			slog.Info("Gateway isolated HTTPS listener starting", "address", *httpsAddr)
			errCh <- tlsServer.Serve(tlsListener)
		}()
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				next, loadErr := config.Load(*configPath)
				if loadErr != nil {
					slog.Warn("reload rejected; retaining last known-good configuration", "error", loadErr)
					continue
			}
			if tlsReloader != nil {
				if reloadErr := tlsReloader.Reload(next); reloadErr != nil {
					slog.Warn("TLS reload rejected; retaining complete last-known-good runtime", "error", reloadErr)
					continue
				}
			}
			handler.Reload(next)
			slog.Info("configuration and listener certificate runtime reloaded atomically from validated source")
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = server.Shutdown(ctx)
		if tlsServer != nil {
			_ = tlsServer.Shutdown(ctx)
		}
		cancel()
		return
	case serveErr := <-errCh:
		if serveErr != nil && serveErr != http.ErrServerClosed {
			slog.Error("listener failed", "error", serveErr)
			os.Exit(1)
		}
	}
	}
}

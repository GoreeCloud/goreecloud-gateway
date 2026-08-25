package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
	"github.com/GoreeCloud/goreecloud-gateway/internal/routing"
)

type Handler struct { cfg atomic.Pointer[config.Config]; transport http.RoundTripper }

func New(cfg *config.Config) *Handler {
	h := &Handler{transport: &http.Transport{Proxy:http.ProxyFromEnvironment, ForceAttemptHTTP2:true, ResponseHeaderTimeout:30*time.Second, IdleConnTimeout:90*time.Second}}
	h.cfg.Store(cfg)
	return h
}

func (h *Handler) Reload(cfg *config.Config) { h.cfg.Store(cfg) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load(); if cfg == nil { http.Error(w, "gateway unavailable", http.StatusServiceUnavailable); return }
	match, ok := routing.Resolve(cfg, r); if !ok { http.NotFound(w, r); return }
	target, err := url.Parse(match.Backend.URL); if err != nil { http.Error(w, "backend unavailable", http.StatusBadGateway); return }
	p := httputil.NewSingleHostReverseProxy(target)
	p.Transport = h.transport
	p.FlushInterval = -1
	originalDirector := p.Director
	p.Director = func(req *http.Request) { originalDirector(req); req.Host = target.Host }
	p.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) { slog.Warn("proxy failure", "route", match.Route.ID, "backend", match.Backend.ID, "error", proxyErr.Error()); http.Error(rw, "upstream unavailable", http.StatusBadGateway) }
	p.ServeHTTP(w, r)
}

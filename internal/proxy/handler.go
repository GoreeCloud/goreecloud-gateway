package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
	"github.com/GoreeCloud/goreecloud-gateway/internal/health"
	"github.com/GoreeCloud/goreecloud-gateway/internal/routing"
)

const maxBackendAttempts = 3

type healthChecker interface {
	Check(context.Context, config.Backend) health.Result
}

type Handler struct {
	cfg       atomic.Pointer[config.Config]
	transport http.RoundTripper
	checker   healthChecker
}

func New(cfg *config.Config) *Handler {
	handler := &Handler{
		transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
		checker: health.New(2 * time.Second),
	}
	handler.cfg.Store(cfg)
	return handler
}

func (h *Handler) Reload(cfg *config.Config) {
	h.cfg.Store(cfg)
}

func (h *Handler) healthyCandidates(ctx context.Context, candidates []config.Backend) []config.Backend {
	results := make([]health.Result, len(candidates))
	var wg sync.WaitGroup
	wg.Add(len(candidates))
	for i, backend := range candidates {
		go func(index int, candidate config.Backend) {
			defer wg.Done()
			results[index] = h.checker.Check(ctx, candidate)
		}(i, backend)
	}
	wg.Wait()

	healthy := make([]config.Backend, 0, len(candidates))
	for i, result := range results {
		if result.Healthy {
			healthy = append(healthy, candidates[i])
			continue
		}
		slog.Warn("backend health check failed", "backend", candidates[i].ID, "status", result.StatusCode, "error", result.Err)
	}
	return healthy
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	cfg := h.cfg.Load()
	if cfg == nil {
		http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
		return
	}

	match, ok := routing.ResolveCandidates(cfg, req)
	if !ok {
		http.NotFound(w, req)
		return
	}

	candidates := h.healthyCandidates(req.Context(), match.Backends)
	if len(candidates) == 0 {
		http.Error(w, "no healthy upstreams", http.StatusServiceUnavailable)
		return
	}

	first, err := url.Parse(candidates[0].URL)
	if err != nil {
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	proxyOrigin := &url.URL{Scheme: first.Scheme, Host: first.Host}
	proxy := httputil.NewSingleHostReverseProxy(proxyOrigin)
	proxy.Transport = &failoverTransport{
		base:        h.transport,
		candidates:  candidates,
		maxAttempts: maxBackendAttempts,
	}
	proxy.FlushInterval = -1
	proxy.ErrorHandler = func(rw http.ResponseWriter, request *http.Request, proxyErr error) {
		slog.Warn("proxy failure", "route", match.Route.ID, "error", proxyErr.Error())
		http.Error(rw, "upstream unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, req)
}

type failoverTransport struct {
	base        http.RoundTripper
	candidates  []config.Backend
	maxAttempts int
}

func (t *failoverTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := t.maxAttempts
	if attempts <= 0 || attempts > len(t.candidates) {
		attempts = len(t.candidates)
	}

	retryable := retryableRequest(req)
	var lastErr error
	for i := 0; i < attempts; i++ {
		backend := t.candidates[i]
		attempt, err := requestForBackend(req, backend)
		if err != nil {
			return nil, err
		}

		response, err := t.base.RoundTrip(attempt)
		if err != nil {
			lastErr = fmt.Errorf("backend %s: %w", backend.ID, err)
			if retryable {
				continue
			}
			return nil, lastErr
		}

		if retryable && retryableStatus(response.StatusCode) && i+1 < attempts {
			_ = response.Body.Close()
			lastErr = fmt.Errorf("backend %s returned %d", backend.ID, response.StatusCode)
			continue
		}
		return response, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no backend attempt completed")
	}
	return nil, lastErr
}

func requestForBackend(req *http.Request, backend config.Backend) (*http.Request, error) {
	target, err := url.Parse(backend.URL)
	if err != nil {
		return nil, err
	}

	clone := req.Clone(req.Context())
	clone.URL.Scheme = target.Scheme
	clone.URL.Host = target.Host
	clone.URL.Path = joinURLPath(target.Path, req.URL.Path)
	clone.Host = target.Host
	if target.RawQuery == "" || req.URL.RawQuery == "" {
		clone.URL.RawQuery = target.RawQuery + req.URL.RawQuery
	} else {
		clone.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
	}
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}

func retryableRequest(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return req.Body == nil || req.GetBody != nil
	default:
		return false
	}
}

func retryableStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func joinURLPath(basePath, requestPath string) string {
	if basePath == "" {
		return requestPath
	}
	if requestPath == "" {
		return basePath
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

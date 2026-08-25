package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

const (
	maxBackendAttempts    = 3
	healthRefreshInterval = 10 * time.Second
)

type healthChecker interface {
	Check(context.Context, config.Backend) health.Result
}

type cachedHealth struct {
	result    health.Result
	checkedAt time.Time
}

type Handler struct {
	cfg       atomic.Pointer[config.Config]
	transport http.RoundTripper
	checker   healthChecker

	healthMu    sync.RWMutex
	healthState map[string]cachedHealth
	healthCtx   context.Context
	healthStop  context.CancelFunc

	roundRobin sync.Map // service ID -> *atomic.Uint64
}

func New(cfg *config.Config) *Handler {
	healthCtx, healthStop := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	handler := &Handler{
		transport: &http.Transport{
			Proxy:                   http.ProxyFromEnvironment,
			DialContext:             dialer.DialContext,
			ForceAttemptHTTP2:       true,
			ResponseHeaderTimeout:   30 * time.Second,
			TLSHandshakeTimeout:     10 * time.Second,
			ExpectContinueTimeout:   1 * time.Second,
			IdleConnTimeout:         90 * time.Second,
			MaxIdleConns:            256,
			MaxIdleConnsPerHost:     32,
			MaxConnsPerHost:         128,
			MaxResponseHeaderBytes:  1 << 20,
		},
		checker:     health.New(2 * time.Second),
		healthState: make(map[string]cachedHealth),
		healthCtx:   healthCtx,
		healthStop:  healthStop,
	}
	handler.cfg.Store(cfg)
	go handler.healthLoop()
	return handler
}

func (h *Handler) Close() {
	if h.healthStop != nil {
		h.healthStop()
	}
	if transport, ok := h.transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (h *Handler) Reload(cfg *config.Config) {
	h.cfg.Store(cfg)
	h.healthMu.Lock()
	clear(h.healthState)
	h.healthMu.Unlock()
}

func (h *Handler) healthLoop() {
	ticker := time.NewTicker(healthRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.healthCtx.Done():
			return
		case <-ticker.C:
			cfg := h.cfg.Load()
			if cfg != nil {
				h.refreshBackends(h.healthCtx, cfg.Backends)
			}
		}
	}
}

func (h *Handler) refreshBackends(ctx context.Context, backends []config.Backend) {
	candidates := make([]config.Backend, 0, len(backends))
	for _, backend := range backends {
		if backend.Enabled {
			candidates = append(candidates, backend)
		}
	}
	if len(candidates) == 0 {
		return
	}

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

	now := time.Now()
	h.healthMu.Lock()
	for i, result := range results {
		h.healthState[candidates[i].ID] = cachedHealth{result: result, checkedAt: now}
	}
	h.healthMu.Unlock()
}

func (h *Handler) healthyCandidates(ctx context.Context, candidates []config.Backend) []config.Backend {
	unknown := make([]config.Backend, 0, len(candidates))
	healthyByID := make(map[string]bool, len(candidates))

	h.healthMu.RLock()
	for _, candidate := range candidates {
		state, ok := h.healthState[candidate.ID]
		if !ok {
			unknown = append(unknown, candidate)
			continue
		}
		healthyByID[candidate.ID] = state.result.Healthy
	}
	h.healthMu.RUnlock()

	if len(unknown) > 0 {
		h.refreshBackends(ctx, unknown)
		h.healthMu.RLock()
		for _, candidate := range unknown {
			state, ok := h.healthState[candidate.ID]
			if ok {
				healthyByID[candidate.ID] = state.result.Healthy
			}
		}
		h.healthMu.RUnlock()
	}

	healthy := make([]config.Backend, 0, len(candidates))
	for _, candidate := range candidates {
		if healthyByID[candidate.ID] {
			healthy = append(healthy, candidate)
			continue
		}
		h.healthMu.RLock()
		state, ok := h.healthState[candidate.ID]
		h.healthMu.RUnlock()
		if ok {
			slog.Warn("backend excluded by health state", "backend", candidate.ID, "status", state.result.StatusCode, "error", state.result.Err)
		}
	}
	return healthy
}

func (h *Handler) rotateCandidates(serviceID string, candidates []config.Backend) []config.Backend {
	if len(candidates) < 2 {
		return candidates
	}
	counterValue, _ := h.roundRobin.LoadOrStore(serviceID, &atomic.Uint64{})
	counter := counterValue.(*atomic.Uint64)
	offset := int((counter.Add(1) - 1) % uint64(len(candidates)))
	rotated := make([]config.Backend, 0, len(candidates))
	rotated = append(rotated, candidates[offset:]...)
	rotated = append(rotated, candidates[:offset]...)
	return rotated
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
	candidates = h.rotateCandidates(match.Service.ID, candidates)

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

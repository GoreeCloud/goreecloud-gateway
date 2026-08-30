package proxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// backendLimitedTransport adds an explicit per-upstream concurrency boundary on
// top of net/http's connection limits. A slot remains held for the lifetime of
// the response body, so streaming responses cannot let a later request exceed
// the configured in-flight backend ceiling.
type backendLimitedTransport struct {
	base http.RoundTripper
	max  int
	host sync.Map // normalized URL authority -> chan struct{}
}

func newBackendLimitedTransport(base http.RoundTripper, max int) *backendLimitedTransport {
	return &backendLimitedTransport{base: base, max: max}
}

func (t *backendLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil || t.max <= 0 {
		return nil, errors.New("gateway proxy: backend concurrency limiter is not configured")
	}
	if req == nil || req.URL == nil {
		return nil, errors.New("gateway proxy: backend request URL is required")
	}
	authority := strings.ToLower(strings.TrimSpace(req.URL.Host))
	if authority == "" {
		return nil, errors.New("gateway proxy: backend request authority is required")
	}
	value, _ := t.host.LoadOrStore(authority, make(chan struct{}, t.max))
	limit := value.(chan struct{})
	select {
	case limit <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}

	release := func() { <-limit }
	response, err := t.base.RoundTrip(req)
	if err != nil {
		release()
		return nil, err
	}
	if response == nil || response.Body == nil {
		release()
		return nil, errors.New("gateway proxy: backend transport returned a response without a body")
	}
	response.Body = &releaseOnCloseBody{ReadCloser: response.Body, release: release}
	return response, nil
}

func (t *backendLimitedTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type releaseOnCloseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *releaseOnCloseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(b.release)
	}
	return n, err
}

func (b *releaseOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

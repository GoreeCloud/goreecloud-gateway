package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestBackendLimitedTransportBoundsResponseLifetimeConcurrency(t *testing.T) {
	var active atomic.Int64
	var maxActive atomic.Int64
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maxActive.Load()
			if current <= observed || maxActive.CompareAndSwap(observed, current) {
				break
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte("ok"))),
			Request:    request,
		}, nil
	})
	transport := newBackendLimitedTransport(base, 2)

	started := make(chan struct{}, 3)
	releaseBodies := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	for range 3 {
		go func() {
			defer wg.Done()
			request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "backend.example"}}
			request = request.WithContext(context.Background())
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Errorf("RoundTrip error: %v", err)
				return
			}
			started <- struct{}{}
			<-releaseBodies
			if err := response.Body.Close(); err != nil {
				t.Errorf("close body: %v", err)
			}
		}()
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("first two backend requests did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("third backend request started before a response-body slot was released")
	case <-time.After(50 * time.Millisecond):
	}

	releaseBodies <- struct{}{}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("third backend request did not start after a slot was released")
	}
	releaseBodies <- struct{}{}
	releaseBodies <- struct{}{}
	wg.Wait()

	if maxActive.Load() > 2 {
		t.Fatalf("base transport concurrency = %d, want <= 2", maxActive.Load())
	}
}

func TestBackendLimitedTransportSeparatesAuthorities(t *testing.T) {
	transport := newBackendLimitedTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil)), Request: request}, nil
	}), 1)
	for _, host := range []string{"a.example", "b.example"} {
		request := (&http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: host}}).WithContext(context.Background())
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

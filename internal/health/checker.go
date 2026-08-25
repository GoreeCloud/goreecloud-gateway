package health

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/GoreeCloud/goreecloud-gateway/internal/config"
)

type Result struct { BackendID string; Healthy bool; StatusCode int; Err error }

type Checker struct { Client *http.Client }

func New(timeout time.Duration) *Checker { return &Checker{Client:&http.Client{Timeout:timeout}} }

func (c *Checker) Check(ctx context.Context, backend config.Backend) Result {
	base, err := url.Parse(backend.URL); if err != nil { return Result{BackendID:backend.ID, Err:err} }
	path := backend.HealthPath; if path == "" { path = "/" }; base.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil); if err != nil { return Result{BackendID:backend.ID, Err:err} }
	resp, err := c.Client.Do(req); if err != nil { return Result{BackendID:backend.ID, Err:err} }; defer resp.Body.Close()
	healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
	var resultErr error; if !healthy { resultErr = fmt.Errorf("health status %d", resp.StatusCode) }
	return Result{BackendID:backend.ID, Healthy:healthy, StatusCode:resp.StatusCode, Err:resultErr}
}

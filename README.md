# GoreeCloud Gateway

Native GoreeCloud reverse proxy, HTTPS gateway, ingress controller, certificate manager, and service publication platform.

## Development status

Gateway is now establishing its GoreeCloud-owned control-plane boundary while Caddy remains the current runtime data plane. The first implemented slice is a local-only, read-only status service and atomic sanitized status-file handoff. It intentionally performs no infrastructure mutation.

### Run

```bash
go run ./cmd/goreecloud-gateway
```

The development server binds to `127.0.0.1:9080` by default.

- `GET /healthz` — process liveness only.
- `GET /v1/status` — privacy-minimized Infrastructure Status v1 envelope.

Set `GOREECLOUD_GATEWAY_STATUS_FILE=/path/to/gateway-status.json` to atomically publish the same sanitized status document for a read-only Manager mount.

### Validate

```bash
go test ./...
go vet ./...
```

See `docs/architecture.md` and `docs/status-contract.md` for authority and privacy boundaries.

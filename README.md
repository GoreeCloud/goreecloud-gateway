# GoreeCloud Gateway

Native GoreeCloud reverse proxy, HTTPS gateway, ingress controller, certificate manager, and service publication platform.

## Development status

Gateway is establishing its GoreeCloud-owned control-plane boundary while Caddy remains the current runtime data plane. The implemented slices now include a local-only status service, atomic sanitized status-file handoff, strict publication-policy validation, and deterministic mutation-free publication planning. No Caddy apply/reload path exists yet.

### Run

```bash
go run ./cmd/goreecloud-gateway
```

The development server binds to `127.0.0.1:9080` by default.

- `GET /healthz` — process liveness only.
- `GET /v1/status` — privacy-minimized Infrastructure Status v1 envelope.

Set `GOREECLOUD_GATEWAY_STATUS_FILE=/path/to/gateway-status.json` to atomically publish the same sanitized status document for a read-only Manager mount.

Set `GOREECLOUD_GATEWAY_PUBLICATION_FILE=/path/to/publication.json` to require a bounded local publication policy to pass strict JSON decoding, route/security validation, and deterministic plan construction before Gateway starts serving. The loader does not contact Caddy and the plan is not exposed through the HTTP service.

A publication policy uses schema version `1` and supports public or private routes. Private routes require canonical allowed CIDRs; upstream URLs may use only `http` or `https` and may not contain credentials, query parameters, fragments, or application paths.

### Validate

```bash
go test ./...
go vet ./...
```

See `docs/architecture.md` and `docs/status-contract.md` for authority and privacy boundaries.

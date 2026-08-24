# GoreeCloud Gateway

GoreeCloud Gateway is the native, first-party GoreeCloud application and service for reverse proxying, application ingress, HTTPS termination, certificate lifecycle management, routing, load balancing, health-aware upstream selection, and controlled service publication.

It is designed from the ground up as a GoreeCloud-owned product. Caddy, Traefik, and Nginx Proxy Manager are feature and interoperability references only; GoreeCloud Gateway is not a fork or re-skin of those applications.

## Product responsibilities

- HTTP and HTTPS reverse proxying
- Host, path, header, method, and protocol-aware routing
- TLS termination and certificate lifecycle management
- ACME automation including DNS-01 integration
- HTTP-to-HTTPS redirects and canonical redirects
- WebSocket and streaming proxy support
- Upstream pools, load balancing, health checks, retries, and failover
- Route priorities, middleware/policy chains, and reusable route templates
- Private and public publication classifications
- Service discovery and configuration validation
- Access logs, privacy-safe diagnostics, metrics, and audit events
- Configuration API and Glaze UI administration
- Import/migration tooling for approved Caddy, Traefik, and Nginx Proxy Manager configurations
- Backup, restore, rollback, and configuration history

## Platform integrations

Gateway must integrate current Stable contracts for Glaze UI, Wardveil Security, Privacy Shield, and Everkeep.

## Responsibility boundaries

Gateway is authoritative for ingress and reverse-proxy behavior. GoreeCloud DNS / Beacon remains authoritative for DNS service and DNS policy. GoreeCloud Network / Conduit remains authoritative for private connectivity and network access policy. Identity remains authoritative for platform identity contracts. Destination applications retain application authorization. Monitor retains general service monitoring.

## Native source architecture

- `cmd/gateway` — service entry point
- `internal/config` — typed configuration and validation
- `internal/router` — deterministic route matching and priority
- `internal/proxy` — HTTP reverse-proxy execution
- `internal/upstream` — pools, balancing, health, retry, and failover
- `internal/tls` — TLS policy and certificate lifecycle
- `internal/policy` — middleware and request/response policy chains
- `internal/api` — administration API
- `internal/observability` — privacy-safe logs, metrics, diagnostics, and audit events
- `internal/platform` — Glaze UI, Wardveil Security, Privacy Shield, and Everkeep adapters
- `internal/migration` — controlled import and compatibility tooling

## Development and release boundary

Source implementation, CI success, isolated runtime validation, and production acceptance are separate states. No source change authorizes production cutover. Existing production Caddy remains authoritative until a later migration is explicitly validated and approved.

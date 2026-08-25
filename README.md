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

Gateway is authoritative for ingress and reverse-proxy behavior only after an approved production cutover. GoreeCloud DNS / Beacon remains authoritative for DNS service and DNS policy. GoreeCloud Network / Conduit remains authoritative for private connectivity and network access policy. Identity remains authoritative for platform identity contracts. Destination applications retain application authorization. Monitor retains general service monitoring.

## Current native source architecture

- `cmd/gateway` — native service entry point and isolated listener lifecycle
- `internal/config` — typed configuration loading and fail-closed validation
- `internal/routing` — deterministic host, path-prefix, and method routing
- `internal/health` — bounded backend health probes
- `internal/proxy` — reverse-proxy execution, persistent health state, round-robin primary selection, bounded failover, streaming, upgraded connections, and transport limits
- `config` — canonical schema and disabled example configuration
- `docs` — architecture, security, and migration/development records
- `scripts` — exact-source foundation validation

Planned subsystems such as the TLS engine, control-plane API, discovery engine, observability layer, migration tooling, and complete Glaze UI / Wardveil Security / Privacy Shield / Everkeep adapters remain separate future implementation work and are not represented as complete by the current tree.

## Current development state

Milestone 1 Proxy Core includes ordered multi-backend route candidates, reusable backend health state with a cancellable background refresh loop, first-request health population for unknown state, fail-closed exclusion of unhealthy upstreams, service-scoped round-robin primary selection, and bounded retry/failover across at most three healthy candidates for safe GET, HEAD, and OPTIONS requests on transport errors or HTTP 502/503/504 responses. Unsafe or non-idempotent methods are not automatically replayed.

The proxy transport now applies explicit dial, TLS-handshake, response-header, expect-continue, idle-connection, pool, per-host connection, and response-header-size bounds. Runtime tests cover early response streaming and upgraded bidirectional connection tunneling in addition to routing, failover, health-state reuse, balanced primary selection, no-healthy-backend failure, unsafe-method non-replay, and configuration reload behavior.

These remain development-source capabilities. Full automatic HTTPS/ACME, production listener ownership, isolated target-host acceptance, persistent control-plane state, production observability, and migration/cutover acceptance remain pending.

## Development and release boundary

Source implementation, CI success, isolated runtime validation, and production acceptance are separate states. No source change authorizes production cutover. Existing production Caddy remains authoritative until a later migration is explicitly validated and approved.

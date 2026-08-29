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

Gateway must integrate current Stable contracts for Glaze UI, Wardveil Security, Privacy Shield, and Everkeep. The currently validated Glaze UI Stable baseline is 1.6.0; Candidate 2.0.0 is not accepted as the Stable migration baseline.

## Responsibility boundaries

Gateway is authoritative for ingress and reverse-proxy behavior. GoreeCloud DNS / Beacon remains authoritative for DNS service and DNS policy. GoreeCloud Network / Conduit remains authoritative for private connectivity and network access policy. Identity remains authoritative for platform identity contracts. Destination applications retain application authorization. Monitor retains general service monitoring.

## Implemented native source

The current development branch contains the first-party Gateway runtime foundation, including typed configuration, deterministic routing, reverse proxying, streaming and upgraded-connection handling, reusable backend health state, health-aware failover, service-scoped round-robin selection, bounded upstream transport settings, last-known-good runtime reload behavior, and a privacy-safe aggregate runtime-status contract.

The TLS lifecycle now includes explicit route-to-certificate-profile inventory, renewal eligibility/request validation, provider-neutral issuance, candidate validation, owner-protected staging, staged-bundle integrity verification, publication planning bound to the exact live serial, rollback-safe on-disk publication, controlled runtime activation, retained backup evidence, and an isolated full-cycle rehearsal boundary. The rehearsal boundary refuses live/staging/backup paths outside its explicitly supplied isolated root, activates only the rehearsal candidate, restores the prior pair and runtime, and always records `production_cutover_authorized=false`.

The runtime-status contract is `goreecloud-gateway-runtime-status/v1`. It exposes aggregate counts for services, enabled routes, enabled backends, and healthy/unhealthy/unknown backend state while intentionally excluding hostnames, backend URLs, request data, headers, client identifiers, credentials, and other sensitive material. This is the source foundation for later Wardveil Security, Privacy Shield, Monitor, and Manager evidence adapters.

The migration-readiness contract is `goreecloud-gateway-migration-evidence/v1`. It is a fail-closed evidence evaluator bound to an exact source revision and immutable runtime-artifact SHA-256. It enumerates route parity, TLS rehearsal, streaming/upgraded connections, sustained load, backpressure, backup/restore, rollback, listener ownership, observability, Privacy Shield, Wardveil Security, Everkeep, and current-Stable Glaze UI validation. Even complete evidence can only make Gateway eligible for an explicitly approved migration rehearsal; the decision always keeps `production_cutover_authorized=false`.

## Exact-source isolated runtime acceptance

`.github/workflows/gateway-isolated-runtime.yml` builds the real `cmd/gateway` binary from the exact candidate revision, verifies the checked-out SHA, and runs `scripts/isolated_runtime_acceptance.py` entirely on loopback.

The bounded exercise:

- starts an isolated loopback backend with a health endpoint;
- launches the actual Gateway binary on a loopback-only listener using temporary non-production configuration;
- proves host-based route forwarding through the running process;
- proves backend health participation in routing;
- verifies an unmatched host remains unrouted with HTTP 404;
- requests graceful process shutdown and requires a clean exit;
- records the exact source revision and SHA-256 of the built Gateway artifact;
- emits `goreecloud-gateway-isolated-runtime-evidence/v1` without credentials, production routes, hostnames, request contents, client identifiers, or other production data;
- always records `production_cutover_authorized=false`.

This workflow supplies bounded runtime evidence only. It does not prove production route parity, TLS ownership, sustained production-equivalent load, backup/restore, rollback, full platform integration, or migration approval.

Both the native-foundation and isolated-runtime workflows explicitly check out and verify the exact pull-request head or push revision before validation. A synthetic merge revision is not accepted as source identity for these migration gates.

## Planned source architecture

- `cmd/gateway` — service entry point
- `internal/config` — typed configuration and validation
- `internal/routing` — deterministic route matching and priority
- `internal/proxy` — HTTP reverse-proxy execution and privacy-safe runtime status
- `internal/upstream` — future dedicated pools, balancing, health, retry, and failover subsystem
- `internal/tlsconfig` — TLS runtime, policy inventory, certificate lifecycle, transaction, activation, and isolated rehearsal controls
- `internal/acceptance` — fail-closed migration-readiness evidence and gate evaluation
- `internal/policy` — middleware and request/response policy chains
- `internal/api` — administration API
- `internal/observability` — privacy-safe logs, metrics, diagnostics, and audit events
- `internal/platform` — Glaze UI, Wardveil Security, Privacy Shield, and Everkeep adapters
- `internal/migration` — controlled import and compatibility tooling

## Development and release boundary

Source implementation, CI success, isolated runtime validation, migration-rehearsal eligibility, and production acceptance are separate states. The isolated renewal rehearsal operates only on paths inside its explicit rehearsal root and does not authorize live publication. The isolated runtime workflow operates only against temporary loopback configuration and is not a production deployment. The migration-readiness evaluator records missing acceptance gates but cannot authorize cutover. No source change authorizes production cutover. Existing production Caddy remains authoritative until a later migration is explicitly validated and approved.

# GoreeCloud Gateway Specifications

## Status

GoreeCloud Gateway is in active development as the first-party GoreeCloud ingress, reverse-proxy, routing, HTTPS, certificate-lifecycle, and controlled service-publication system.

The canonical product record is maintained in Google Drive under `GoreeCloud/Projects/Project Specification — Gateway`. This repository document is the version-coupled implementation specification and must not silently override that canonical project record.

Production authority has **not** migrated. Existing production Caddy remains authoritative until retained migration evidence passes the required gates and an explicit production migration is approved.

## Native implementation boundary

Gateway is a GoreeCloud-owned implementation rather than a fork or re-skin of Caddy, Traefik, or Nginx Proxy Manager. Those products may be used as feature, migration, and interoperability references only.

Current native source includes:

- typed `goreecloud-gateway-config/v1` configuration;
- deterministic host/path/header/method routing;
- HTTP reverse proxying, streaming, and upgraded connections;
- health-aware backend selection and failover;
- bounded upstream transport behavior;
- last-known-good runtime configuration reload behavior;
- route-scoped TLS policy and certificate-profile inventory;
- provider-neutral certificate renewal, protected staging, integrity verification, publication planning, rollback-safe publication, controlled activation, and isolated renewal rehearsal;
- backup/restore and compare-and-swap rollback primitives for isolated configuration recovery;
- privacy-safe runtime status and migration evidence contracts;
- exact-source isolated runtime acceptance;
- exact-source isolated sustained-load evidence collection.

## Acceptance contracts

`goreecloud-gateway-migration-evidence/v1` is fail closed and binds evidence to an exact source revision and immutable runtime artifact. Required migration gates include configuration validation, route parity, TLS renewal rehearsal, streaming/upgrades, sustained load, backpressure, backup/restore, rollback, listener ownership, observability, Privacy Shield, Wardveil Security, Everkeep, current-Stable Glaze UI, GoreeCloud Mesh coordination, GoreeCloud Identity integration, and governance integration.

Complete source evidence can make a candidate eligible for a migration rehearsal only. It cannot authorize production cutover.

The isolated runtime workflow builds the actual Gateway and recovery artifacts from the exact candidate source, exercises them on loopback with temporary configuration, and emits sanitized evidence. The isolated sustained-load workflow builds the actual Gateway artifact from the exact candidate source and records steady loopback request volume, failure count, error rate, and latency percentiles.

Neither isolated workflow represents production capacity, production route parity, public listener ownership, or production approval.

## Platform boundaries

- Privacy Shield / Privacy Center governs privacy, consent, minimization, governance, and user control.
- Wardveil Security / Security Center governs security protection, detection, verification, and response.
- Everkeep / Continuity Center governs backup, recovery, preservation, portability, and continuity.
- Glaze UI / Design Center governs interface, accessibility, responsiveness, and design-system conformance.
- GoreeCloud Mesh / Mesh Center governs platform coordination, integration capabilities, and events.
- GoreeCloud Identity / Identity Center governs identities, accounts, credentials, authorization, sessions, devices, and delegated authority.

Gateway must consume those platform contracts without assuming their authority.

## Production acceptance boundary

Production migration remains blocked until representative environment evidence proves the intended route/configuration parity, listener transfer, certificate and rollback behavior, sustained-load/error/latency objectives, privacy-safe observability, platform-system acceptance, recovery, and reversible cutover. Source code and CI do not grant production authority.

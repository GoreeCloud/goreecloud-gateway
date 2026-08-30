# GoreeCloud Gateway Features

This file distinguishes implemented branch behavior from accepted future scope. A listed objective is not a claim of production availability.

## Implemented on the active development branch

- Native HTTP reverse proxy runtime.
- Deterministic route matching and conflict validation.
- Host, path, method, and configured routing controls.
- Streaming and upgraded-connection proxy support.
- Backend health participation, failover, and bounded transport behavior.
- Last-known-good runtime configuration reload behavior.
- TLS route/profile inventory and certificate lifecycle primitives.
- Provider-neutral renewal candidate issuance boundary.
- Owner-protected certificate staging and SHA-256 integrity verification.
- Exact-live-serial publication planning and rollback-safe publication.
- Controlled runtime certificate activation and isolated renewal rehearsal.
- Configuration recovery snapshots, compare-and-swap restore, and rollback rehearsal.
- Privacy-safe aggregate runtime status.
- Fail-closed migration-readiness evaluation.
- Exact-source loopback runtime acceptance with bounded concurrency/backpressure evidence.
- Exact-source isolated sustained-load evidence with request count, failure/error rate, and p50/p95/p99 latency recording.
- Migration gates for Privacy Shield, Wardveil Security, Everkeep, current-Stable Glaze UI, GoreeCloud Mesh, GoreeCloud Identity, and governance integration.

## Accepted but not yet production-accepted

- Production-representative sustained-load, latency, and error-rate acceptance.
- Real migration-source configuration and route parity.
- Public listener ownership transfer and reversible cutover rehearsal.
- Target-environment privacy-safe operational evidence.
- Final certificate/DNS provider integration and production issuance acceptance.
- Full administration API and Glaze UI management surface.
- Complete service discovery and policy-chain administration.
- Production backup/restore and disaster-recovery evidence.

## Explicit non-claims

- The isolated load harness is not a production-capacity benchmark.
- Migration-readiness code cannot approve production cutover.
- Caddy production authority has not been transferred.
- Platform-system gate fields are acceptance boundaries, not proof that target-environment integration has passed.

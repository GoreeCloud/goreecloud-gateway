# GoreeCloud Gateway Features

Status vocabulary: **Accepted main**, **Validated development candidate**, **Planned**, or **Blocked by prerequisite**. Candidate or isolated-runtime evidence is not production-cutover authority.

## Accepted main

| Feature / record | Status | Boundary |
|---|---|---|
| GoreeCloud Gateway product identity | Accepted main | Canonical branding consumer contract and local synchronized artwork exist. |
| GNU AGPL v3 repository license material | Accepted main | Root `LICENSE`; third-party dependencies retain separate terms. |
| Caddy-authoritative migration boundary | Accepted main | Documentation explicitly keeps production publication on Caddy until cutover approval. |
| Six mandatory repository governance records | Accepted main after this governance change | Documentation/governance only; does not merge runtime development. |

## Native development candidates

Separate draft pull requests contain executable Gateway work. Current development evidence includes or targets:

- first-party Go Gateway runtime/control-plane slices;
- deterministic routing and backend selection;
- health-aware failover;
- streaming and upgraded-connection handling;
- route-scoped TLS policy and certificate profiles;
- provider-neutral certificate renewal and protected publication/rollback concepts;
- exact-source migration-evidence contracts;
- loopback isolated runtime acceptance;
- isolated sustained-load/backpressure evidence;
- configuration recovery and rollback primitives;
- configuration-parity fingerprints and migration-source identity contracts;
- local Infrastructure Status v1 and publication preflight/validation contracts;
- privacy-minimized status/evidence outputs;
- platform-system acceptance gates for Glaze UI, Wardveil Security, Privacy Shield, Everkeep, Mesh, Identity, and governance.

These are **Validated development candidate** capabilities only at the exact heads/workflow runs documented in the authoritative Gateway project specification and changelog. They are not accepted `main` behavior until their own PR review/merge gates are satisfied.

## Planned capabilities

- complete production-grade HTTP/HTTPS listener/data plane;
- production-safe automatic HTTPS/ACME and certificate lifecycle;
- visual Services/Routes/Backends/Certificates/Discovery/Access/Traffic/Logs/Security/Health/Configuration/Settings administration;
- complete staged configuration transactions and last-known-good activation behavior;
- approved Docker discovery and proposed-publication workflows;
- advanced route matching, middleware/policy chains, rate limiting, redirects/header transforms, compression, and load balancing;
- documented first-party API and CLI;
- optional HTTP/3 after separate dependency, security, and runtime acceptance;
- production Caddy migration tooling and reversible cutover.

## Blocked by prerequisite

- production listener ownership on TCP 80/443;
- Caddy retirement;
- migration-source route/configuration parity acceptance;
- production-representative load/SLO/backpressure evidence;
- target-environment backup/restore and rollback;
- production certificate/TLS renewal evidence;
- target-environment Privacy Shield, Wardveil Security, Everkeep, Mesh, Identity, Glaze UI, and governance integration evidence;
- explicit production migration approval and Stable qualification.

## Evidence rule

Gateway must never convert discovery, candidate configuration, source CI, isolated runtime testing, successful proxy traffic, or a migration evidence artifact into a production-authorization claim without the separately required target-environment and governance evidence.

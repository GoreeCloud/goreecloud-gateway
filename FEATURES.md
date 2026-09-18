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
- provider-neutral DNS-01 challenge abstraction with a bounded Porkbun TXT-record adapter for exact create/cleanup operations;
- RFC 8555 order-based renewal issuer with existing-account enforcement, DNS-01-only pending authorization, propagation confirmation, exact challenge cleanup, fresh certificate-key generation, CSR finalization, and handoff to the independent validation/staging boundary;\n- create-once encrypted ACME account-key envelopes using AES-256-GCM, CA-directory binding, public-key fingerprints, owner-only state roots/files, symlink rejection, authenticated metadata, and explicit no-overwrite rollover boundaries;\n- explicit two-phase ACME account registration planning/execution with exact TOS URL acceptance, short-lived plan binding, contact-set hashing, EAB requirement enforcement, requirement-drift detection, and privacy-safe registration receipts;\n- protected file-based loading of the external 256-bit ACME account wrapping key with regular-file, permission, symlink-path, size, and exact-key-length validation, plus offline encrypted-envelope restore coverage;\n- a fail-closed `gateway-acme-account` Development operator tool that separates local encrypted account-key creation, non-mutating registration planning, and explicitly confirmed account registration; contacts/plans/acceptance/EAB keys are read from protected files, EAB MAC keys are base64url-decoded in memory, and registration output remains privacy-safe;\n- immutable encrypted ACME account-key rollover preparation bundles that are written before any future CA key-change request and cryptographically bound to the exact active account fingerprint, replacement-key fingerprint, and ACME directory; stale bundles fail closed after active-account drift;\n- a transactional ACME account-key rollover execution boundary that preserves an encrypted retired copy and a complete staged replacement active envelope before contacting the CA, leaves the old active key unchanged while retaining the staged replacement on any unconfirmed CA outcome to prevent blind replay, and atomically replaces the active envelope only after confirmed CA success;\n- a read-only ACME rollover recovery probe that requires complete pending replacement state, authenticates the old and prepared replacement keys independently with RFC 8555 existing-account lookup, classifies old/new/both/neither recognition, and treats transport/protocol errors as inconclusive rather than replaying key change;\n- a local recovery executor that performs a fresh read-only probe immediately before mutation, requires explicit old-authoritative or new-authoritative confirmation, preserves an encrypted retired snapshot, clears non-authoritative pending state only for old-authoritative, atomically activates pending state only for new-authoritative, and refuses both/neither/inconclusive outcomes;
- exact-source migration-evidence contracts;
- loopback isolated runtime acceptance;
- isolated sustained-load/backpressure evidence;
- configuration recovery and rollback primitives;
- configuration-parity fingerprints and migration-source identity contracts;
- local Infrastructure Status v1 and publication preflight/validation contracts;
- privacy-minimized status/evidence outputs;
- platform-system acceptance gates for GoreeCloud Manager, Privacy Shield, Wardveil Security, Everkeep, Glaze UI, GoreeCloud Mesh, GoreeCloud Identity, GoreeCloud Policy, and GoreeCloud Observability, with governance remaining separately authoritative for publication/cutover approval.

These are **Validated development candidate** capabilities only at the exact heads/workflow runs documented in the authoritative Gateway project specification and changelog. They are not accepted `main` behavior until their own PR review/merge gates are satisfied.

## Planned capabilities

- complete production-grade HTTP/HTTPS listener/data plane;
- approved operator execution/human TOS review using the now-wired account-registration tool, approved wrapping-key provisioning/escrow and target recovery rehearsal, operator wiring and target rehearsal for the now-transactional CA account-key rollover boundary, read-only authority probe, and explicit recovery executor, plus live CA/Porkbun issuance and renewal acceptance over the established RFC 8555 DNS-01 issuer;
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
- target-environment GoreeCloud Manager, Privacy Shield, Wardveil Security, Everkeep, Glaze UI, GoreeCloud Mesh, GoreeCloud Identity, GoreeCloud Policy, and GoreeCloud Observability integration evidence, plus separately governed publication/cutover authorization;
- explicit production migration approval and Stable qualification.

## Evidence rule

Gateway must never convert discovery, candidate configuration, source CI, isolated runtime testing, successful proxy traffic, or a migration evidence artifact into a production-authorization claim without the separately required target-environment and governance evidence.

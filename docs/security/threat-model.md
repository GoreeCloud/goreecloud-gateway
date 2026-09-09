# GoreeCloud Gateway Threat Model

## Scope

This document defines the initial Milestone 0 security boundary for GoreeCloud Gateway. It governs source development and validation only. Existing production Caddy remains authoritative until a separately validated migration and production cutover is approved.

## Protected assets

Gateway must protect canonical configuration, active route state, certificate metadata and private material, administrative authorization, backend identities, publication intent, route history, rollback state, operational evidence, and the integrity of the HTTP/HTTPS data plane.

## Primary trust boundaries

### Listener ownership

Development listeners must remain isolated from production Caddy. Gateway must not claim TCP 80, TCP 443, or UDP 443 while Caddy owns those production listeners. Listener conflicts are validation failures, not conditions to work around automatically.

### Configuration activation

Candidate configuration is untrusted until validation completes. An invalid candidate must never replace the last known-good active configuration. Activation and rollback must be explicit state transitions with retained history.

### Publication boundary

Backend discovery does not equal publication. Service registration does not equal route activation. A route may remain disabled. Public and restricted-public exposure require explicit intent, required TLS, access-policy validation where applicable, conflict checks, and unsafe public exposure review.

### Control plane and data plane

Administrative UI/API failures must not unnecessarily terminate traffic already served by a valid data-plane configuration. The data plane consumes only validated configuration through a defined internal contract.

### Backend trust

Backends are not trusted merely because they are reachable. Gateway must validate destination syntax, route references, health requirements, protocol expectations, and policy compatibility. Discovery metadata is input to a proposal workflow, not automatic authority.

### TLS and certificate material

Certificate-management failure must fail safely and must not downgrade a route to plaintext. Private keys, ACME credentials, DNS-provider credentials, and certificate secrets must never appear in routine logs, status payloads, or configuration exports unless an explicitly protected recovery format requires them.

### Request privacy

Privacy Shield minimization applies to request handling and observability. Sensitive headers, cookies, authorization values, tokens, credentials, request bodies, and unnecessary client-identifying information must not be emitted through routine logs or administrative status surfaces.

## Threats and required controls

- **Accidental public exposure:** private by default, explicit exposure classification, disabled-until-approved route lifecycle, fail-closed validation.
- **Listener takeover or collision:** explicit listener ownership checks and no production port competition with Caddy during migration.
- **Route ambiguity:** reject duplicate or conflicting host/path/method matches before activation.
- **Dangling references:** reject Services, Routes, or Backends that reference missing objects.
- **TLS downgrade:** require TLS for public and restricted-public publication; certificate failure cannot silently disable encryption.
- **Administrative lockout:** retain a known-good configuration and a tested rollback path independent of the candidate configuration.
- **Backend redirection abuse:** validate configured destinations and prevent discovery from directly publishing unapproved endpoints.
- **Secret leakage:** redact sensitive headers and credentials; keep secrets outside normal telemetry and evidence payloads.
- **Control-plane compromise:** authenticate and authorize administrative writes, retain audit evidence, and keep runtime activation transactional.
- **Configuration corruption:** validate schema and semantic relationships before preview or activation; retain recoverable history through Everkeep.
- **Misleading security claims:** Wardveil Security status must be evidence-backed and must not represent an unvalidated route, backend, certificate, listener, or policy as secure.

## Milestone 0 acceptance boundary

Milestone 0 may establish schemas, contracts, validation, tests, CI, architecture, and threat-model evidence. It does not authorize live proxy listeners, certificate issuance, DNS changes, firewall changes, production publication, or Caddy retirement.

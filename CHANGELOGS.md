# GoreeCloud Gateway Changelogs

This repository-local record is the authoritative Git-native chronological change history for GoreeCloud Gateway source and repository governance. Production cutover, deployment, and lifecycle promotion remain separately evidence-gated.

## Unreleased — Development

### PR #9 — staged Caddy-replacement Development candidate

- Added and iterated the first-party Gateway runtime/control-plane foundation, deterministic routing/backend selection, health-aware failover, streaming/upgraded-connection handling, trusted-proxy handling, and recovery/rollback primitives.
- Added migration-source/parity evidence, privacy-minimized status/publication preflight, isolated runtime, sustained-load/backpressure, and vulnerability-reachability gates.
- Added provider-neutral DNS-01 handling, a bounded Porkbun adapter, RFC 8555 DNS-01 issuance, encrypted ACME account-state handling, explicit registration/TOS controls, protected wrapping-key loading, rollover preparation/execution, read-only authority probing, explicit recovery, and guarded operator tooling.
- Added a read-only Caddy/VPS preflight collector for target evidence without mutating Caddy, Docker, firewall, DNS, certificates, or listeners.
- Reconciled the candidate to current GLAZE UI V1.6 / 1.6.0 source authority while keeping the future administration UI unaccepted.
- Migrated repository feature/change governance from retired `FEATURE-ROADMAP.md` / Drive-roadmap synchronization to `IMPLEMENTED-FEATURES.md`, `PLANNED-FEATURES.md`, and `CHANGELOGS.md`.
- Preserved Caddy as production-authoritative. No source or documentation change in this record authorizes listener transfer, production deployment, Release Candidate, Production Acceptance, or Stable status.

Exact candidate revisions and workflow results are authoritative in GitHub PR/workflow evidence rather than duplicated here as moving pre-merge SHAs.

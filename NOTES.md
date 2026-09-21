# GoreeCloud Gateway — Development Notes

## Current stabilization context

- Lifecycle remains Development / nonconformant. Caddy remains the production-authoritative public HTTP/HTTPS gateway; no listener ownership, DNS, firewall, certificate, Docker, or production publication authority has moved to GoreeCloud Gateway.
- Draft PR #9 is the active native Gateway/Caddy-replacement source candidate. It contains the native routing/control-plane foundation, trusted-proxy and forwarding-identity enforcement, bounded recovery/rollback primitives, certificate/ACME development boundaries, and the read-only target-Caddy preflight collector.
- The candidate is declared against Platform Contract 0.4 and all nine Integral Platform Systems. Current Official Stable GLAZE UI V1.6 / 1.6.0 is required for the future administration experience; no accepted Gateway administration UI exists yet.
- Repository CI, isolated runtime tests, load tests, vulnerability reachability, and source recovery tests are Development evidence only. They do not establish target-VPS parity, production deployment, Release Candidate, Production Acceptance, or Stable status.

## Active Caddy-replacement gates

- Execute and review the sanitized read-only Caddy/VPS preflight against the authorized target before proposing any mutation.
- Establish route, listener, TLS/certificate, Docker-network, WebSocket/streaming, and applicable HTTP/2/gRPC parity for the exact Gateway candidate.
- Provision production ACME/DNS authority through approved protected credential handling only after the applicable warning/approval process.
- Complete an alternate-port target-VPS rehearsal that cannot conflict with Caddy's current TCP 80/443 authority.
- Prove rollback/recovery on the target and retain Caddy as rollback authority until post-cutover acceptance is complete.
- Obtain accepted Manager, Privacy Shield, Wardveil Security, Everkeep, Glaze UI, Mesh, Identity, Policy, and Observability integration evidence where applicable.
- Reconcile the Caddy/NetBird port-separation governance before any listener-transfer proposal.
- Complete release provenance, deployment approval, Production Acceptance, and Stable qualification before representing Gateway as the active public gateway.

## Safety and evidence boundary

The read-only preflight collector must remain non-mutating and privacy-minimized. Do not store reusable DNS/API credentials, ACME private keys, certificate private keys, account secrets, or other reusable credentials in repository notes or ordinary migration evidence. Planned or source-implemented behavior is not target-runtime evidence.

# Isolated Sustained-Load Acceptance

`Gateway Isolated Sustained Load` is a development acceptance workflow for the first-party GoreeCloud Gateway runtime.

The workflow checks out and verifies the exact candidate source revision, builds `cmd/gateway`, starts a temporary loopback backend and loopback-only Gateway listener, runs a steady bounded request workload, and writes sanitized `goreecloud-gateway-isolated-sustained-load-evidence/v1`.

The evidence includes only the source revision, runtime artifact SHA-256, loopback listener scope, worker count, target and observed duration, request and failure counts, error rate, p50/p95/p99 latency, and the harness health ceiling. Credentials and production data are excluded, `production_capacity_claimed` is false, and `production_cutover_authorized` is false.

The p95 ceiling is a harness-health guard intended to catch a severely stalled isolated run. It is not a production service-level objective.

This workflow does **not** establish production capacity, production route parity, public listener readiness, target-environment network behavior, or production migration approval. Production-representative load acceptance remains a separate migration gate.

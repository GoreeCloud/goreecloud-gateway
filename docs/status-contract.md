# Infrastructure Status v1

GoreeCloud Gateway publishes a privacy-minimized, read-only operational status envelope for GoreeCloud Manager and other approved observers.

## Contract

The v1 envelope contains exactly these top-level concepts:

- `schema_version`: integer `1`;
- `producer`: `service_id`, `adapter_id`, and declared `runtime_authority`;
- `generated_at`: UTC RFC 3339 timestamp;
- `state`: coarse lifecycle/operational state;
- `privacy`: explicit false guarantees for sensitive content classes;
- `acceptance`: runtime-acceptance and production-approval boundaries;
- `capabilities`: unique capability identifiers with coarse states.

The development server currently reports `development` and `pending` capability states. It must not claim runtime acceptance, production approval, certificate readiness, or publication readiness until those claims are backed by target-environment evidence.

## Forbidden status content

The contract must not contain credentials, API tokens, certificate/key material, private keys, raw logs, request data, client addresses, DNS query data, peer identities, route inventories, or personal records.

## Current authority boundary

Caddy remains the current HTTPS/reverse-proxy data plane. This foundation does not mutate Caddy configuration and does not expose a Caddy administration API. GoreeCloud Gateway is establishing the GoreeCloud-owned control-plane and publication-policy boundary first.

## Manager handoff

When `GOREECLOUD_GATEWAY_STATUS_FILE` is configured, Gateway atomically writes the sanitized envelope to that path. A Manager deployment can mount the file read-only and validate it without receiving Gateway or Caddy credentials.

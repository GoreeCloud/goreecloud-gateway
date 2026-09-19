# Caddy VPS Read-Only Preflight

## Purpose

`deploy/vps/caddy-read-only-preflight.sh` captures the minimum live target evidence needed to begin Caddy-to-Gateway migration review without changing Caddy, Docker, firewall, DNS, certificates, or listener ownership.

It is a discovery/reporting tool only. Its output is not migration acceptance, does not create the reviewed migration-source manifest, and cannot authorize production cutover.

## Safety boundary

The script declares and preserves:

- `mode=read-only`;
- `mutation_permitted=no`;
- `secret_values_printed=no`;
- `live_provider_query_performed=no`; and
- `caddy_production_authority_unchanged=yes`.

It does not run Docker start/stop/restart/remove operations, Docker Compose mutation, Caddy reload, systemctl mutation, firewall mutation, DNS-provider requests, ACME requests, certificate renewal, or file writes.

The only `docker exec` operations are read-only commands: Caddy version, configuration SHA-256, and either Caddy configuration adaptation or raw native-JSON reading piped directly into the sanitizer. The adapted/native configuration is never printed. Environment variables are never inspected or emitted.

## Collected evidence

The report includes:

- host/kernel/architecture and Docker/Compose versions;
- Caddy container image identity, state, restart policy, Compose project/service labels, config path, adapter, and config SHA-256;
- mount identities and Compose file paths plus hashes, never file contents;
- published Docker ports;
- Caddy Docker network names and Caddy addresses;
- sanitized Caddy structure derived in memory:
  - HTTP server/listener counts;
  - route host matchers;
  - reverse-proxy upstream dial targets;
  - handler module names;
  - TLS automation subjects;
  - issuer module names; and
  - DNS provider module name only;
- host TCP 80/443 and UDP 443 listeners;
- read-only firewall rules matching ports 80/443 when current privileges permit; and
- certificate metadata from Caddy's mounted data directory: relative certificate file identity, SHA-256, subject, issuer, serial, validity dates, fingerprint, and SAN extension.

Private-key files are never read. Raw Caddy configuration, Docker environment variables, API tokens, provider secrets, private keys, and full firewall configuration are never printed.

## Exact-source execution

Run only from an exact reviewed Gateway source revision. One bounded pattern is:

```sh
set -o pipefail

gh api \
  "repos/GoreeCloud/goreecloud-gateway/contents/deploy/vps/caddy-read-only-preflight.sh?ref=<EXACT_GATEWAY_REVISION>" \
  --jq .content \
| base64 -d \
| ssh goreecloud-vps-01 'bash -s'
```

Optional environment overrides may be supplied on the remote side when discovery cannot determine the correct values:

- `CADDY_CONTAINER`
- `CADDY_CONFIG_PATH`
- `CADDY_CONFIG_ADAPTER`

Do not supply credentials through these variables.

## Review rule

Before using the report as migration-source input:

1. retain the exact Gateway source revision used to run the collector;
2. independently review the reported container/config identity against the target VPS;
3. review the actual Caddy source configuration through the separately approved secure process;
4. construct and retain the governed migration-source manifest and independent review evidence;
5. use `gateway-migration-verify` only after that review; and
6. keep `production_cutover_authorized=false`.

Caddy remains production-authoritative until all target acceptance and governance gates pass.

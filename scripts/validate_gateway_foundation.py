#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "config" / "gateway.schema.json"
EXAMPLE = ROOT / "config" / "example.json"
CAPABILITIES = ROOT / "capabilities.json"
THREAT_MODEL = ROOT / "docs" / "security" / "threat-model.md"
PARITY_SOURCE = ROOT / "internal" / "config" / "parity.go"
PARITY_TEST = ROOT / "internal" / "config" / "parity_test.go"
PARITY_DOC = ROOT / "docs" / "configuration-parity.md"


def fail(message: str) -> None:
    print(f"gateway-foundation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path):
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT)}: {exc}")


def require_markers(path: Path, markers) -> None:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            fail(f"{path.relative_to(ROOT)} missing required marker: {marker}")


def unique_ids(items, kind):
    ids = [item.get("id") for item in items]
    if any(not value for value in ids):
        fail(f"{kind} contains a blank id")
    if len(ids) != len(set(ids)):
        fail(f"{kind} ids must be unique")
    return set(ids)


def capability_ids_from_contract(contract):
    entries = contract.get("capabilities", [])
    if not isinstance(entries, list):
        fail("capabilities must be an array")
    ids = set()
    for entry in entries:
        if isinstance(entry, str):
            capability_id = entry
        elif isinstance(entry, dict):
            capability_id = entry.get("id")
        else:
            fail("capability entries must be strings or objects with an id")
        if not capability_id:
            fail("capability entry has no id")
        ids.add(capability_id)
    return ids


def main() -> None:
    schema = load_json(SCHEMA)
    config = load_json(EXAMPLE)
    capabilities = load_json(CAPABILITIES)

    if schema.get("$id") != "https://goreecloud.com/schemas/gateway/config/v1":
        fail("unexpected configuration schema id")
    if config.get("schema") != "goreecloud-gateway-config/v1":
        fail("example configuration uses the wrong schema version")

    services = config.get("services", [])
    routes = config.get("routes", [])
    backends = config.get("backends", [])
    service_ids = unique_ids(services, "services")
    unique_ids(routes, "routes")
    backend_ids = unique_ids(backends, "backends")

    for service in services:
        refs = service.get("backend_ids", [])
        if not refs:
            fail(f"service {service['id']} has no backends")
        missing = sorted(set(refs) - backend_ids)
        if missing:
            fail(f"service {service['id']} references missing backends: {missing}")

    seen_route_keys = set()
    for route in routes:
        if route.get("service_id") not in service_ids:
            fail(f"route {route['id']} references a missing service")
        hostname = str(route.get("hostname", "")).strip().lower().rstrip(".")
        path_prefix = route.get("path_prefix", "")
        if not hostname or not path_prefix.startswith("/"):
            fail(f"route {route['id']} has an invalid hostname or path")
        key = (hostname, path_prefix, tuple(sorted(route.get("methods", []))))
        if key in seen_route_keys:
            fail(f"conflicting duplicate route match: {key}")
        seen_route_keys.add(key)
        exposure = route.get("exposure")
        tls_mode = route.get("tls", {}).get("mode")
        if exposure in {"restricted-public", "public"} and tls_mode != "required":
            fail(f"route {route['id']} cannot expose public traffic without required TLS")
        if route.get("enabled"):
            fail("Milestone 0 example routes must remain disabled")

    for backend in backends:
        url = backend.get("url", "")
        if not (url.startswith("http://") or url.startswith("https://")):
            fail(f"backend {backend['id']} uses an unsupported URL")

    capability_ids = capability_ids_from_contract(capabilities)
    required_caps = {
        "http_reverse_proxy",
        "https_termination",
        "host_path_header_method_routing",
        "certificate_inventory",
        "configuration_validation",
        "rollback",
    }
    missing_caps = sorted(required_caps - capability_ids)
    if missing_caps:
        fail(f"capability contract is missing: {missing_caps}")

    if not THREAT_MODEL.is_file():
        fail("missing threat model")
    threat_text = THREAT_MODEL.read_text(encoding="utf-8")
    for marker in ["listener ownership", "unsafe public exposure", "last known-good", "sensitive headers", "Caddy"]:
        if marker.lower() not in threat_text.lower():
            fail(f"threat model missing required boundary: {marker}")

    require_markers(PARITY_SOURCE, [
        "goreecloud-gateway-config-parity-evidence/v1",
        "ConfigParityFingerprint",
        "BuildConfigParityEvidence",
        "ValidateConfigParityEvidence",
        "ProductionCutoverAuthorized",
    ])
    require_markers(PARITY_TEST, [
        "TestConfigParityFingerprintIsOrderIndependent",
        "TestConfigParityFingerprintChangesWithRouteSemantics",
        "TestBuildAndValidateConfigParityEvidence",
        "TestValidateConfigParityEvidenceRejectsMismatchAndCutover",
    ])
    require_markers(PARITY_DOC, [
        "independently reviewed",
        "SHA-256",
        "production cutover",
        "Caddy",
    ])

    print("gateway-foundation: PASS")


if __name__ == "__main__":
    main()

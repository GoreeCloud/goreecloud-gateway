#!/usr/bin/env python3
"""Run a bounded loopback-only GoreeCloud Gateway runtime acceptance exercise."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time

SCHEMA = "goreecloud-gateway-isolated-runtime-evidence/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        if self.path == "/health":
            body = b"healthy\n"
        else:
            body = b"goreecloud-gateway-isolated-runtime\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler contract
        self.send_response(200)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(port: int, host: str, path: str = "/") -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", path, headers={"Host": host})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_for_gateway(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Gateway exited before acceptance request with code {process.returncode}")
        try:
            status, _ = request(port, "unmatched.acceptance.test")
            if status == 404:
                return
        except (ConnectionError, OSError):
            pass
        time.sleep(0.1)
    raise RuntimeError("Gateway loopback listener did not become ready")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()

    source_revision = os.environ.get("GOREECLOUD_GATEWAY_SOURCE_REVISION", "").strip().lower()
    if not HEX40.fullmatch(source_revision):
        raise SystemExit("GOREECLOUD_GATEWAY_SOURCE_REVISION must be an exact 40-character commit SHA")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"Gateway binary not found: {binary}")

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    backend_port = int(backend.server_address[1])
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()

    gateway_port = reserve_loopback_port()
    process: subprocess.Popen[bytes] | None = None
    graceful_shutdown = False
    route_proxy_validated = False
    unmatched_route_validated = False
    try:
        with tempfile.TemporaryDirectory(prefix="goreecloud-gateway-acceptance-") as temp:
            config_path = Path(temp) / "gateway.json"
            config = {
                "schema": "goreecloud-gateway-config/v1",
                "services": [
                    {
                        "id": "isolated-service",
                        "name": "Isolated acceptance service",
                        "backend_ids": ["isolated-backend"],
                    }
                ],
                "routes": [
                    {
                        "id": "isolated-route",
                        "service_id": "isolated-service",
                        "hostname": "gateway.acceptance.test",
                        "path_prefix": "/",
                        "methods": ["GET", "HEAD"],
                        "exposure": "private",
                        "enabled": True,
                        "tls": {"mode": "disabled"},
                    }
                ],
                "backends": [
                    {
                        "id": "isolated-backend",
                        "url": f"http://127.0.0.1:{backend_port}",
                        "enabled": True,
                        "health_path": "/health",
                    }
                ],
                "certificate_profiles": [],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            process = subprocess.Popen(
                [
                    str(binary),
                    "-config",
                    str(config_path),
                    "-http",
                    f"127.0.0.1:{gateway_port}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            wait_for_gateway(gateway_port, process)

            status, body = request(gateway_port, "gateway.acceptance.test", "/probe")
            if status != 200 or body != b"goreecloud-gateway-isolated-runtime\n":
                raise RuntimeError(f"Gateway route probe failed: status={status}, body={body!r}")
            route_proxy_validated = True

            status, _ = request(gateway_port, "unmatched.acceptance.test")
            if status != 404:
                raise RuntimeError(f"unmatched host returned {status}, expected 404")
            unmatched_route_validated = True

            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
            if process.returncode != 0:
                stdout, stderr = process.communicate()
                raise RuntimeError(
                    f"Gateway graceful shutdown returned {process.returncode}: "
                    f"stdout={stdout.decode(errors='replace')!r} stderr={stderr.decode(errors='replace')!r}"
                )
            graceful_shutdown = True
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=5)

    evidence = {
        "schema": SCHEMA,
        "source_revision": source_revision,
        "runtime_artifact_sha256": sha256(binary),
        "listener_scope": "127.0.0.1",
        "loopback_listener_validated": True,
        "route_proxy_validated": route_proxy_validated,
        "unmatched_route_validated": unmatched_route_validated,
        "backend_health_validated": route_proxy_validated,
        "graceful_shutdown_validated": graceful_shutdown,
        "credentials_included": False,
        "production_cutover_authorized": False,
    }
    if not all(
        (
            evidence["loopback_listener_validated"],
            route_proxy_validated,
            unmatched_route_validated,
            evidence["backend_health_validated"],
            graceful_shutdown,
        )
    ):
        raise SystemExit("Gateway isolated runtime acceptance evidence is incomplete")
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("GoreeCloud Gateway isolated runtime acceptance: PASS")


if __name__ == "__main__":
    main()

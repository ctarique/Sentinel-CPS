"""Live loopback authorization tests against an isolated Flask process."""

from __future__ import annotations

import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
OPERATOR_TOKEN = "a" * 64
MITIGATION_TOKEN = "b" * 64
INVALID_TOKEN = "c" * 64


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def request(
    base_url: str,
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    outgoing = urllib.request.Request(
        base_url + path,
        data=body,
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(outgoing, timeout=3) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


class LiveAuthorizationTests(unittest.TestCase):
    def test_live_role_separation_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel_live_auth_") as root:
            temporary_root = Path(root)
            data_dir = temporary_root / "data"
            config_path = temporary_root / "config.json"
            server_log = temporary_root / "server.log"
            port = reserve_loopback_port()
            config = json.loads(
                (BASE_DIR / "deploy" / "config.mock.json").read_text(
                    encoding="utf-8"
                )
            )
            config.update(
                {
                    "host": "127.0.0.1",
                    "port": port,
                    "mitigation_api_enabled": True,
                }
            )
            config_path.write_text(json.dumps(config) + "\n", encoding="utf-8")

            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPYCACHEPREFIX": str(temporary_root / "pycache"),
                    "PYTHONUNBUFFERED": "1",
                    "SENTINEL_GATEWAY_CONFIG": str(config_path),
                    "SENTINEL_GATEWAY_DATA_DIR": str(data_dir),
                    "SENTINEL_OPERATOR_TOKEN": OPERATOR_TOKEN,
                    "SENTINEL_MITIGATION_TOKEN": MITIGATION_TOKEN,
                }
            )
            base_url = f"http://127.0.0.1:{port}"
            observed_bodies: list[str] = []

            with server_log.open("w", encoding="utf-8") as log_handle:
                process = subprocess.Popen(
                    [sys.executable, str(BASE_DIR / "app.py")],
                    cwd=BASE_DIR,
                    env=environment,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        if process.poll() is not None:
                            self.fail(
                                "isolated Gateway exited during startup: "
                                + server_log.read_text(encoding="utf-8")
                            )
                        try:
                            status, health = request(base_url, "GET", "/api/health")
                            if status == 200:
                                observed_bodies.append(health)
                                break
                        except urllib.error.URLError:
                            pass
                        if time.monotonic() >= deadline:
                            self.fail("isolated Gateway did not become ready")
                        time.sleep(0.05)

                    status, display = request(base_url, "GET", "/display")
                    observed_bodies.append(display)
                    self.assertEqual(status, 200)
                    lowered_display = display.lower()
                    for forbidden in (
                        "<form",
                        "<input",
                        "<button",
                        "<textarea",
                        "/api/command",
                        "/api/mitigation/stop",
                        "x-sentinel-operator-token",
                        "method: 'post'",
                    ):
                        with self.subTest(forbidden=forbidden):
                            self.assertNotIn(forbidden, lowered_display)

                    for path in ("/api/track", "/api/display/status"):
                        status, body = request(base_url, "GET", path)
                        observed_bodies.append(body)
                        self.assertEqual(status, 200)

                    _, original_track_body = request(base_url, "GET", "/api/track")
                    original_track = json.loads(original_track_body)
                    log_before = server_log.read_text(encoding="utf-8")
                    status, body = request(
                        base_url,
                        "POST",
                        "/api/command",
                        payload={"command": "START"},
                    )
                    observed_bodies.append(body)
                    self.assertEqual(status, 401)
                    status, body = request(
                        base_url,
                        "POST",
                        "/api/command",
                        payload={"command": "START"},
                        headers={"X-Sentinel-Operator-Token": INVALID_TOKEN},
                    )
                    observed_bodies.append(body)
                    self.assertEqual(status, 403)
                    time.sleep(0.05)
                    log_after = server_log.read_text(encoding="utf-8")
                    self.assertEqual(
                        log_after.count("[SIM TX] ->"),
                        log_before.count("[SIM TX] ->"),
                    )

                    replacement = {
                        "centerline_points": [
                            {"x": 0.2, "y": 0.3},
                            {"x": 0.7, "y": 0.6},
                        ]
                    }
                    for headers, expected in (
                        ({}, 401),
                        ({"X-Sentinel-Operator-Token": INVALID_TOKEN}, 403),
                    ):
                        status, body = request(
                            base_url,
                            "POST",
                            "/api/track",
                            payload=replacement,
                            headers=headers,
                        )
                        observed_bodies.append(body)
                        self.assertEqual(status, expected)
                    _, unchanged_body = request(base_url, "GET", "/api/track")
                    self.assertEqual(json.loads(unchanged_body), original_track)

                    status, body = request(
                        base_url,
                        "POST",
                        "/api/command",
                        payload={"command": "RESET"},
                        headers={"X-Sentinel-Operator-Token": OPERATOR_TOKEN},
                    )
                    observed_bodies.append(body)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body)["result"], "ACKNOWLEDGED")

                    status, body = request(
                        base_url,
                        "POST",
                        "/api/track",
                        payload=replacement,
                        headers={"X-Sentinel-Operator-Token": OPERATOR_TOKEN},
                    )
                    observed_bodies.append(body)
                    self.assertEqual(status, 200)
                    _, stored_body = request(base_url, "GET", "/api/track")
                    self.assertEqual(json.loads(stored_body), replacement)

                    for extra_headers, expected in (
                        ({"X-Forwarded-For": "203.0.113.10"}, 401),
                        (
                            {
                                "X-Sentinel-Operator-Token": INVALID_TOKEN,
                                "X-Unrelated-Authorization": OPERATOR_TOKEN,
                            },
                            403,
                        ),
                    ):
                        status, body = request(
                            base_url,
                            "POST",
                            "/api/command",
                            payload={"command": "STOP"},
                            headers=extra_headers,
                        )
                        observed_bodies.append(body)
                        self.assertEqual(status, expected)

                    status, body = request(
                        base_url,
                        "POST",
                        "/api/mitigation/stop",
                        payload={},
                        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
                    )
                    observed_bodies.append(body)
                    self.assertEqual(status, 401)
                    status, body = request(
                        base_url,
                        "POST",
                        "/api/command",
                        payload={"command": "STOP"},
                        headers={"X-Sentinel-Operator-Token": MITIGATION_TOKEN},
                    )
                    observed_bodies.append(body)
                    self.assertEqual(status, 403)

                    status, health = request(base_url, "GET", "/api/health")
                    observed_bodies.append(health)
                    self.assertEqual(status, 200)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

            evidence_text = "\n".join(observed_bodies)
            evidence_text += server_log.read_text(encoding="utf-8")
            actions_path = data_dir / "actions.csv"
            with actions_path.open(newline="", encoding="utf-8") as handle:
                action_rows = list(csv.DictReader(handle))
            evidence_text += actions_path.read_text(encoding="utf-8")
            for path in sorted(data_dir.glob("*.csv")):
                evidence_text += path.read_text(encoding="utf-8")
            for credential in (OPERATOR_TOKEN, MITIGATION_TOKEN, INVALID_TOKEN):
                self.assertNotIn(credential, evidence_text)
            rejected_start_rows = [
                row
                for row in action_rows
                if row["command"] == "START"
                and row["details"].startswith("txid=")
            ]
            self.assertEqual(rejected_start_rows, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

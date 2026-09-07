#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from operator_token import OPERATOR_TOKEN_REQUIREMENT, is_valid_operator_token


BASE_URL = os.environ.get(
    "SENTINEL_GATEWAY_URL",
    "http://127.0.0.1:8080",
).rstrip("/")
OPERATOR_TOKEN = os.environ.get("SENTINEL_OPERATOR_TOKEN")
if not is_valid_operator_token(OPERATOR_TOKEN):
    raise SystemExit(
        "SENTINEL_OPERATOR_TOKEN must be set to a test deployment credential "
        f"containing {OPERATOR_TOKEN_REQUIREMENT}"
    )


def request_json(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    body = None
    headers = {}

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["X-Sentinel-Operator-Token"] = OPERATOR_TOKEN

    request = urllib.request.Request(
        BASE_URL + path,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        status = exc.code

    return status, json.loads(raw)


class GatewayLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        status, response = request_json(
            "POST", "/api/command", {"command": "RESET"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["result"], "ACKNOWLEDGED")

    def tearDown(self) -> None:
        """Return the live Gateway to its fail-safe state after every test."""
        status, response = request_json(
            "POST", "/api/command", {"command": "STOP"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["result"], "ACKNOWLEDGED")
        self.assertEqual(response["telemetry"]["state"], "LOCKED")

    def test_health_endpoint(self) -> None:
        status, response = request_json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["mode"], "mock")
        self.assertEqual(response["serial_transport"], "mock")
        self.assertEqual(response["port"], "/dev/ttyUSB0")
        self.assertIs(response["keepalive_enabled"], True)
        self.assertEqual(response["keepalive_interval_ms"], 3000)
        self.assertFalse(response["keepalive_active"])
        for field in (
            "last_keepalive_timestamp",
            "last_keepalive_result",
            "last_keepalive_ack_latency_ms",
            "keepalive_failure_count",
            "last_safety_stop_result",
            "safety_status",
        ):
            self.assertIn(field, response)

    def test_start_stop_reset_policy(self) -> None:
        status, started = request_json(
            "POST", "/api/command", {"command": "START"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(started["result"], "ACKNOWLEDGED")
        self.assertIsNotNone(started["ack_latency_ms"])
        self.assertIn("transaction_id", started)
        self.assertIn("command_total_ms", started)
        self.assertLess(
            started["gateway_processing_ms"], started["command_total_ms"]
        )
        self.assertEqual(started["telemetry"]["state"], "RUNNING")
        self.assertIn("gateway_processing_ms", started)

        status, running_health = request_json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(running_health["keepalive_active"])
        self.assertEqual(running_health["acknowledged_state"], "RUNNING")

        status, stopped = request_json(
            "POST", "/api/command", {"command": "STOP"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(stopped["result"], "ACKNOWLEDGED")
        self.assertEqual(stopped["telemetry"]["state"], "LOCKED")
        status, stopped_health = request_json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertFalse(stopped_health["keepalive_active"])

        status, rejected = request_json(
            "POST", "/api/command", {"command": "START"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(rejected["result"], "REJECTED_LOCKED")
        self.assertEqual(rejected["telemetry"]["state"], "LOCKED")

        status, reset = request_json(
            "POST", "/api/command", {"command": "RESET"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(reset["result"], "ACKNOWLEDGED")

        status, restarted = request_json(
            "POST", "/api/command", {"command": "START"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(restarted["result"], "ACKNOWLEDGED")

        status, reported = request_json(
            "POST", "/api/command", {"command": "STATUS"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(reported["result"], "ACKNOWLEDGED")

    def test_invalid_command_is_rejected(self) -> None:
        status, response = request_json(
            "POST", "/api/command", {"command": "UNSAFE_COMMAND"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(response["error"], "Invalid command")
        self.assertIn("event_id", response)

    def test_track_validation(self) -> None:
        status, valid = request_json(
            "POST",
            "/api/track",
            {
                "centerline_points": [
                    {"x": 100, "y": 100},
                    {"x": 200, "y": 150},
                    {"x": 300, "y": 200},
                ]
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(valid["status"], "logged")
        self.assertEqual(valid["centerline_points"], 3)

        status, invalid = request_json(
            "POST",
            "/api/track",
            {"centerline_points": [{"x": "bad", "y": 100}]},
        )
        self.assertEqual(status, 400)
        self.assertIn("non-numeric", invalid["error"])

    def test_metrics_endpoint(self) -> None:
        request_json("POST", "/api/command", {"command": "PING"})
        status, response = request_json("GET", "/api/metrics")

        self.assertEqual(status, 200)
        self.assertGreaterEqual(response["sample_count"], 1)
        self.assertIn("overall", response)
        self.assertIn("by_command", response)
        self.assertIn("measurement", response)
        self.assertIn("automatic_keepalive", response)


if __name__ == "__main__":
    unittest.main(verbosity=2)

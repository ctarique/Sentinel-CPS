"""Application-layer role separation tests for Gateway HTTP clients."""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


TEST_OPERATOR_TOKEN = "a" * 64
TEST_MITIGATION_TOKEN = "TEST_ONLY_MITIGATION_TOKEN_FOR_ROLE_SEPARATION_2026"
INVALID_OPERATOR_TOKEN = "b" * 63
os.environ.setdefault("SENTINEL_OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)

TEST_DATA_DIR = None
if "SENTINEL_GATEWAY_DATA_DIR" not in os.environ:
    TEST_DATA_DIR = tempfile.TemporaryDirectory(prefix="sentinel_role_tests_")
    os.environ["SENTINEL_GATEWAY_DATA_DIR"] = TEST_DATA_DIR.name

import app  # noqa: E402


BASE_DIR = Path(app.__file__).resolve().parent


class OperatorAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        app.bridge._set_control_state(
            locked=True,
            acknowledged_state="LOCKED",
            local_lock_reason="TEST_SETUP",
            force_generation=True,
        )
        app.bridge._set_telemetry_state(
            "LOCKED", vehicle_id="role_test", source="test_setup"
        )
        with app.track_lock:
            app.current_centerline_points[:] = [
                dict(point) for point in app.DEFAULT_CENTERLINE_POINTS
            ]

    @staticmethod
    def operator_headers(token: str | None = None) -> dict[str, str]:
        return {
            app.OPERATOR_TOKEN_HEADER: app.OPERATOR_TOKEN if token is None else token
        }

    def assert_credential_absent(self, credential: str, content: str) -> None:
        self.assertFalse(
            credential in content,
            "credential value unexpectedly appeared in inspected output",
        )

    def post_command(self, command: str, headers=None):
        with app.app.test_client() as client:
            return client.post(
                "/api/command", json={"command": command}, headers=headers or {}
            )

    def test_start_stop_and_reset_missing_token_return_401_without_dispatch(self) -> None:
        with mock.patch.object(app.bridge, "write", wraps=app.bridge.write) as write_spy:
            for command in ("START", "STOP", "RESET"):
                with self.subTest(command=command):
                    response = self.post_command(command)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(
                        response.get_json(),
                        {"error": "Operator authorization required."},
                    )
        write_spy.assert_not_called()
        self.assertTrue(app.bridge.get_status()["gateway_locked"])

    def test_start_stop_and_reset_invalid_token_return_403_without_dispatch(self) -> None:
        headers = self.operator_headers(INVALID_OPERATOR_TOKEN)
        with mock.patch.object(app.bridge, "write", wraps=app.bridge.write) as write_spy:
            for command in ("START", "STOP", "RESET"):
                with self.subTest(command=command):
                    response = self.post_command(command, headers)
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(
                        response.get_json(),
                        {"error": "Operator authorization required."},
                    )
        write_spy.assert_not_called()
        self.assertTrue(app.bridge.get_status()["gateway_locked"])

    def test_valid_start_reaches_existing_locked_policy(self) -> None:
        response = self.post_command("START", self.operator_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], "REJECTED_LOCKED")
        self.assertTrue(app.bridge.get_status()["gateway_locked"])

    def test_valid_stop_reaches_existing_command_policy(self) -> None:
        response = self.post_command("STOP", self.operator_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], "ACKNOWLEDGED")
        self.assertEqual(response.get_json()["telemetry"]["state"], "LOCKED")

    def test_valid_reset_reaches_existing_command_policy(self) -> None:
        response = self.post_command("RESET", self.operator_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], "ACKNOWLEDGED")
        self.assertFalse(app.bridge.get_status()["gateway_locked"])

    def test_status_ping_and_unknown_command_paths_are_protected(self) -> None:
        for command in ("STATUS", "PING", "UNSAFE_COMMAND"):
            with self.subTest(command=command):
                self.assertEqual(self.post_command(command).status_code, 401)
                self.assertEqual(
                    self.post_command(
                        command, self.operator_headers(INVALID_OPERATOR_TOKEN)
                    ).status_code,
                    403,
                )

        for command in ("STATUS", "PING"):
            with self.subTest(valid_command=command):
                self.assertEqual(
                    self.post_command(command, self.operator_headers()).status_code,
                    200,
                )
        self.assertEqual(
            self.post_command(
                "UNSAFE_COMMAND", self.operator_headers()
            ).status_code,
            400,
        )

    def test_track_replacement_requires_operator_and_get_remains_read_only(self) -> None:
        replacement = {
            "centerline_points": [
                {"x": 0.1, "y": 0.2},
                {"x": 0.8, "y": 0.7},
            ]
        }
        with app.track_lock:
            original = [dict(point) for point in app.current_centerline_points]

        with app.app.test_client() as client:
            missing = client.post("/api/track", json=replacement)
            invalid = client.post(
                "/api/track",
                json=replacement,
                headers=self.operator_headers(INVALID_OPERATOR_TOKEN),
            )
            unchanged = client.get("/api/track")
            valid = client.post(
                "/api/track", json=replacement, headers=self.operator_headers()
            )
            stored = client.get("/api/track")

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(invalid.status_code, 403)
        self.assertEqual(unchanged.get_json()["centerline_points"], original)
        self.assertEqual(valid.status_code, 200)
        self.assertEqual(valid.get_json()["status"], "logged")
        self.assertEqual(stored.get_json(), replacement)

    def test_read_only_routes_do_not_dispatch_or_change_state(self) -> None:
        status_before = app.bridge.get_status()
        telemetry_before = app.bridge.get_latest_telemetry()
        with app.track_lock:
            track_before = [dict(point) for point in app.current_centerline_points]

        with mock.patch.object(app.bridge, "write", wraps=app.bridge.write) as write_spy:
            with app.app.test_client() as client:
                responses = (
                    client.get("/display"),
                    client.get("/api/display/status"),
                    client.get("/api/health"),
                    client.get("/api/telemetry"),
                    client.get("/api/metrics"),
                    client.get("/api/track"),
                )

        self.assertTrue(all(response.status_code == 200 for response in responses))
        write_spy.assert_not_called()
        status_after = app.bridge.get_status()
        self.assertEqual(
            status_after["gateway_locked"], status_before["gateway_locked"]
        )
        self.assertEqual(
            status_after["acknowledged_state"], status_before["acknowledged_state"]
        )
        self.assertEqual(app.bridge.get_latest_telemetry(), telemetry_before)
        with app.track_lock:
            self.assertEqual(app.current_centerline_points, track_before)

    def test_display_contains_only_read_only_workflow(self) -> None:
        with app.app.test_client() as client:
            response = client.get("/display")
        html = response.get_data(as_text=True)
        lowered = html.lower()
        self.assertEqual(response.status_code, 200)
        self.assertIn("read-only laboratory display", lowered)
        self.assertIn("/api/track", html)
        self.assertIn("/api/display/status", html)
        for forbidden in (
            "<button",
            "<form",
            "<input",
            "<textarea",
            "/api/command",
            "/api/mitigation/stop",
            "method: 'post'",
            "x-sentinel-operator-token",
            "sessionstorage",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)
        for credential in (
            app.OPERATOR_TOKEN,
            TEST_OPERATOR_TOKEN,
            TEST_MITIGATION_TOKEN,
        ):
            self.assert_credential_absent(credential, html)

    def test_display_status_exposes_only_selected_read_only_fields(self) -> None:
        with app.app.test_client() as client:
            body = client.get("/api/display/status").get_json()
        self.assertEqual(
            set(body),
            {"gateway_locked", "acknowledged_state", "vehicle_state", "steer"},
        )
        for sensitive_field in ("port", "baud", "transport_error", "mode"):
            self.assertNotIn(sensitive_field, body)

    def test_operator_dashboard_uses_session_storage_and_protected_header(self) -> None:
        with app.app.test_client() as client:
            html = client.get("/").get_data(as_text=True)
        lowered = html.lower()
        self.assertIn('type="password"', lowered)
        self.assertIn("sessionstorage", lowered)
        self.assertNotIn("localstorage", lowered)
        self.assertIn(app.OPERATOR_TOKEN_HEADER, html)
        self.assert_credential_absent(app.OPERATOR_TOKEN, html)
        self.assert_credential_absent(TEST_MITIGATION_TOKEN, html)

    def test_credentials_remain_independent(self) -> None:
        original_manager = app.mitigation_manager
        manager = app.MitigationManager(
            app.bridge,
            enabled=True,
            loopback_only=True,
            cache_size=8,
            token=TEST_MITIGATION_TOKEN,
        )
        app.mitigation_manager = manager
        try:
            with app.app.test_client() as client:
                operator_for_mitigation = client.post(
                    "/api/mitigation/stop",
                    json={},
                    headers={"Authorization": f"Bearer {app.OPERATOR_TOKEN}"},
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                mitigation_for_operator = client.post(
                    "/api/command",
                    json={"command": "STOP"},
                    headers={app.OPERATOR_TOKEN_HEADER: TEST_MITIGATION_TOKEN},
                )
        finally:
            app.mitigation_manager = original_manager

        self.assertEqual(operator_for_mitigation.status_code, 401)
        self.assertEqual(mitigation_for_operator.status_code, 403)

    def test_authorization_failures_do_not_leak_credentials(self) -> None:
        before_rows = self._action_rows()
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            response = self.post_command(
                "START", self.operator_headers(INVALID_OPERATOR_TOKEN)
            )
        new_rows = self._action_rows()[len(before_rows):]
        combined_response = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 403)
        self.assert_credential_absent(INVALID_OPERATOR_TOKEN, output.getvalue())
        self.assert_credential_absent(INVALID_OPERATOR_TOKEN, combined_response)
        self.assert_credential_absent(app.OPERATOR_TOKEN, combined_response)
        self.assertTrue(new_rows)
        self.assertEqual(new_rows[-1]["command"], "OPERATOR_AUTHORIZATION")
        self.assertEqual(new_rows[-1]["details"], "operator_authorization_invalid")

        for path in (app.ACTIONS_CSV, app.TELEMETRY_CSV, app.PERFORMANCE_CSV):
            content = path.read_text(encoding="utf-8")
            self.assert_credential_absent(INVALID_OPERATOR_TOKEN, content)
            self.assert_credential_absent(app.OPERATOR_TOKEN, content)
            self.assert_credential_absent(TEST_MITIGATION_TOKEN, content)

    def test_operator_token_is_absent_from_read_only_api_responses(self) -> None:
        with app.app.test_client() as client:
            bodies = (
                client.get("/api/display/status").get_data(as_text=True),
                client.get("/api/health").get_data(as_text=True),
                client.get("/api/telemetry").get_data(as_text=True),
                client.get("/api/metrics").get_data(as_text=True),
                client.get("/api/track").get_data(as_text=True),
            )
        for body in bodies:
            self.assert_credential_absent(app.OPERATOR_TOKEN, body)
            self.assert_credential_absent(TEST_MITIGATION_TOKEN, body)

    def test_non_ascii_invalid_token_is_rejected_without_server_error(self) -> None:
        response = self.post_command(
            "START", self.operator_headers("INVALID_TEST_ONLY_CREDENTIAL_é_2026")
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json(), {"error": "Operator authorization required."}
        )

    @staticmethod
    def _action_rows() -> list[dict[str, str]]:
        with app.ACTIONS_CSV.open("r", newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))


class OperatorStartupTests(unittest.TestCase):
    def run_import(self, config_name: str, token_marker=...) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["SENTINEL_GATEWAY_CONFIG"] = str(
            BASE_DIR / "deploy" / config_name
        )
        with tempfile.TemporaryDirectory(prefix="sentinel_startup_auth_") as data_dir:
            environment["SENTINEL_GATEWAY_DATA_DIR"] = data_dir
            if token_marker is ...:
                environment.pop("SENTINEL_OPERATOR_TOKEN", None)
            else:
                environment["SENTINEL_OPERATOR_TOKEN"] = token_marker
            return subprocess.run(
                [sys.executable, "-c", "import app"],
                cwd=BASE_DIR,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

    def test_hardware_mode_fails_closed_when_token_missing(self) -> None:
        result = self.run_import("config.hardware.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SENTINEL_OPERATOR_TOKEN is required", result.stderr)
        self.assertNotIn("/dev/ttyUSB0", result.stdout + result.stderr)

    def test_hardware_mode_fails_closed_when_token_empty(self) -> None:
        result = self.run_import("config.hardware.json", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SENTINEL_OPERATOR_TOKEN is required", result.stderr)
        self.assertNotIn("/dev/ttyUSB0", result.stdout + result.stderr)

    def test_mock_mode_also_requires_explicit_token(self) -> None:
        result = self.run_import("config.mock.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SENTINEL_OPERATOR_TOKEN is required", result.stderr)

    def test_explicit_test_token_allows_mock_startup_without_a_default(self) -> None:
        result = self.run_import("config.mock.json", TEST_OPERATOR_TOKEN)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(
            TEST_OPERATOR_TOKEN in result.stdout + result.stderr,
            "test credential unexpectedly appeared in startup output",
        )

    def test_operator_token_contract_is_exact_lowercase_hex(self) -> None:
        valid = "a" * 64
        for invalid in (
            "",
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "g" * 64,
            " a" * 32,
            '"' + valid + '"',
            "${TOKEN}" + "a" * 56,
            "a" * 63 + "\\",
        ):
            with self.subTest(invalid=repr(invalid)):
                result = self.run_import("config.mock.json", invalid)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exactly 64 lowercase hexadecimal", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for the Gateway fail-safe startup policy."""

import os
import tempfile
import unittest


os.environ.setdefault("SENTINEL_OPERATOR_TOKEN", "a" * 64)

TEST_DATA_DIR = None
if "SENTINEL_GATEWAY_DATA_DIR" not in os.environ:
    TEST_DATA_DIR = tempfile.TemporaryDirectory(
        prefix="sentinel_safe_boot_tests_"
    )
    os.environ["SENTINEL_GATEWAY_DATA_DIR"] = TEST_DATA_DIR.name

import app


INITIAL_STATUS = app.bridge.get_status().copy()
INITIAL_LOCKED = app.bridge.locked
INITIAL_SAFE_BOOT_LOCKED = app.bridge.safe_boot_locked


class GatewaySafeBootTests(unittest.TestCase):
    def setUp(self) -> None:
        app.bridge.locked = True
        app.bridge._set_telemetry_state(
            "LOCKED",
            vehicle_id="gateway_safe_boot_test",
            source="test_setup",
        )

    def tearDown(self) -> None:
        app.bridge.locked = True
        app.bridge._set_telemetry_state(
            "LOCKED",
            vehicle_id="gateway_safe_boot_test",
            source="test_teardown",
        )

    def test_gateway_starts_locked(self) -> None:
        self.assertTrue(INITIAL_SAFE_BOOT_LOCKED)
        self.assertTrue(INITIAL_LOCKED)
        self.assertTrue(INITIAL_STATUS["gateway_locked"])
        self.assertTrue(INITIAL_STATUS["safe_boot_locked"])
        self.assertEqual(INITIAL_STATUS["vehicle_state"], "LOCKED")

    def test_start_is_rejected_before_reset(self) -> None:
        success, result = app.bridge.write("START")

        self.assertFalse(success)
        self.assertEqual(result, "REJECTED_LOCKED")
        self.assertTrue(app.bridge.locked)
        self.assertEqual(
            app.bridge.get_latest_telemetry()["state"],
            "LOCKED",
        )

    def test_reset_unlocks_gateway(self) -> None:
        success, result = app.bridge.write("RESET")

        self.assertTrue(success)
        self.assertEqual(result, "ACKNOWLEDGED")
        self.assertFalse(app.bridge.locked)

        success, result = app.bridge.write("START")

        self.assertTrue(success)
        self.assertEqual(result, "ACKNOWLEDGED")
        self.assertEqual(
            app.bridge.get_latest_telemetry()["state"],
            "RUNNING",
        )


if __name__ == "__main__":
    unittest.main()

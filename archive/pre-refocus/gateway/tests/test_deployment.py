"""Deterministic tests for the managed Gateway deployment boundary."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEPLOY_DIR = BASE_DIR / "deploy"
VALIDATOR = DEPLOY_DIR / "validate-environment.py"
VALID_TOKEN = "a" * 64


class EnvironmentValidationTests(unittest.TestCase):
    def run_validator(self, path: Path, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(path), *arguments],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_valid_environment_file_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel_env_valid_") as root:
            path = Path(root) / "gateway.env"
            path.write_text(
                "# Generated only on the deployment host\n"
                f"SENTINEL_OPERATOR_TOKEN={VALID_TOKEN}\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            result = self.run_validator(
                path,
                "--require-owner-uid",
                str(os.getuid()),
                "--require-owner-gid",
                str(os.getgid()),
                "--require-mode",
                "0600",
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_environment_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel_env_missing_") as root:
            result = self.run_validator(Path(root) / "missing.env")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is missing", result.stderr)

    def test_symlink_environment_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel_env_symlink_") as root:
            directory = Path(root)
            target = directory / "target.env"
            target.write_text(
                f"SENTINEL_OPERATOR_TOKEN={VALID_TOKEN}\n", encoding="utf-8"
            )
            link = directory / "gateway.env"
            link.symlink_to(target)
            result = self.run_validator(link)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be a symbolic link", result.stderr)

    def test_non_regular_environment_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel_env_types_") as root:
            directory = Path(root)
            fifo = directory / "gateway.fifo"
            os.mkfifo(fifo)
            for path in (directory, fifo, Path("/dev/null")):
                with self.subTest(path=str(path)):
                    result = self.run_validator(path)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must be a regular file", result.stderr)

    def test_unsafe_operator_assignments_are_rejected(self) -> None:
        unsafe_contents = {
            "missing": "SENTINEL_MITIGATION_TOKEN=test-only-value\n",
            "duplicate": (
                f"SENTINEL_OPERATOR_TOKEN={VALID_TOKEN}\n"
                f"SENTINEL_OPERATOR_TOKEN={'b' * 64}\n"
            ),
            "short": f"SENTINEL_OPERATOR_TOKEN={'a' * 63}\n",
            "long": f"SENTINEL_OPERATOR_TOKEN={'a' * 65}\n",
            "nonhex": f"SENTINEL_OPERATOR_TOKEN={'a' * 63}g\n",
            "uppercase": f"SENTINEL_OPERATOR_TOKEN={'A' * 64}\n",
            "leading-whitespace": f" SENTINEL_OPERATOR_TOKEN={VALID_TOKEN}\n",
            "value-whitespace": f"SENTINEL_OPERATOR_TOKEN={VALID_TOKEN} \n",
            "quoted": f'SENTINEL_OPERATOR_TOKEN="{VALID_TOKEN}"\n',
            "escaped": f"SENTINEL_OPERATOR_TOKEN={'a' * 63}\\\n",
            "substitution": "SENTINEL_OPERATOR_TOKEN=$(generate-token)\n",
            "placeholder": "SENTINEL_OPERATOR_TOKEN=REPLACE_WITH_RANDOM_SECRET\n",
            "inline-comment": f"SENTINEL_OPERATOR_TOKEN={VALID_TOKEN} # token\n",
        }
        with tempfile.TemporaryDirectory(prefix="sentinel_env_invalid_") as root:
            path = Path(root) / "gateway.env"
            for name, content in unsafe_contents.items():
                with self.subTest(name=name):
                    path.write_text(content, encoding="utf-8")
                    result = self.run_validator(path)
                    self.assertNotEqual(result.returncode, 0)
            path.write_bytes(
                f"SENTINEL_OPERATOR_TOKEN={'a' * 32}".encode()
                + b"\x00"
                + ("a" * 32).encode()
                + b"\n"
            )
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("control character", result.stderr)


class DeploymentStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = (DEPLOY_DIR / "install.sh").read_text(encoding="utf-8")
        cls.unit = (DEPLOY_DIR / "sentinel-gateway.service").read_text(
            encoding="utf-8"
        )

    def test_environment_validation_precedes_host_mutation(self) -> None:
        validation = self.installer.index(
            '"${SOURCE_DIR}/deploy/validate-environment.py"'
        )
        mutation_markers = (
            'chown root:root "${GATEWAY_ENV_FILE}"',
            'chmod 0600 "${GATEWAY_ENV_FILE}"',
            'groupadd --system "${SERVICE_GROUP}"',
            "useradd \\" + "\n        --system",
            "usermod \\" + "\n        --gid",
            '"${INSTALL_ROOT}"',
            "rsync -a \\",
            "install \\",
            "systemctl daemon-reload",
            "systemctl enable --now",
        )
        for marker in mutation_markers:
            with self.subTest(marker=marker):
                self.assertGreater(self.installer.index(marker), validation)

    def test_installer_produces_and_verifies_root_owned_mode_0600_file(self) -> None:
        self.assertIn('chown root:root "${GATEWAY_ENV_FILE}"', self.installer)
        self.assertIn('chmod 0600 "${GATEWAY_ENV_FILE}"', self.installer)
        for required in (
            "--require-owner-uid 0",
            "--require-owner-gid 0",
            "--require-mode 0600",
        ):
            self.assertIn(required, self.installer)

    def test_managed_unit_requires_the_environment_file(self) -> None:
        self.assertIn(
            "EnvironmentFile=/etc/sentinel-cps/gateway.env", self.unit.splitlines()
        )

    def test_installer_and_application_share_the_token_validator(self) -> None:
        application = (BASE_DIR / "app.py").read_text(encoding="utf-8")
        validator = VALIDATOR.read_text(encoding="utf-8")
        for source in (application, validator):
            self.assertIn("from operator_token import", source)
            self.assertIn("is_valid_operator_token", source)

    def test_stale_root_deployment_artifacts_are_absent(self) -> None:
        self.assertFalse((BASE_DIR / "sentinel.service").exists())
        self.assertFalse((BASE_DIR / "index.html").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

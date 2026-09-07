#!/usr/bin/env python3
"""Validate the Gateway EnvironmentFile without evaluating its contents."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOURCE_DIR))

from operator_token import (  # noqa: E402
    OPERATOR_TOKEN_ENV,
    OPERATOR_TOKEN_REQUIREMENT,
    is_valid_operator_token,
)


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def validate_path(path: Path) -> os.stat_result:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        fail(f"Required Gateway environment file is missing: {path}")
    except OSError as exc:
        fail(f"Cannot inspect Gateway environment file {path}: {exc}")

    if stat.S_ISLNK(path_stat.st_mode):
        fail(f"Gateway environment path must not be a symbolic link: {path}")
    if not stat.S_ISREG(path_stat.st_mode):
        fail(f"Gateway environment path must be a regular file: {path}")
    return path_stat


def validate_contents(path: Path) -> None:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fail(f"Cannot read Gateway environment file {path}: {exc}")

    if any(byte < 32 and byte != 10 or byte == 127 for byte in raw):
        fail("Gateway environment file contains a control character")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("Gateway environment file must be valid UTF-8")

    assignments: list[str] = []
    prefix = f"{OPERATOR_TOKEN_ENV}="
    for line in text.split("\n"):
        if not line or line.startswith("#"):
            continue
        if OPERATOR_TOKEN_ENV not in line:
            continue
        if not line.startswith(prefix):
            fail(
                f"{OPERATOR_TOKEN_ENV} must use an exact unquoted KEY=value assignment"
            )
        assignments.append(line[len(prefix) :])

    if not assignments:
        fail(f"Gateway environment file is missing {OPERATOR_TOKEN_ENV}")
    if len(assignments) != 1:
        fail(
            "Gateway environment file contains duplicate "
            f"{OPERATOR_TOKEN_ENV} assignments"
        )
    if not is_valid_operator_token(assignments[0]):
        fail(f"{OPERATOR_TOKEN_ENV} must contain {OPERATOR_TOKEN_REQUIREMENT}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--require-owner-uid", type=int)
    parser.add_argument("--require-owner-gid", type=int)
    parser.add_argument("--require-mode", type=lambda value: int(value, 8))
    args = parser.parse_args(argv)

    path_stat = validate_path(args.path)
    validate_contents(args.path)

    if (
        args.require_owner_uid is not None
        and path_stat.st_uid != args.require_owner_uid
    ):
        fail("Gateway environment file has an unexpected owner UID")
    if (
        args.require_owner_gid is not None
        and path_stat.st_gid != args.require_owner_gid
    ):
        fail("Gateway environment file has an unexpected owner GID")
    if (
        args.require_mode is not None
        and stat.S_IMODE(path_stat.st_mode) != args.require_mode
    ):
        fail("Gateway environment file has an unexpected permission mode")

    print("PASS: Gateway environment file is safe and the operator token is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

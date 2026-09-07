"""Shared Sentinel-CPS operator-token contract."""

from __future__ import annotations

import re


OPERATOR_TOKEN_ENV = "SENTINEL_OPERATOR_TOKEN"
OPERATOR_TOKEN_HEADER = "X-Sentinel-Operator-Token"
OPERATOR_TOKEN_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
OPERATOR_TOKEN_REQUIREMENT = "exactly 64 lowercase hexadecimal characters"


def is_valid_operator_token(token: object) -> bool:
    """Return whether *token* meets the shared deployment/runtime contract."""

    return (
        isinstance(token, str)
        and OPERATOR_TOKEN_PATTERN.fullmatch(token) is not None
    )

#!/usr/bin/env python3
"""Create sanitized copies of Sentinel-CPS evidence files.

This helper does not modify originals. It is not perfect; manually review all
redacted files before publishing.
"""

import argparse
import os
import re
from pathlib import Path

TEXT_EXTS = {".txt", ".csv", ".log", ".md", ".json", ".service", ".conf"}

PATTERNS = [
    (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "[REDACTED_IPV4]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"), "[REDACTED_IPV6]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "[REDACTED_MAC]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\b"), "[REDACTED_MAC]"),
    (re.compile(r"/home/[^/\s]+"), "/home/[REDACTED_USER]"),
    (re.compile(r"/Users/[^/\s]+"), "/Users/[REDACTED_USER]"),
    (re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?i)\b(hostname|static hostname|transient hostname|pretty hostname):\s*[^\n]+"), r"\1: [REDACTED_HOSTNAME]"),
    (re.compile(r"(?i)\buser=([A-Za-z0-9._-]+)"), "user=[REDACTED_USER]"),
]


def redact_text(text: str) -> str:
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_file(path: Path, output_root: Path, base_root: Path) -> Path:
    rel_path = path.relative_to(base_root) if path.is_relative_to(base_root) else Path(path.name)
    out_path = output_root / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    data = path.read_text(encoding="utf-8", errors="ignore")
    redacted = redact_text(data)
    out_path.write_text(redacted, encoding="utf-8")
    return out_path


def gather_files(target: Path, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target]
    if not target.is_dir():
        raise FileNotFoundError(str(target))
    pattern = "**/*" if recursive else "*"
    return [p for p in target.glob(pattern) if p.is_file() and p.suffix.lower() in TEXT_EXTS and "redacted" not in p.parts]


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact private values from Sentinel-CPS evidence files.")
    parser.add_argument("target", help="File or directory to redact")
    parser.add_argument("--recursive", action="store_true", help="Recursively redact supported text files in a directory")
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"[!] Target not found: {target}")

    base_root = target if target.is_dir() else target.parent
    output_root = (base_root / "redacted").resolve()
    files = gather_files(target, args.recursive)

    if not files:
        print("[!] No supported text files found to redact.")
        return

    print(f"[*] Redacting {len(files)} file(s). Originals will not be modified.")
    for file_path in files:
        out_path = redact_file(file_path, output_root, base_root)
        print(f"[+] {file_path} -> {out_path}")

    print("[*] Redaction complete. Manually review redacted files before publishing.")


if __name__ == "__main__":
    main()

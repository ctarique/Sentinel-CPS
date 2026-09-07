#!/usr/bin/env python3
"""Run the offline-only Sentinel-CPS Isolation Forest analyst-review study."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from isolation_forest_component import StudyError, run_study  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline-only Isolation Forest evidence-window ranking study.")
    parser.add_argument("--manifest", required=True, help="Explicit operator-supplied dataset manifest CSV")
    parser.add_argument("--config", required=True, help="Isolation Forest study JSON config")
    parser.add_argument("--output-dir", required=True, help="New or empty operator-controlled output directory")
    parser.add_argument("--safe-overwrite", action="store_true", help="Replace only the four known study artifacts in an existing output directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = run_study(args.manifest, args.config, args.output_dir, args.safe_overwrite)
    except StudyError as exc:
        print(f"Isolation Forest study validation failed: {exc}", file=sys.stderr)
        return 2
    print("Offline Isolation Forest study complete: ranked evidence windows for analyst review.")
    print(f"eligible={result['eligible_windows']} excluded={result['excluded_windows']} train={result['training_windows']} validation={result['validation_windows']} status={'RANKING_ONLY' if result['ranking_only'] else 'THRESHOLD_AVAILABLE'}")
    print(f"output={result['output_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

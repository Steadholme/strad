#!/usr/bin/env python3
"""Write an env-key-only diff; values are never emitted."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def keys(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        if key in result:
            raise SystemExit(f"duplicate env key: {key}")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    old = keys(args.old)
    new = keys(args.new)
    result = {
        "schema_version": 1,
        "added_keys": sorted(new.keys() - old.keys()),
        "removed_keys": sorted(old.keys() - new.keys()),
        "changed_keys": sorted(key for key in old.keys() & new.keys() if old[key] != new[key]),
        "values_redacted": True,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

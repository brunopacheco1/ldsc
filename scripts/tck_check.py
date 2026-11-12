#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Fail unless the DSP TCK log shows the implemented test groups passing.

Implemented: metadata (MET), catalog (CAT) and contract negotiation as
provider (CN) and as consumer (CN_C).

The TCK prints one line per test with its display name, for example
"CAT:01-01: Verify catalog request". A line that names a required test and
also reports a failure fails this check, and every required test must
appear in the log.
"""
import re
import sys
from pathlib import Path

REQUIRED = (
    ["MET:01-01", "CAT:01-01", "CAT:01-02", "CAT:01-03"]
    + [f"CN:0{group}-0{test}" for group, count in ((1, 4), (2, 7), (3, 4)) for test in range(1, count + 1)]
    + [f"CN_C:0{group}-0{test}" for group, count in ((1, 4), (2, 6), (3, 6)) for test in range(1, count + 1)]
)
FAILURE = re.compile(r"fail|error|exception", re.IGNORECASE)


def read_log(path: str) -> list[str] | None:
    """The log's lines, or None unless path is a .log file inside the working directory."""
    root = Path.cwd().resolve()
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root) or resolved.suffix != ".log":
        return None
    with resolved.open(encoding="utf-8", errors="replace") as file:
        return file.read().splitlines()


def main(path: str) -> int:
    lines = read_log(path)
    if lines is None:
        print(f"::error::refusing {path}: expected a .log file inside the working directory")
        return 2
    status = 0
    for test in REQUIRED:
        hits = [line for line in lines if test in line]
        if not hits:
            print(f"::error::{test} not found in TCK output")
            status = 1
        elif any(FAILURE.search(line) for line in hits):
            print(f"::error::{test} failed: {hits}")
            status = 1
        else:
            print(f"{test}: ok")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

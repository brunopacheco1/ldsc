#!/usr/bin/env python3
# SPDX-FileCopyrightText: LDSC contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Fail unless the DSP TCK log shows the bake-off tests (MET, CAT) passing.

The TCK prints one line per test with its display name, for example
"CAT:01-01: Verify catalog request". A line that names a required test and
also reports a failure fails this check, and every required test must
appear in the log.
"""
import re
import sys

REQUIRED = ["MET:01-01", "CAT:01-01", "CAT:01-02", "CAT:01-03"]
FAILURE = re.compile(r"fail|error|exception", re.IGNORECASE)


def main(path: str) -> int:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
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

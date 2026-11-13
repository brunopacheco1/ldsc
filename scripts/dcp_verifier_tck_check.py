#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Fail unless the DCP TCK log shows every verifier test passing.

The DCP TCK v1.2.1 prints one line per finished test, "<STATUS>: <display
name>", where STATUS is SUCCESSFUL, FAILED or ABORTED. Its verifier package
(presentation.verifier) holds 22 tests, run against the connector. Every one
must pass, and the run must have finished.
"""
import re
import sys

from tck_check import read_log

EXPECTED = 22
RESULT = re.compile(r"\b(SUCCESSFUL|FAILED|ABORTED): (.+)$")


def main(path: str) -> int:
    lines = read_log(path)
    if lines is None:
        print(f"::error::refusing {path}: expected a .log file inside the working directory")
        return 2
    results = [found.groups() for found in map(RESULT.search, lines) if found]
    failed = [name for status, name in results if status != "SUCCESSFUL"]
    for name in failed:
        print(f"::error::not passed: {name}")
    passed = len(results) - len(failed)
    status = 1 if failed else 0
    if passed != EXPECTED:
        print(f"::error::{passed} tests passed, expected {EXPECTED}")
        status = 1
    if not any("Test run complete" in line for line in lines):
        print("::error::the TCK run did not complete")
        status = 1
    if status == 0:
        print(f"DCP TCK: all {passed} verifier tests passed")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

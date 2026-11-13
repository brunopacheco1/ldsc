#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Fail unless the DCP TCK log shows every credential service test passing.

The DCP TCK v1.2.1 prints one line per finished test, "<STATUS>: <display
name>", where STATUS is SUCCESSFUL, FAILED or ABORTED. Its credential
service packages (presentation.cs and issuance.cs) hold 54 tests that run
(the three presentation definition tests are @Disabled in the TCK itself
and print nothing). Every one must pass, and the run must have finished.
"""
import re
import sys

from tck_check import read_log

EXPECTED = 54
RESULT = re.compile(r"\b(SUCCESSFUL|FAILED|ABORTED): (.+)$")


def main(path: str) -> int:
    lines = read_log(path)
    if lines is None:
        print(f"::error::refusing {path}: expected a .log file inside the working directory")
        return 2
    passed, status = 0, 0
    for line in lines:
        found = RESULT.search(line)
        if not found:
            continue
        if found.group(1) == "SUCCESSFUL":
            passed += 1
        else:
            print(f"::error::{found.group(1)}: {found.group(2)}")
            status = 1
    if passed != EXPECTED:
        print(f"::error::{passed} tests passed, expected {EXPECTED}")
        status = 1
    if not any("Test run complete" in line for line in lines):
        print("::error::the TCK run did not complete")
        status = 1
    if status == 0:
        print(f"DCP TCK: all {passed} credential service tests passed")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

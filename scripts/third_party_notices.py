#!/usr/bin/env python3
# SPDX-FileCopyrightText: LDSC contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Writes a third-party notices file from CycloneDX SBOMs (written by cargo-cyclonedx):
every external crate compiled into the LDSC binaries, with its licence and project page.
Attached to each GitHub release.

Usage: third_party_notices.py VERSION crates/ldsc-connector/ldsc-connector_bin.cdx.json ... > THIRD-PARTY-NOTICES.txt
"""
import json
import sys
from pathlib import Path

# Our own crates: covered by this repository's REUSE check.
OWN_PREFIX = "ldsc-"


def load_bom(path, root):
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root) or not resolved.name.endswith(".cdx.json"):
        raise SystemExit(f"Refusing {path}: expected a .cdx.json file inside {root}")
    with resolved.open(encoding="utf-8") as file:
        return json.load(file)


def describe(component):
    licences = []
    for entry in component.get("licenses", []):
        licence = entry.get("license", {})
        licences.append(entry.get("expression") or licence.get("id") or licence.get("name") or "unknown")
    pages = [ref["url"] for ref in component.get("externalReferences", []) if ref.get("type") in ("website", "vcs")]
    return " OR ".join(licences) or "unknown", pages[0] if pages else ""


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    version, paths = argv[0], argv[1:]
    root = Path.cwd().resolve()
    components = {}
    for path in paths:
        bom = load_bom(path, root)
        binary = bom.get("metadata", {}).get("component", {}).get("name", path)
        for component in bom.get("components", []):
            if component["name"].startswith(OWN_PREFIX):
                continue
            key = f"{component['name']} {component.get('version', '')}"
            entry = components.setdefault(key, {"component": component, "binaries": set()})
            entry["binaries"].add(binary)
    print(f"LDSC {version} - third-party components")
    print()
    print("The LDSC binaries are statically linked and include the following crates.")
    print()
    for key in sorted(components):
        licence, page = describe(components[key]["component"])
        print(key)
        print(f"    Licence: {licence}")
        if page:
            print(f"    Project: {page}")
        print(f"    Used by: {', '.join(sorted(components[key]['binaries']))}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

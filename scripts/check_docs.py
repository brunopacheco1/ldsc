#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Check that the documentation still matches the code.

What a machine can check; the release's documentation review covers the
rest (docs/RELEASING.md):

- every C4 diagram in docs/diagrams/ is a draw.io file (.drawio.svg) and
  is shown in docs/ARCHITECTURE.md, and every diagram ARCHITECTURE.md
  shows exists;
- every crate of the workspace appears in at least one diagram;
- every image the Dockerfile builds (portitor-*) appears in the C2
  (containers) diagram;
- every Rust file a diagram names (for example `store.rs`) exists;
- every type or trait the C4 (code) diagrams name exists in the code;
- every OpenAPI file in docs/api/ has the workspace version.

Run from the repository root: python3 scripts/check_docs.py
"""
import base64
import html
import json
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path

ROOT = Path.cwd()
DIAGRAMS = ROOT / "docs" / "diagrams"
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"


def drawio_model(svg_path):
    """The draw.io model (mxGraphModel) kept in a .drawio.svg file."""
    content = ET.parse(svg_path).getroot().get("content")
    if not content:
        raise ValueError("no draw.io model (content attribute); save it from draw.io as .drawio.svg")
    diagram = ET.fromstring(content).find("diagram")
    if diagram is None:
        raise ValueError("no <diagram> in the draw.io model")
    model = diagram.find("mxGraphModel")
    if model is not None:
        return model
    # draw.io's compressed form: base64, raw deflate, then URL encoding
    packed = base64.b64decode(diagram.text or "")
    text = urllib.parse.unquote(zlib.decompress(packed, -15).decode("utf-8"))
    return ET.fromstring(text)


def labels(model):
    """The plain text of every label, with whether it is a shape's."""
    out = []
    for cell in model.iter("mxCell"):
        value = cell.get("value") or ""
        text = re.sub(r"<br\s*/?>", "\n", value)
        text = re.sub(r"<[^>]+>", "", text)
        # free text (a legend, a note) is not a shape
        shape = cell.get("vertex") == "1" and not (cell.get("style") or "").startswith("text;")
        out.append((shape, html.unescape(text).strip()))
    return out


def workspace():
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    members = re.search(r"members\s*=\s*\[([^\]]*)\]", text).group(1)
    crates = [m.split("/")[-1] for m in re.findall(r'"([^"]+)"', members)]
    version = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE).group(1)
    return crates, version


def main():
    errors = []
    crates, version = workspace()
    files = sorted(DIAGRAMS.glob("*.drawio.svg"))
    others = sorted(p.name for p in DIAGRAMS.iterdir() if not p.name.endswith(".drawio.svg"))
    if others:
        errors.append(f"docs/diagrams holds files that are not .drawio.svg: {others}")
    if not files:
        errors.append("docs/diagrams has no .drawio.svg diagram")

    architecture = ARCHITECTURE.read_text(encoding="utf-8")
    shown = set(re.findall(r"diagrams/([\w.-]+\.drawio\.svg)", architecture))
    for name in sorted(shown - {p.name for p in files}):
        errors.append(f"ARCHITECTURE.md shows diagrams/{name}, which does not exist")
    for path in files:
        if path.name not in shown:
            errors.append(f"docs/diagrams/{path.name} is not shown in ARCHITECTURE.md")

    rust_files = {p.name for p in (ROOT / "crates").rglob("*.rs")}
    sources = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "crates").rglob("*.rs"))
    text_of, shapes_of = {}, {}
    for path in files:
        try:
            found = labels(drawio_model(path))
            text_of[path.name] = "\n".join(t for _, t in found)
            shapes_of[path.name] = [t for shape, t in found if shape and t]
        except (ET.ParseError, ValueError, zlib.error) as e:
            errors.append(f"docs/diagrams/{path.name}: {e}")
    everything = "\n".join(text_of.values())

    for crate in crates:
        if crate not in everything:
            errors.append(f"crate {crate} appears in no diagram")

    images = re.findall(r"^FROM\s+\S+\s+AS\s+(portitor-[\w-]+)", (ROOT / "Dockerfile").read_text(encoding="utf-8"),
                        re.MULTILINE | re.IGNORECASE)
    c2 = "\n".join(t for name, t in text_of.items() if name.startswith("c2-"))
    for image in images:
        if image not in c2:
            errors.append(f"image {image} (Dockerfile) is not in the C2 diagram")

    for name, text in text_of.items():
        for file in sorted(set(re.findall(r"\b([a-z_]+\.rs)\b", text))):
            if file not in rust_files:
                errors.append(f"docs/diagrams/{name} names {file}, which no crate has")
        if name.startswith("c4-"):
            names = set()
            for shape in shapes_of[name]:
                title = re.match(r"(?:trait\s+)?([A-Z]\w*)", shape)
                if title:
                    names.add(title.group(1))
                names.update(re.findall(r"\b[A-Z][a-z0-9]+[A-Z]\w*\b", shape))
            for ident in sorted(names):
                if not re.search(rf"\b(struct|trait|enum|type)\s+{ident}\b", sources):
                    errors.append(f"docs/diagrams/{name} names {ident}, which the code does not define")

    for spec in sorted((ROOT / "docs" / "api").glob("*.json")):
        found = json.loads(spec.read_text(encoding="utf-8")).get("info", {}).get("version")
        if found != version:
            errors.append(f"docs/api/{spec.name} has version {found}, the workspace {version}")

    for error in errors:
        print(f"::error::{error}")
    if not errors:
        print(f"documentation checks passed: {len(files)} diagrams, {len(crates)} crates, {len(images)} images")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

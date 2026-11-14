#!/usr/bin/env python3
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Make the reduced code lists of the demo bundle (ADR 0005, "Bundle format").

A bundle carries code lists and ontologies only as the data that SHACL
`sh:class` and the vocabulary shapes read. This script keeps, from
N-Triples input:

- code lists: every `rdf:type` and `skos:inScheme` triple;
- ontologies: the `rdfs:subClassOf` triples and the `rdf:type` triples of
  named individuals, but only where the class leads (through
  `rdfs:subClassOf`) to a class that the shapes name with `sh:class`.

Triples with a blank node are dropped. The output is sorted and has no
duplicates, so the same input always gives the same bytes.

Input: one N-Triples file per source, named `<name>.nt` as in SOURCES,
in the folder given with --in. The sources are published as RDF/XML or
Turtle. Convert them to N-Triples with any RDF tool first, for example
`riot --output=ntriples file.rdf > name.nt` (Apache Jena). Portitor's own
binaries never parse RDF/XML. The shapes (--shapes) are read only for
their `sh:class` values. Every path must be inside the current folder:
run it from the repository root, with the inputs in a folder under it.

  python3 scripts/reduce_code_lists.py --in <folder> \\
    --shapes examples/bundle/healthdcat-ap-r8/shapes/*/*.ttl \\
    --out examples/bundle/healthdcat-ap-r8/vocabulary/code-lists.nt

The sources are the files that the HealthDCAT-AP release 8 validator
loads (`config.properties` of
https://data.health.europa.eu/healthdcat-ap/releases/release-8/html/shacl/HealthDCAT-AP_validator/config/rdf-validator/ehds/,
`owlImportMapping`, folder `catalogue/`), as copied in
https://github.com/msicilia/redcap2hdcat/tree/e81888347bd194cf14838b9f09f006616052355a/paper/eval/shapes/release-8/ehds/catalogue
(the official host could not be reached when the demo bundle was made,
2026-11-14). Left out: schema.org (no shape names one of its classes);
the ADMS code lists (`ADMS_SKOS_v1.00.rdf`: licence type, publisher type,
status) and the Core Location vocabulary (`locn.ttl`), both under the ISA
Open Metadata Licence v1.1, whose text we could not record in LICENSES/.
A dataset that uses an ADMS licence type or publisher type then fails the
vocabulary shapes.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
SUBCLASS = "http://www.w3.org/2000/01/rdf-schema#subClassOf"
IN_SCHEME = "http://www.w3.org/2004/02/skos/core#inScheme"
# rdf:type objects that only declare schema terms, not individuals
SCHEMA_NAMESPACES = (
    "http://www.w3.org/2002/07/owl#",
    "http://www.w3.org/2000/01/rdf-schema#",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
)

CODE_LIST = "code list"
ONTOLOGY = "ontology"
# The IRIs below name the sources; this script never fetches them. An
# IRI is an identifier, so its http scheme cannot change to https.
OP = "http://publications.europa.eu/resource/authority/"  # NOSONAR identifier, never fetched
HDEU_AUTHORITY = "https://hdeu-dcat.data.health.europa.eu/resource/authority/"

# name (input file <name>.nt), kind, the IRI it stands for, licence as the
# publisher states it ("not stated" when we found no statement)
EU = "CC-BY-4.0 (EU reuse policy, Commission Decision 2011/833/EU and C(2019) 1655)"
HDEU = "not stated in the file; published with HealthDCAT-AP release 8 (CC-BY-4.0)"
W3C = "W3C Software and Document Notice and License (W3C-20150513)"
SOURCES = [
    # EU Publications Office authority tables (https://op.europa.eu/en/web/eu-vocabularies)
    ("access-right", CODE_LIST, OP + "access-right", EU),
    ("continents", CODE_LIST, OP + "continent", EU),
    ("corporatebodies", CODE_LIST, OP + "corporate-body", EU),
    ("countries", CODE_LIST, OP + "country", EU),
    ("data-theme", CODE_LIST, OP + "data-theme", EU),
    ("dataset-types", CODE_LIST, OP + "dataset-type", EU),
    ("distribution-status", CODE_LIST, OP + "distribution-status", EU),
    ("filetypes", CODE_LIST, OP + "file-type", EU),
    ("frequencies", CODE_LIST, OP + "frequency", EU),
    ("languages", CODE_LIST, OP + "language", EU),
    ("places", CODE_LIST, OP + "place", EU),
    ("planned-availability", CODE_LIST, OP + "planned-availability", EU),
    # HealthData@EU code lists
    ("coding-system", CODE_LIST, HDEU_AUTHORITY + "coding-system", HDEU),
    ("health-activity", CODE_LIST, HDEU_AUTHORITY + "health-activity", HDEU),
    ("health-theme", CODE_LIST, HDEU_AUTHORITY + "health-theme", HDEU),
    ("healthcategories", CODE_LIST, HDEU_AUTHORITY + "healthcategories", HDEU),
    ("publisher-type", CODE_LIST, HDEU_AUTHORITY + "publisher-type", HDEU),
    ("standard", CODE_LIST, HDEU_AUTHORITY + "standard", HDEU),
    # ontologies (class hierarchy only)
    ("adms", ONTOLOGY, "http://www.w3.org/ns/adms.ttl", W3C),
    ("csvw", ONTOLOGY, "http://www.w3.org/ns/csvw.ttl", W3C),
    ("dcat2", ONTOLOGY, "https://www.w3.org/ns/dcat2.ttl", "CC-BY-4.0 (stated in the file)"),
    ("dqv", ONTOLOGY, "http://www.w3.org/ns/dqv.ttl", W3C),
    ("dublin_core_terms", ONTOLOGY, "http://dublincore.org/2020/01/20/dublin_core_terms.ttl", "CC-BY-4.0 (DCMI)"),
    ("eli", ONTOLOGY, "http://data.europa.eu/eli/ontology", EU),  # NOSONAR identifier, never fetched
    ("index", ONTOLOGY, "http://xmlns.com/foaf/spec/index.rdf", "CC-BY-1.0 (FOAF specification; not stated in the file)"),
    ("m8g", ONTOLOGY, "https://raw.githubusercontent.com/SEMICeu/uri.semic.eu-puris/main/releases/m8g/m8g.ttl",
     "CC-BY-4.0 (SEMIC)"),
    ("ns", ONTOLOGY, "http://www.w3.org/2006/vcard/ns.ttl", W3C),
    ("prov-o", ONTOLOGY, "http://www.w3.org/ns/prov-o.ttl", W3C),
    ("spdx-ontology.owl", ONTOLOGY, "https://spdx.org/rdf/terms/spdx-ontology.owl.xml",
     "not stated in the file (SPDX specification: CC-BY-3.0)"),
    ("time", ONTOLOGY, "http://www.w3.org/2006/time.ttl", "CC-BY-4.0 (stated in the file)"),
]


def inside_here(argument):
    """The path, resolved; it must be inside the current folder."""
    here = Path.cwd().resolve()
    path = (here / argument).resolve()
    if not path.is_relative_to(here):
        sys.exit(f"{argument}: not inside the current folder {here}")
    return path


def is_iri(term):
    return term.startswith("<") and term.endswith(">")


def is_node(term):
    """An IRI or a blank node: what a subject can be."""
    return is_iri(term) or term.startswith("_:")


def parse_triple(line):
    """(subject, predicate, object) of one N-Triples line, or None.

    Subjects and predicates hold no spaces, so two splits find them; the
    object is the rest, before the final ".".
    """
    if not line.endswith("."):
        return None
    parts = line[:-1].rstrip().split(None, 2)
    if len(parts) != 3 or not is_node(parts[0]) or not is_iri(parts[1]):
        return None
    return parts[0], parts[1][1:-1], parts[2]


def triples(path):
    """(subject, predicate, object) of each N-Triples line, as written."""
    with path.open(encoding="utf-8") as lines:
        for number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            triple = parse_triple(line)
            if triple is None:
                sys.exit(f"{path}:{number}: not an N-Triples line")
            yield triple


def shape_classes(paths):
    """The class IRIs that the shapes name with sh:class (prefixed or full)."""
    classes = set()
    for path in paths:
        text = path.read_text(encoding="utf-8")
        prefixes = dict(re.findall(r"@prefix\s+([\w-]*):\s*<([^>]*)>", text))
        for value in re.findall(r"sh:class\s+(<[^>]*>|[\w-]*:[\w-]+)", text):
            if value.startswith("<"):
                classes.add(value[1:-1])
                continue
            prefix, local = value.split(":", 1)
            if prefix not in prefixes:
                sys.exit(f"{path}: unknown prefix {prefix}:")
            classes.add(prefixes[prefix] + local)
    return classes


def read_sources(folder):
    """Code list triples to keep, ontology subclass edges, ontology individuals."""
    kept = set()
    subclass = []  # (sub, super) edges of the ontologies
    individuals = []  # (subject, class) rdf:type triples of the ontologies
    for name, kind, _, _ in SOURCES:
        for s, p, o in triples(folder / f"{name}.nt"):
            if not (is_iri(s) and is_iri(o)):
                continue
            if kind == CODE_LIST:
                if p in (RDF_TYPE, IN_SCHEME):
                    kept.add(f"{s} <{p}> {o} .")
            elif p == SUBCLASS:
                subclass.append((s[1:-1], o[1:-1]))
            elif p == RDF_TYPE and not o[1:-1].startswith(SCHEMA_NAMESPACES):
                individuals.append((s, o[1:-1]))
    return kept, subclass, individuals


def leading_classes(classes, subclass):
    """The classes, and every class that leads to one through rdfs:subClassOf."""
    leads = set(classes)
    changed = True
    while changed:
        before = len(leads)
        leads.update(sub for sub, sup in subclass if sup in leads)
        changed = len(leads) != before
    return leads


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--in", dest="folder", required=True, help="folder with one <name>.nt per source")
    parser.add_argument("--shapes", nargs="+", required=True, help="the bundle's SHACL shapes (Turtle)")
    parser.add_argument("--out", required=True, help="the reduced N-Triples file to write")
    args = parser.parse_args()
    folder = inside_here(args.folder)
    shapes = [inside_here(path) for path in args.shapes]
    out = inside_here(args.out)

    missing = [name for name, *_ in SOURCES if not (folder / f"{name}.nt").is_file()]
    if missing:
        sys.exit(f"missing input files in {folder}: {', '.join(n + '.nt' for n in missing)}")

    kept, subclass, individuals = read_sources(folder)
    leads = leading_classes(shape_classes(shapes), subclass)
    kept.update(f"<{sub}> <{SUBCLASS}> <{sup}> ." for sub, sup in subclass if sup in leads)
    kept.update(f"{s} <{RDF_TYPE}> <{cls}> ." for s, cls in individuals if cls in leads)

    output = "".join(line + "\n" for line in sorted(kept)).encode("utf-8")
    out.write_bytes(output)
    print(f"{args.out}: {len(kept)} triples, {len(output)} bytes, "
          f"sha256 {hashlib.sha256(output).hexdigest()}", file=sys.stderr)


if __name__ == "__main__":
    main()

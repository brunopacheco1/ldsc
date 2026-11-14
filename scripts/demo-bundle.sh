#!/usr/bin/env bash
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Builds and signs the demo schema and vocabulary bundle (ADR 0005,
# "Bundle format") from examples/bundle/healthdcat-ap-r8/ with
# `portitor-issuer bundle build`: HealthDCAT-AP release 8 and DCAT-AP
# 3.0.0 shapes for the three access levels, and reduced code lists. The
# datasets in examples/healthdcat-datasets.json are written for it, with
# full IRIs for every term outside the DSP 2025-1 context (the catalog
# serves that context only).
#
# Usage: scripts/demo-bundle.sh <work folder> [portitor-issuer]
#   Without a binary it builds the debug one. It writes, in the work folder:
#     bundle-key.pem   the bundle key (made here, as the demos make their
#                      keys, if the file does not exist yet); keep it
#                      offline in a real data space
#     bundle-key.jwk   its public key, for PORTITOR_ISSUER_BUNDLE_KEY_FILE
#     bundles/         for PORTITOR_ISSUER_BUNDLE_DIR: <version>/, the
#                      signed bundle, and latest.json, which names it as
#                      the newest version
#
# Settings (environment), with the defaults of scripts/demo.sh's issuer:
#   AUTHORITY      the authority's DID         did:web:127.0.0.1%3A18060
#   VERSION        the bundle version          r8-demo-1
# A version folder that exists already is never written again.
# Needs openssl.

set -euo pipefail

cd "$(dirname "$0")/.."
WORK=${1:?usage: scripts/demo-bundle.sh <work folder> [portitor-issuer]}
if [[ $# -ge 2 ]]; then
  ISSUER=$2
else
  cargo build --quiet -p portitor-issuer
  ISSUER=${CARGO_TARGET_DIR:-target}/debug/portitor-issuer
fi
AUTHORITY=${AUTHORITY:-did:web:127.0.0.1%3A18060}
VERSION=${VERSION:-r8-demo-1}
SOURCE=examples/bundle/healthdcat-ap-r8
PROFILE=https://data.health.europa.eu/healthdcat-ap/releases/release-8/

mkdir -p "$WORK/bundles"
if [[ ! -f "$WORK/bundle-key.pem" ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/bundle-key.pem" 2>/dev/null
fi

output=$("$ISSUER" bundle build --in "$SOURCE" --out "$WORK/bundles" --version "$VERSION" \
  --profile "$PROFILE" --authority "$AUTHORITY" --kid "$AUTHORITY#bundle-key" \
  --key "$WORK/bundle-key.pem")
echo "$output"
sed -n 's/^public key (for PORTITOR_ISSUER_BUNDLE_KEY_FILE): //p' <<<"$output" >"$WORK/bundle-key.jwk"
echo "public key in $WORK/bundle-key.jwk"

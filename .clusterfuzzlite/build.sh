#!/bin/bash -eu
# SPDX-FileCopyrightText: Portitor contributors
#
# SPDX-License-Identifier: Apache-2.0

# Builds every fuzz target in fuzz/ and copies it to $OUT.
cd "$SRC/portitor"
cargo fuzz build -O --debug-assertions
for f in fuzz/fuzz_targets/*.rs; do
  name=$(basename "${f%.*}")
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$name" "$OUT/"
done

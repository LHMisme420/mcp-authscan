#!/bin/sh
# Build the scoped Zenodo upload zip from the committed dataset tree.
# Run from the repository root:  sh bench/dataset/zenodo/make_bundle.sh
# Produces mcp-authscan-dataset-v1.zip containing only bench/dataset (no
# scanner source, no unrelated findings), with hashes intact.
set -eu
out="mcp-authscan-dataset-v1.zip"
rm -f "$out"
( cd bench && zip -r -X "../$out" dataset \
    -x 'dataset/zenodo/make_bundle.sh' ) >/dev/null
echo "wrote $out"
unzip -l "$out" | tail -n +2 | head -n 40

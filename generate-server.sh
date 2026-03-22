#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SPEC="$ROOT_DIR/Basalt-Main/openapispec.yaml"
OUT_DIR="$SCRIPT_DIR/generated/api-server"

if [[ ! -f "$SPEC" ]]; then
  echo "ERROR: $SPEC not found."
  exit 1
fi

echo "Generating Axum server from $SPEC ..."

npx @openapitools/openapi-generator-cli generate \
  -i "$SPEC" \
  -g rust-axum \
  -o "$OUT_DIR" \
  --package-name basalt-networking-api-server \

# Remove boilerplate files the generator creates
rm -f "$OUT_DIR/git_push.sh" "$OUT_DIR/.travis.yml"

echo "Done. Server scaffold generated at $OUT_DIR/"

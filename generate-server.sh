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

# --- Post-generation patches ---
# The rust-axum generator incorrectly renders integer enums (e.g. LibType,
# ReshareType) with string-based serde renames (#[serde(rename = "0")]) instead
# of integer representations.  This causes deserialization to fail when clients
# send the spec-correct integer values (e.g. lib_type: 1 instead of "1").
#
# Fix: replace the generated enum blocks with serde_repr-based versions that
# serialize/deserialize as integers, matching the OpenAPI spec and the Go
# server's expectations.

MODELS="$OUT_DIR/src/models.rs"
CARGO="$OUT_DIR/Cargo.toml"

# 1. Add serde_repr dependency if not already present
if ! grep -q 'serde_repr' "$CARGO"; then
  sed -i '/^serde_json/a serde_repr = "0.1"' "$CARGO"
  echo "  Patched Cargo.toml: added serde_repr dependency"
fi

# 2. Patch integer enums in models.rs using Python for reliable multi-line replacement
python3 - "$MODELS" <<'PYEOF'
import sys, re

with open(sys.argv[1], "r") as f:
    src = f.read()

# --- LibType ---
lib_type_old = re.compile(
    r'/// TSS library/protocol type\n'
    r'/// Enumeration of values\.\n'
    r'/// Since this enum\'s variants do not hold data, we can easily define them as `#\[repr\(C\)\]`\n'
    r'/// which helps with FFI\.\n'
    r'#\[allow\(non_camel_case_types, clippy::large_enum_variant\)\]\n'
    r'#\[repr\(C\)\]\n'
    r'#\[derive\(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize\)\]\n'
    r'#\[cfg_attr\(feature = "conversion", derive\(frunk_enum_derive::LabelledGenericEnum\)\)\]\n'
    r'pub enum LibType \{\n'
    r'    #\[serde\(rename = "0"\)\]\n'
    r'    GG20,\n'
    r'    #\[serde\(rename = "1"\)\]\n'
    r'    DKLS,\n'
    r'    #\[serde\(rename = "2"\)\]\n'
    r'    KeyImport,\n'
    r'\}',
    re.MULTILINE
)

lib_type_new = """/// TSS library/protocol type
/// Enumeration of values.
/// Patched by generate-server.sh: uses serde_repr for integer serialization.
#[allow(non_camel_case_types, clippy::large_enum_variant)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum LibType {
    GG20 = 0,
    DKLS = 1,
    KeyImport = 2,
}"""

src, n = lib_type_old.subn(lib_type_new, src)
if n: print("  Patched LibType enum to use serde_repr")

# --- ReshareType ---
reshare_type_old = re.compile(
    r'/// Reshare operation type\n'
    r'/// Enumeration of values\.\n'
    r'/// Since this enum\'s variants do not hold data, we can easily define them as `#\[repr\(C\)\]`\n'
    r'/// which helps with FFI\.\n'
    r'#\[allow\(non_camel_case_types, clippy::large_enum_variant\)\]\n'
    r'#\[repr\(C\)\]\n'
    r'#\[derive\(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize\)\]\n'
    r'#\[cfg_attr\(feature = "conversion", derive\(frunk_enum_derive::LabelledGenericEnum\)\)\]\n'
    r'pub enum ReshareType \{\n'
    r'    #\[serde\(rename = "0"\)\]\n'
    r'    Normal,\n'
    r'    #\[serde\(rename = "1"\)\]\n'
    r'    Plugin,\n'
    r'\}',
    re.MULTILINE
)

reshare_type_new = """/// Reshare operation type
/// Enumeration of values.
/// Patched by generate-server.sh: uses serde_repr for integer serialization.
#[allow(non_camel_case_types, clippy::large_enum_variant)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum ReshareType {
    Normal = 0,
    Plugin = 1,
}"""

src, n = reshare_type_old.subn(reshare_type_new, src)
if n: print("  Patched ReshareType enum to use serde_repr")

with open(sys.argv[1], "w") as f:
    f.write(src)
PYEOF

echo "Done. Server scaffold generated at $OUT_DIR/"

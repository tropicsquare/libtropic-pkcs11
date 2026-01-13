#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

OUT="${OUT:-/tmp/rnd.bin}"

pkcs11-tool --module "$MODULE" "${PIN_ARGS[@]}" --generate-random 32 -o "$OUT"
xxd "$OUT"

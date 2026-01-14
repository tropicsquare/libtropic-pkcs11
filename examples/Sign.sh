#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-2}"          # P-256 slot by default
MECH="${MECH:-ECDSA}"      # Use EDDSA for Ed25519 keys
IN="${IN:-/tmp/hash.bin}"
OUT="${OUT:-/tmp/sig_${SLOT}.bin}"
SLOT_HEX=$(printf "%02x" "$SLOT")

if [ ! -f "$IN" ]; then
    echo "0123456789ABCDEF0123456789ABCDEF" > "$IN"
fi

echo "Signing with slot $SLOT (id $SLOT_HEX), mech=$MECH"
pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism "$MECH" \
    --id "$SLOT_HEX" --input-file "$IN" --output-file "$OUT"

echo "Signature (first 2 lines):"
xxd "$OUT" | head -2

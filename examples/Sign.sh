#!/bin/bash
# Sign data using an ECC key stored in TROPIC01
# Usage: [SLOT=<slot_number>] [MECH=<mechanism>] [IN=<input_file>] [OUT=<output_file>] ./Sign.sh
#
# Example: SLOT=24 MECH=ECDSA ./Sign.sh
# Example: SLOT=5 MECH=EDDSA IN=/tmp/message.bin ./Sign.sh
#
# Mechanism:
#   1. Calls C_SignInit + C_Sign via pkcs11-tool --sign
#   2. Input data is sent to TROPIC01 (hash for ECDSA, message for EDDSA)
#   3. Signing is performed inside the chip using the private key
#   4. Private key never leaves TROPIC01; only signature is returned
#   5. Use ECDSA for P-256 keys, EDDSA for Ed25519 keys

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-24}"         # P-256 slot by default (same as GenerateKey.sh)
MECH="${MECH:-ECDSA}"      # Use EDDSA for Ed25519 keys
IN="${IN:-/tmp/hash.bin}"
OUT="${OUT:-/tmp/sig_${SLOT}.bin}"

if [ ! -f "$IN" ]; then
    echo "0123456789ABCDEF0123456789ABCDEF" > "$IN"
fi

# Note: pkcs11-tool --sign doesn't pass CKA_LABEL to C_FindObjectsInit (bug/limitation),
# so we must use --id instead. CKA_ID is slot number as a single byte.
SLOT_HEX=$(printf '%02x' "$SLOT")

echo "Signing with slot $SLOT (id=0x$SLOT_HEX), mech=$MECH"
pkcs11-tool --module "$MODULE" --sign --pin 1234 --mechanism "$MECH" \
    --id "$SLOT_HEX" --input-file "$IN" --output-file "$OUT"

echo "Signature (first 2 lines):"
xxd "$OUT" | head -2

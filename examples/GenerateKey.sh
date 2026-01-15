#!/bin/bash
# Generate an ECC P-256 key pair in a specific slot
# Usage: [SLOT=<slot_number>] ./GenerateKey.sh
#
# Example: SLOT=24 ./GenerateKey.sh
#
# Mechanism:
#   1. Calls C_GenerateKeyPair via pkcs11-tool --keypairgen
#   2. TROPIC01 generates a P-256 (secp256r1) key pair internally
#   3. Private key never leaves the chip; only public key is readable
#   4. Key is stored in ECC slot specified by --id (0-31 available)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-24}"
SLOT_HEX=$(printf "%02x" "$SLOT")

echo "Generating P-256 key in slot $SLOT (id $SLOT_HEX)"
pkcs11-tool --module "$MODULE" --keypairgen --key-type EC:secp256r1 --id "$SLOT_HEX"

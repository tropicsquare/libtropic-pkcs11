#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-24}"
SLOT_HEX=$(printf "%02x" "$SLOT")

echo "Generating P-256 key in slot $SLOT (id $SLOT_HEX)"
pkcs11-tool --module "$MODULE" --keypairgen --key-type EC:secp256r1 --id "$SLOT_HEX"

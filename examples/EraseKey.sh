#!/bin/bash
# Erase an ECC key from a specific slot
# Usage: [SLOT=<slot_number>] ./EraseKey.sh
#
# Example: SLOT=24 ./EraseKey.sh
#
# Mechanism:
#   1. Calls C_DestroyObject via pkcs11-tool --delete-object
#   2. Finds the private key by CKA_LABEL (slot number)
#   3. TROPIC01 securely erases the key pair from the ECC slot
#   4. Both private and public keys are removed (same slot)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-24}"
SLOT_HEX=$(printf "%02x" "$SLOT")

echo "Erasing ECC key in ECC slot $SLOT ($SLOT_HEX)"
pkcs11-tool --module "$MODULE" --delete-object --type privkey --id "$SLOT_HEX"

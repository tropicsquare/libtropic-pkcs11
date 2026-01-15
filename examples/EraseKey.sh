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

echo "Erasing ECC key in slot $SLOT"
pkcs11-tool --module "$MODULE" --delete-object --type privkey --label "$SLOT" 2>/dev/null || echo "(slot $SLOT was empty)"

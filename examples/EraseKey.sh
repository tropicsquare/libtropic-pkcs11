#!/bin/bash
# Erase an ECC key from a specific slot
# Usage: SLOT=<slot_number> ./EraseKey.sh
#
# Example: SLOT=24 ./EraseKey.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

require_module

SLOT="${SLOT:-24}"
SLOT_HEX=$(printf "%02x" "$SLOT")

echo "Erasing ECC key in slot $SLOT (id $SLOT_HEX)"
pkcs11-tool --module "$MODULE" --delete-object --type privkey --id "$SLOT_HEX"

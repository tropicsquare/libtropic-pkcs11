#!/bin/bash
# Erase user data in TROPIC01 R-MEM slots
# Usage: [SLOT=<slot_number>] ./EraseUserData.sh
#
# Example: SLOT=60 ./EraseUserData.sh
# Example: SLOT=100 DATA_FILE=/tmp/mydata.bin ./EraseUserData.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-60}"

echo "Erasing slot $SLOT"
pkcs11-tool --module "$MODULE" --delete-object --type data --label "$SLOT"
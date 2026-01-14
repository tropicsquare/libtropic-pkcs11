#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

SLOT="${SLOT:-60}"
LABEL="r-mem-slot:${SLOT}"
DATA_FILE="${DATA_FILE:-/tmp/rmem_data.bin}"
READ_FILE="${READ_FILE:-/tmp/rmem_read.bin}"

if [ ! -f "$DATA_FILE" ]; then
    echo "Sample data for slot $SLOT @ $(date +%s)" > "$DATA_FILE"
fi

echo "Erasing $LABEL"
pkcs11-tool --module "$MODULE" --delete-object --type data --label "$LABEL" 2>/dev/null || true

echo "Writing $LABEL from $DATA_FILE"
pkcs11-tool --module "$MODULE" --write-object "$DATA_FILE" --type data --label "$LABEL"

echo "Reading back $LABEL to $READ_FILE"
pkcs11-tool --module "$MODULE" --read-object --type data --label "$LABEL" -o "$READ_FILE"

echo "Diff result:"
if diff "$DATA_FILE" "$READ_FILE" > /dev/null; then
    echo "OK: data matches"
else
    echo "Mismatch"
    exit 1
fi

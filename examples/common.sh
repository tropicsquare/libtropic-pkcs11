#!/bin/bash

# Shared settings for example scripts
SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULE="$ROOT_DIR/build/liblibtropic_pkcs11.so"

# PIN handling (default empty)
PIN="${PIN:-""}"
PIN_ARGS=(--pin "$PIN")
LOGIN_ARGS=(--login --pin "$PIN")

require_module() {
    if [ ! -f "$MODULE" ]; then
        echo "Module not found at $MODULE. Run examples/Build.sh first." >&2
        exit 1
    fi
}

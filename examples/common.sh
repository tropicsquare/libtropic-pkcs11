#!/bin/bash
# Common settings and helper functions for example scripts
# Usage: source common.sh
#
# This file is sourced by other scripts, not run directly.
#
# Provides:
#   MODULE      - Path to the compiled PKCS#11 shared library
#   PIN_ARGS    - Array with PIN argument for pkcs11-tool
#   LOGIN_ARGS  - Array with login + PIN arguments for pkcs11-tool
#   require_module() - Function to verify module exists before use

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULE="$ROOT_DIR/build/libtropic_pkcs11.so"

# PIN handling (default empty)
PIN="1234"
PIN_ARGS=(--pin "$PIN")
LOGIN_ARGS=(--login --pin "$PIN")

require_module() {
    if [ ! -f "$MODULE" ]; then
        echo "Module not found at $MODULE. Run examples/Build.sh first." >&2
        exit 1
    fi
}

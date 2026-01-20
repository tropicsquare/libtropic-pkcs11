#!/bin/bash
# Build the PKCS#11 module from source
# Usage: ./Build.sh
#
# Build steps:
#   1. Remove existing build directory for clean build
#   2. Run cmake with USB device path and logging enabled
#   3. Compile with make to produce liblibtropic_pkcs11.so

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR" && pwd)"
cd "$ROOT_DIR"

rm -rf build
mkdir build

cd build
cmake -DTS_USB_DEV="/dev/ttyACM0" ..
make -j`nproc`

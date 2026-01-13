#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"
rm -rf build
mkdir build
cd build
cmake -DTS_USB_DEV="/dev/ttyACM0" -DLT_PKCS11_LOG_EN=OFF ..
make

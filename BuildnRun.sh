#!/bin/bash

set -e

# Clean and build
rm -rf build
mkdir build
cd build
cmake ..
make

# Path to the built PKCS11 module
MODULE_PATH="/home/ales/Documents/PKCS11/libtropic-pkcs11/build/liblibtropic_pkcs11.so"

echo ""
echo "=========================================="
echo "Example 1: Generate 32 random bytes"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" --generate-random 32 --output-file /tmp/random.bin && xxd /tmp/random.bin

echo ""
echo "=========================================="
echo "Example 2: List token slots (-T)"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" -T

echo ""
echo "=========================================="
echo "Example 3: Show module info (-I)"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" -I


#!/bin/bash
# Debug script to check PKCS#11 setup

echo "=== Checking PKCS#11 Library ==="
echo

# Check if library exists
LIB_PATH="/usr/lib/aarch64-linux-gnu/ossl-modules/liblibtropic_pkcs11.so"
if [ -f "$LIB_PATH" ]; then
    echo "✓ Library exists: $LIB_PATH"
    ls -lh "$LIB_PATH"
    echo
else
    echo "✗ Library NOT found: $LIB_PATH"
    exit 1
fi

# Check if C_GetFunctionList symbol exists in the library
echo "Checking for C_GetFunctionList symbol..."
if nm -D "$LIB_PATH" 2>/dev/null | grep -q "C_GetFunctionList"; then
    echo "✓ C_GetFunctionList found in library"
else
    echo "✗ C_GetFunctionList NOT found - library may be broken"
fi
echo

# Try to test the library directly
echo "=== Testing with PKCS11_PROVIDER_DEBUG ==="
export OPENSSL_CONF="$PWD/openss.cnf"
export PKCS11_PROVIDER_DEBUG=1

echo "Running: openssl rand -provider pkcs11prov -hex 8"
openssl rand -provider pkcs11prov -hex 8 2>&1

echo
echo "If you don't see >>> LOG messages above, the library isn't being called."



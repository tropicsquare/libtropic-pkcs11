#!/bin/bash
# Test OpenSSL with PKCS#11 provider

echo "=== OpenSSL PKCS#11 Provider Test ==="
echo

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    PROVIDER_PATH="/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11prov.so"
elif [ "$ARCH" = "x86_64" ]; then
    PROVIDER_PATH="/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11prov.so"
else
    echo "Unknown architecture: $ARCH"
    exit 1
fi

echo "Architecture: $ARCH"
echo "Provider path: $PROVIDER_PATH"
echo

# Check if provider exists
if [ ! -f "$PROVIDER_PATH" ]; then
    echo "ERROR: PKCS#11 provider not found!"
    echo "Install with: sudo apt-get install openssl-pkcs11-provider"
    echo "Or: sudo apt-get install libengine-pkcs11-openssl"
    exit 1
fi

echo "✓ PKCS#11 provider found"
echo

# Check OpenSSL version
echo "OpenSSL version:"
openssl version
echo

# Set config
export OPENSSL_CONF="$PWD/openssl.cnf"
echo "Using config: $OPENSSL_CONF"
echo

# Update config with correct architecture
if [ "$ARCH" = "x86_64" ]; then
    sed -i 's|/usr/lib/aarch64-linux-gnu|/usr/lib/x86_64-linux-gnu|g' "$OPENSSL_CONF"
fi

# List providers
echo "=== Listing OpenSSL Providers ==="
openssl list -providers
echo

# Check if pkcs11 provider is loaded
if openssl list -providers | grep -q "pkcs11"; then
    echo "✓ PKCS#11 provider is loaded!"
    echo
    
    # Test random generation
    echo "=== Testing Random Generation with PKCS#11 ==="
    echo "Generating 16 bytes..."
    openssl rand -provider pkcs11 -hex 16
    echo
    
    echo "Generating 32 bytes..."
    openssl rand -provider pkcs11 -hex 32
    echo
    
    echo "=== SUCCESS! ==="
    echo "Your PKCS#11 library is working with OpenSSL!"
else
    echo "✗ PKCS#11 provider not loaded"
    echo "Check your openssl.cnf configuration"
fi


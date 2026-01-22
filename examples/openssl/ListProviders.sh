#!/bin/bash
#
# List OpenSSL PKCS11 provider was loaded


export PROVIDER_PATH=/usr/lib/x86_64-linux-gnu/engines-3/pkcs11prov.so
export OPENSSL_CONF="`pwd`/openssl_libp11_provider.cnf"

if [ ! -f "$PROVIDER_PATH" ]; then
    echo "ERROR: PKCS#11 provider not found!"
    echo "Build libp11 or other PKCS11 provider"
    exit 1
fi

echo "OpenSSL config:  $OPENSSL_CONF"
echo "PKCS11 provider: $PROVIDER_PATH"
echo

# List providers
echo "=== Listing OpenSSL Providers ==="
openssl list -providers
echo
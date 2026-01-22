#!/bin/bash
#
# List OpenSSL PKCS11 provider was loaded


export PROVIDER_PATH=/usr/lib/x86_64-linux-gnu/engines-3/pkcs11prov.so
export OPENSSL_CONF="`pwd`/openssl_libp11_provider.cnf"

# ECC Key slot
SLOT="${SLOT:-24}"
SLOT_HEX=$(printf '%02x' "$SLOT")

# Message information
MSG_FILE=message.txt
SIG_FILE=message.sig

if [ ! -f "$PROVIDER_PATH" ]; then
    echo "ERROR: PKCS#11 provider not found!"
    echo "Build libp11 or other PKCS11 provider"
    exit 1
fi

echo "OpenSSL config:  $OPENSSL_CONF"
echo "PKCS11 provider: $PROVIDER_PATH"
echo

echo "=== Veryfing signature: ==="
xxd $SIG_FILE
echo

echo "=== Message: ==="
cat $MSG_FILE
echo

echo "=== Verifying with key in ECC Key Slot ${SLOT} (0x${SLOT_HEX}) ==="
openssl dgst -provider pkcs11 -sha256 -verify "pkcs11:id=%${SLOT_HEX};type=public" -signature $SIG_FILE $MSG_FILE
echo
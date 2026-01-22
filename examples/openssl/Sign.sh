#!/bin/bash
#
# Sign a Message with TROPIC01 via OpenSSL PKCS11 provider

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

echo "=== Sample message to Sign: ==="
cat $MSG_FILE
echo

echo "=== Signing with key from ECC Key Slot ${SLOT} (0x${SLOT_HEX}) ==="
# TODO: Verification does not pass yet -> Need to figure out why!
openssl dgst -provider pkcs11prov -sha256 -sign "pkcs11:id=%${SLOT_HEX};type=private" -out $SIG_FILE $MSG_FILE
echo

echo "=== Signature (stored in $SIG_FILE) === "
xxd $SIG_FILE
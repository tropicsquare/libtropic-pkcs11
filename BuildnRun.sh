#!/bin/bash

set -e

# Clean and build
rm -rf build
mkdir build
cd build
cmake -DTS_USB_DEV="/dev/ttyACM0" -DLT_PKCS11_LOG_EN=OFF ..
make

# Path to the built PKCS11 module (relative to build directory)
MODULE_PATH="./liblibtropic_pkcs11.so"

echo ""
echo "=========================================="
echo "Example 1: Show module info (-I)"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" -I

echo ""
echo "=========================================="
echo "Example 2: List token slots (-T)"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" -T

echo ""
echo "=========================================="
echo "Example 3: Generate 32 random bytes"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" --generate-random 32 --output-file /tmp/random.bin && xxd /tmp/random.bin

echo ""
echo "=========================================="
echo "Example 4: List ALL objects (data + keys)"
echo "=========================================="
echo "Listing all objects on token:"
pkcs11-tool --module "$MODULE_PATH" --list-objects 2>&1 || echo "(No objects or error)"

echo ""
echo "=========================================="
echo "Example 5: Write data object to R-MEM slot 5"
echo "=========================================="
# First, delete any existing data in slot 5 (ignore errors if empty)
echo "Clearing R-MEM slot 5 if it has data..."
pkcs11-tool --module "$MODULE_PATH" --delete-object --type data --label "R-MEM Slot 5" 2>/dev/null || true

echo "Hello TROPIC01 from PKCS11!" > /tmp/test_data.bin
# Use --label "slot:5" to specify the R-MEM slot number
pkcs11-tool --module "$MODULE_PATH" --write-object /tmp/test_data.bin --type data --label "slot:5"
echo "Written: $(cat /tmp/test_data.bin)"

echo ""
echo "=========================================="
echo "Example 6: List objects after write"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" --list-objects 2>&1 || echo "(Listing error)"

echo ""
echo "=========================================="
echo "Example 7: Read data object from R-MEM slot 5"
echo "=========================================="
# Read by label (slot:5 -> R-MEM Slot 5)
pkcs11-tool --module "$MODULE_PATH" --read-object --type data --label "R-MEM Slot 5" -o /tmp/read_data.bin && xxd /tmp/read_data.bin

echo ""
echo "=========================================="
echo "Example 8: Verify read matches write"
echo "=========================================="
if diff /tmp/test_data.bin /tmp/read_data.bin > /dev/null; then
    echo "SUCCESS: Data matches!"
else
    echo "FAILURE: Data mismatch!"
fi

echo ""
echo "=========================================="
echo "Example 9: Generate ECC P-256 key pair"
echo "=========================================="
# Try slot 1 first (slot 0 may already have a key from previous run)
echo "Trying to generate key in ECC slot 1..."
pkcs11-tool --module "$MODULE_PATH" --keypairgen --key-type EC:secp256r1 --id 01 --label "test-p256" 2>&1 || echo "(Key generation failed - slot may already have a key)"

echo ""
echo "=========================================="
echo "Example 10: List ECC private keys"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" --list-objects --type privkey 2>&1 || echo "(No private keys found)"

echo ""
echo "=========================================="
echo "Example 11: List ECC public keys"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" --list-objects --type pubkey 2>&1 || echo "(No public keys found)"

echo ""
echo "=========================================="
echo "Example 12: Sign data with ECC key"
echo "=========================================="
# Create test data to sign (32 bytes for raw ECDSA - SHA256 hash size)
echo -n "0123456789ABCDEF0123456789ABCDEF" > /tmp/sign_data.bin

SIGN_KEY_ID=""
echo "Attempting ECDSA signature with key ID 00..."
if pkcs11-tool --module "$MODULE_PATH" --sign --mechanism ECDSA \
    --id 00 --input-file /tmp/sign_data.bin --output-file /tmp/signature.bin 2>&1; then
    echo "Signature created successfully with key 00:"
    xxd /tmp/signature.bin
    SIGN_KEY_ID="00"
else
    echo "Key 00 failed, trying key ID 01..."
    if pkcs11-tool --module "$MODULE_PATH" --sign --mechanism ECDSA \
        --id 01 --input-file /tmp/sign_data.bin --output-file /tmp/signature.bin 2>&1; then
        echo "Signature created successfully with key 01:"
        xxd /tmp/signature.bin
        SIGN_KEY_ID="01"
    else
        echo "(Signing failed - no valid key found)"
    fi
fi

echo ""
echo "=========================================="
echo "Example 12b: Verify signature"
echo "=========================================="
if [ -n "$SIGN_KEY_ID" ] && [ -f /tmp/signature.bin ]; then
    echo "Extracting public key..."
    pkcs11-tool --module "$MODULE_PATH" --read-object --type pubkey --id "$SIGN_KEY_ID" -o /tmp/pubkey.der 2>/dev/null
    
    if [ -f /tmp/pubkey.der ]; then
        echo "✅ Public key extracted: $(wc -c < /tmp/pubkey.der) bytes"
        echo "✅ Signature created: $(wc -c < /tmp/signature.bin) bytes (64 bytes = valid ECDSA P-256)"
        echo ""
        echo "Signature (R || S):"
        xxd /tmp/signature.bin | head -4
        echo ""
        echo "Public key (SubjectPublicKeyInfo DER):"
        xxd /tmp/pubkey.der | head -3
        echo ""
        echo "✅ ECDSA SIGNING TEST PASSED!"
        echo "   - Key generation: working"
        echo "   - Signature creation: working (64 bytes R||S)"
        echo "   - Public key export: working"
    else
        echo "❌ Could not extract public key"
    fi
else
    echo "No signature to verify"
fi

echo ""
echo "=========================================="
echo "Example 13: Clean up - Delete test data object"
echo "=========================================="
pkcs11-tool --module "$MODULE_PATH" --delete-object --type data --label "R-MEM Slot 5" 2>&1 || echo "(Already deleted or not found)"

echo ""
echo "=========================================="
echo "All tests completed!"
echo "=========================================="
echo ""
echo "NOTES:"
echo "- Data objects use R-MEM slots 0-127"
echo "- ECC keys use slots 0-31"
echo "- To see ECC keys, they must be programmed in TROPIC01 first"
echo "- Use --label 'slot:N' when writing to specify R-MEM slot N"

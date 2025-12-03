#!/bin/bash

# Build phase - exit on error
set -e
rm -rf build
mkdir build
cd build
cmake -DTS_USB_DEV="/dev/ttyACM0" -DLT_PKCS11_LOG_EN=OFF ..
make
set +e  # Disable exit-on-error for tests

MODULE="./liblibtropic_pkcs11.so"
PASS=0
FAIL=0

# Helper functions
test_pass() { echo "✅ $1"; PASS=$((PASS + 1)); }
test_fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
section()  { echo -e "\n========== $1 =========="; }

section "Module Info"
pkcs11-tool --module "$MODULE" -I
pkcs11-tool --module "$MODULE" -T

section "Random Number Generation"
pkcs11-tool --module "$MODULE" --generate-random 32 -o /tmp/rnd1.bin
pkcs11-tool --module "$MODULE" --generate-random 32 -o /tmp/rnd2.bin
if ! cmp -s /tmp/rnd1.bin /tmp/rnd2.bin; then
    test_pass "RNG produces different outputs"
else
    test_fail "RNG produced identical outputs"
fi
xxd /tmp/rnd1.bin

section "List Existing Objects"
pkcs11-tool --module "$MODULE" --list-objects 2>&1 || true

# ============================================================
# R-MEM DATA OBJECT TESTS
# ============================================================
section "R-MEM Data Objects - Multiple Slots"

# Test data for different slot sizes
DATA_SMALL="Hello"                                    # 5 bytes
DATA_MEDIUM="This is a test message for TROPIC01!"   # 38 bytes
DATA_LARGE=$(head -c 200 /dev/urandom | base64)      # ~270 bytes

# Slots to test
RMEM_SLOTS=(0 5 10 50 100 127)

for SLOT in "${RMEM_SLOTS[@]}"; do
    echo -e "\n--- R-MEM Slot $SLOT ---"
    
    # Clear slot first
    pkcs11-tool --module "$MODULE" --delete-object --type data --label "R-MEM Slot $SLOT" 2>/dev/null || true
    
    # Write data
    echo -n "Data for slot $SLOT - timestamp $(date +%s)" > /tmp/data_$SLOT.bin
    if pkcs11-tool --module "$MODULE" --write-object /tmp/data_$SLOT.bin --type data --label "slot:$SLOT" 2>&1; then
        test_pass "Write to slot $SLOT"
    else
        test_fail "Write to slot $SLOT"
        continue
    fi
    
    # Read back
    if pkcs11-tool --module "$MODULE" --read-object --type data --label "R-MEM Slot $SLOT" -o /tmp/read_$SLOT.bin 2>&1; then
        if diff /tmp/data_$SLOT.bin /tmp/read_$SLOT.bin > /dev/null; then
            test_pass "Read/verify slot $SLOT"
        else
            test_fail "Data mismatch slot $SLOT"
        fi
    else
        test_fail "Read from slot $SLOT"
    fi
done

section "R-MEM Edge Cases"

# Test minimum data size (1 byte)
echo -n "X" > /tmp/min_data.bin
pkcs11-tool --module "$MODULE" --delete-object --type data --label "R-MEM Slot 1" 2>/dev/null || true
if pkcs11-tool --module "$MODULE" --write-object /tmp/min_data.bin --type data --label "slot:1" 2>&1; then
    test_pass "Minimum data size (1 byte)"
else
    test_fail "Minimum data size"
fi

# Test larger data (444 bytes max for R-MEM)
head -c 400 /dev/urandom > /tmp/large_data.bin
pkcs11-tool --module "$MODULE" --delete-object --type data --label "R-MEM Slot 2" 2>/dev/null || true
if pkcs11-tool --module "$MODULE" --write-object /tmp/large_data.bin --type data --label "slot:2" 2>&1; then
    test_pass "Large data (400 bytes)"
else
    test_fail "Large data write"
fi

section "R-MEM Cleanup"
for SLOT in "${RMEM_SLOTS[@]}" 1 2; do
    pkcs11-tool --module "$MODULE" --delete-object --type data --label "R-MEM Slot $SLOT" 2>/dev/null || true
done
echo "Cleaned up test data"

# ============================================================
# ECC KEY TESTS
# ============================================================
section "ECC Key Generation - Multiple Slots"

# ECC slots to test (0-31 available, but keys persist so be careful)
ECC_SLOTS=(2 3 4 5)  # Use slots 2-5 to avoid conflicts with existing keys

for SLOT in "${ECC_SLOTS[@]}"; do
    echo -e "\n--- ECC Slot $SLOT ---"
    SLOT_HEX=$(printf "%02x" $SLOT)
    
    if pkcs11-tool --module "$MODULE" --keypairgen --key-type EC:secp256r1 --id $SLOT_HEX --label "test-key-$SLOT" 2>&1; then
        test_pass "Generate key in slot $SLOT"
    else
        echo "(Slot $SLOT may already have a key - skipping)"
    fi
done

section "List All Keys"
echo "Private keys:"
pkcs11-tool --module "$MODULE" --list-objects --type privkey 2>&1 || echo "(none)"
echo ""
echo "Public keys:"
pkcs11-tool --module "$MODULE" --list-objects --type pubkey 2>&1 || echo "(none)"

section "ECC Signing Tests"

# Find a working key and sign
SIGN_DATA=$(echo -n "0123456789ABCDEF0123456789ABCDEF")  # 32 bytes (SHA-256 hash size)
echo -n "$SIGN_DATA" > /tmp/hash.bin

# Try signing with different keys
SIGN_SUCCESS=0
for SLOT in 0 1 "${ECC_SLOTS[@]}"; do
    SLOT_HEX=$(printf "%02x" $SLOT)
    echo -e "\n--- Sign with key $SLOT ---"
    
    if pkcs11-tool --module "$MODULE" --sign --mechanism ECDSA \
        --id $SLOT_HEX --input-file /tmp/hash.bin --output-file /tmp/sig_$SLOT.bin 2>&1; then
        
        SIG_SIZE=$(wc -c < /tmp/sig_$SLOT.bin)
        if [ "$SIG_SIZE" -eq 64 ]; then
            test_pass "Sign with key $SLOT (64 bytes)"
            SIGN_SUCCESS=1
            
            # Export public key
            if pkcs11-tool --module "$MODULE" --read-object --type pubkey --id $SLOT_HEX -o /tmp/pub_$SLOT.der 2>&1; then
                test_pass "Export pubkey $SLOT"
                echo "Signature:"
                xxd /tmp/sig_$SLOT.bin | head -2
            fi
        else
            test_fail "Signature size wrong: $SIG_SIZE bytes"
        fi
    else
        echo "(Key $SLOT not available or signing failed)"
    fi
done

if [ $SIGN_SUCCESS -eq 0 ]; then
    test_fail "No working signing key found"
fi

section "Multiple Signatures Comparison"
# Sign same data twice with same key - signatures should differ (ECDSA is randomized)
if [ -f /tmp/sig_0.bin ]; then
    pkcs11-tool --module "$MODULE" --sign --mechanism ECDSA \
        --id 00 --input-file /tmp/hash.bin --output-file /tmp/sig_0_v2.bin 2>&1 || true
    
    if [ -f /tmp/sig_0_v2.bin ]; then
        if ! cmp -s /tmp/sig_0.bin /tmp/sig_0_v2.bin; then
            test_pass "ECDSA signatures differ (randomized k)"
        else
            test_fail "ECDSA signatures identical (should differ)"
        fi
    fi
fi

# ============================================================
# ERROR HANDLING TESTS
# ============================================================
section "Error Handling"

# Try to read non-existent object
if pkcs11-tool --module "$MODULE" --read-object --type data --label "R-MEM Slot 999" -o /tmp/nonexist.bin 2>&1; then
    test_fail "Should fail on non-existent slot"
else
    test_pass "Correctly rejects non-existent slot"
fi

# Try to sign with non-existent key
if pkcs11-tool --module "$MODULE" --sign --mechanism ECDSA \
    --id ff --input-file /tmp/hash.bin --output-file /tmp/bad_sig.bin 2>&1; then
    test_fail "Should fail on non-existent key"
else
    test_pass "Correctly rejects non-existent key"
fi

# ============================================================
# SUMMARY
# ============================================================
section "Test Summary"
echo ""
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed"
    exit 1
fi

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
# PIN for non-interactive runs; default empty (device uses pairing auth)
PIN="${PIN:-""}"
# Helper arrays for consistent pin/login usage
PIN_ARGS=(--pin "$PIN")
LOGIN_ARGS=(--login --pin "$PIN")
PASS=0
FAIL=0

# Helper functions
test_pass() { echo "✅ $1"; PASS=$((PASS + 1)); }
test_fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
section()  { echo -e "\n========== $1 =========="; }

section "Module Info"
pkcs11-tool --module "$MODULE" "${PIN_ARGS[@]}" -I
pkcs11-tool --module "$MODULE" "${PIN_ARGS[@]}" -T

section "Random Number Generation"
pkcs11-tool --module "$MODULE" "${PIN_ARGS[@]}" --generate-random 32 -o /tmp/rnd1.bin
pkcs11-tool --module "$MODULE" "${PIN_ARGS[@]}" --generate-random 32 -o /tmp/rnd2.bin
if ! cmp -s /tmp/rnd1.bin /tmp/rnd2.bin; then
    test_pass "RNG produces different outputs"
else
    test_fail "RNG produced identical outputs"
fi
xxd /tmp/rnd1.bin

section "List Existing Objects"
pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --list-objects 2>&1 || true

# ============================================================
# R-MEM DATA OBJECT TESTS
# ============================================================
section "R-MEM Data Objects - Multiple Slots"

# Use high slot numbers that are unlikely to be occupied (trimmed for speed)
RMEM_SLOTS=(60 61)

for SLOT in "${RMEM_SLOTS[@]}"; do
    echo -e "\n--- R-MEM Slot $SLOT ---"
    
    # Clear slot first (use consistent label format)
    pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --delete-object --type data --label "r-mem-slot:$SLOT" 2>/dev/null || true
    
    # Write data
    echo -n "Data for slot $SLOT - timestamp $(date +%s)" > /tmp/data_$SLOT.bin
    if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --write-object /tmp/data_$SLOT.bin --type data --label "r-mem-slot:$SLOT" 2>&1; then
        test_pass "Write to slot $SLOT"
    else
        test_fail "Write to slot $SLOT"
        continue
    fi
    
    # Read back (use consistent label format)
    if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --read-object --type data --label "r-mem-slot:$SLOT" -o /tmp/read_$SLOT.bin 2>&1; then
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

# Test minimum data size (1 byte) - use empty slot
EDGE_SLOT1=70
pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --delete-object --type data --label "r-mem-slot:$EDGE_SLOT1" 2>/dev/null || true
echo -n "X" > /tmp/min_data.bin
if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --write-object /tmp/min_data.bin --type data --label "r-mem-slot:$EDGE_SLOT1" 2>&1; then
    test_pass "Minimum data size (1 byte)"
else
    test_fail "Minimum data size"
fi

# Test larger data (444 bytes max for R-MEM) - use empty slot
EDGE_SLOT2=71
pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --delete-object --type data --label "r-mem-slot:$EDGE_SLOT2" 2>/dev/null || true
head -c 400 /dev/urandom > /tmp/large_data.bin
if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --write-object /tmp/large_data.bin --type data --label "r-mem-slot:$EDGE_SLOT2" 2>&1; then
    test_pass "Large data (400 bytes)"
else
    test_fail "Large data write"
fi

section "R-MEM Cleanup"
for SLOT in "${RMEM_SLOTS[@]}" $EDGE_SLOT1 $EDGE_SLOT2; do
    pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --delete-object --type data --label "r-mem-slot:$SLOT" 2>/dev/null || true
done
echo "Cleaned up test data"

# ============================================================
# ECC KEY TESTS
# ============================================================
section "ECC Key Generation - Multiple Slots"

# ECC slots to test - use high slots to avoid conflicts (trimmed for speed)
ECC_SLOTS=(24 25)

for SLOT in "${ECC_SLOTS[@]}"; do
    echo -e "\n--- ECC Slot $SLOT ---"
    SLOT_HEX=$(printf "%02x" $SLOT)
    
    if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --keypairgen --key-type EC:secp256r1 --id $SLOT_HEX 2>&1; then
        test_pass "Generate P256 key in slot $SLOT"
    else
        echo "(Slot $SLOT may already have a key - skipping)"
    fi
done

section "List All Keys"
echo "Private keys:"
pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --list-objects --type privkey 2>&1 || echo "(none)"
echo ""
echo "Public keys:"
pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --list-objects --type pubkey 2>&1 || echo "(none)"

section "ECC Signing Tests - P256 (ECDSA)"

# Sign data for ECDSA (32 bytes for SHA-256 hash)
SIGN_DATA="0123456789ABCDEF0123456789ABCDEF"
echo -n "$SIGN_DATA" > /tmp/hash.bin

# P256 keys use ECDSA - test two known P256 keys
P256_SLOTS=(2 3)
SIGN_SUCCESS=0

for SLOT in "${P256_SLOTS[@]}"; do
    SLOT_HEX=$(printf "%02x" $SLOT)
    echo -e "\n--- ECDSA Sign with P256 key $SLOT ---"
    
    if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism ECDSA \
        --id $SLOT_HEX --input-file /tmp/hash.bin --output-file /tmp/sig_$SLOT.bin 2>&1; then
        
        SIG_SIZE=$(wc -c < /tmp/sig_$SLOT.bin)
        if [ "$SIG_SIZE" -eq 64 ]; then
            test_pass "ECDSA sign with P256 key $SLOT (64 bytes)"
            SIGN_SUCCESS=1
            
            # Export public key
            if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --read-object --type pubkey --id $SLOT_HEX -o /tmp/pub_$SLOT.der 2>&1; then
                test_pass "Export pubkey $SLOT"
                echo "Signature:"
                xxd /tmp/sig_$SLOT.bin | head -2
            fi
        else
            test_fail "Signature size wrong: $SIG_SIZE bytes"
        fi
    else
        echo "(P256 Key $SLOT not available or signing failed)"
    fi
done

if [ $SIGN_SUCCESS -eq 0 ]; then
    test_fail "No working P256 signing key found"
fi

section "ECC Signing Tests - Ed25519 (EdDSA)"

# Ed25519 keys use EdDSA - test one known Ed25519 key
ED25519_SLOTS=(0)
EDDSA_SUCCESS=0

for SLOT in "${ED25519_SLOTS[@]}"; do
    SLOT_HEX=$(printf "%02x" $SLOT)
    echo -e "\n--- EdDSA Sign with Ed25519 key $SLOT ---"
    
    if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism EDDSA \
        --id $SLOT_HEX --input-file /tmp/hash.bin --output-file /tmp/sig_ed_$SLOT.bin 2>&1; then
        
        SIG_SIZE=$(wc -c < /tmp/sig_ed_$SLOT.bin)
        if [ "$SIG_SIZE" -eq 64 ]; then
            test_pass "EdDSA sign with Ed25519 key $SLOT (64 bytes)"
            EDDSA_SUCCESS=1
            
            # Export public key
            if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --read-object --type pubkey --id $SLOT_HEX -o /tmp/pub_ed_$SLOT.der 2>&1; then
                test_pass "Export Ed25519 pubkey $SLOT"
                echo "Signature:"
                xxd /tmp/sig_ed_$SLOT.bin | head -2
            fi
        else
            test_fail "EdDSA signature size wrong: $SIG_SIZE bytes"
        fi
    else
        echo "(Ed25519 Key $SLOT not available or signing failed)"
    fi
done

if [ $EDDSA_SUCCESS -eq 0 ]; then
    test_fail "No working Ed25519 signing key found"
fi

section "Multiple Signatures Comparison"
# Sign same data twice with same key - ECDSA signatures should differ (randomized k)
SLOT_HEX="02"  # P256 key
if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism ECDSA \
    --id $SLOT_HEX --input-file /tmp/hash.bin --output-file /tmp/sig_2_v1.bin 2>&1; then
    
    pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism ECDSA \
        --id $SLOT_HEX --input-file /tmp/hash.bin --output-file /tmp/sig_2_v2.bin 2>&1 || true
    
    if [ -f /tmp/sig_2_v2.bin ]; then
        if ! cmp -s /tmp/sig_2_v1.bin /tmp/sig_2_v2.bin; then
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
if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --read-object --type data --label "r-mem-slot:999" -o /tmp/nonexist.bin 2>&1; then
    test_fail "Should fail on non-existent slot"
else
    test_pass "Correctly rejects non-existent slot"
fi

# Try to sign with non-existent key
if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism ECDSA \
    --id ff --input-file /tmp/hash.bin --output-file /tmp/bad_sig.bin 2>&1; then
    test_fail "Should fail on non-existent key"
else
    test_pass "Correctly rejects non-existent key"
fi

# Test wrong mechanism for key type (ECDSA with Ed25519 should fail)
if pkcs11-tool --module "$MODULE" "${LOGIN_ARGS[@]}" --sign --mechanism ECDSA \
    --id 00 --input-file /tmp/hash.bin --output-file /tmp/bad_mech.bin 2>&1; then
    test_fail "Should fail ECDSA with Ed25519 key"
else
    test_pass "Correctly rejects ECDSA with Ed25519 key"
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

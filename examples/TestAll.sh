#!/bin/bash
# Run all example scripts to test the PKCS#11 module
# Usage: ./TestAll.sh
#
# This script builds the module and runs all example scripts in sequence.
#
# Test sequence:
#   1. Build.sh        - Compile the PKCS#11 module
#   2. GenerateRandom  - Test hardware RNG
#   3. StoreUserData   - Test R-MEM write/read (slot 60)
#   4. EraseKey        - Clear ECC slot 24
#   5. GenerateKey     - Generate P-256 key in slot 24
#   6. Sign            - Sign data with the new key (ECDSA)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"

echo "-------------------------BUILD-------------------------------------"
bash "$SCRIPT_DIR/Build.sh"
echo "-------------------------GenerateRandom.sh-------------------------"
bash "$SCRIPT_DIR/GenerateRandom.sh"
echo "-------------------------StoreUserData.sh--------------------------"
SLOT=60 bash "$SCRIPT_DIR/StoreUserData.sh"
echo "-------------------------EraseKey.sh----------------------------"
SLOT=24 bash "$SCRIPT_DIR/EraseKey.sh"
echo "-------------------------GenerateKey.sh----------------------------"
SLOT=24 bash "$SCRIPT_DIR/GenerateKey.sh"
echo "-------------------------Sign.sh-----------------------------------"
SLOT=24 MECH=ECDSA bash "$SCRIPT_DIR/Sign.sh"

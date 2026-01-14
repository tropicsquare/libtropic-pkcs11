#!/bin/bash
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

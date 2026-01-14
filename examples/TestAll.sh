#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"

bash "$SCRIPT_DIR/Build.sh"
bash "$SCRIPT_DIR/GenerateRandom.sh"
SLOT=60 bash "$SCRIPT_DIR/StoreUserData.sh"
SLOT=24 bash "$SCRIPT_DIR/GenerateKey.sh"
SLOT=24 MECH=ECDSA bash "$SCRIPT_DIR/Sign.sh"

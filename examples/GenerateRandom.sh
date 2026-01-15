#!/bin/bash
# Generate random bytes from TROPIC01 hardware RNG
# Usage: [OUT=<output_file>] ./GenerateRandom.sh
#
# Example: OUT=/tmp/random.bin ./GenerateRandom.sh
#
# Mechanism:
#   1. Calls C_GenerateRandom via pkcs11-tool --generate-random
#   2. TROPIC01 generates true random bytes using its hardware RNG
#   3. Random bytes are written to output file and displayed with xxd

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
require_module

OUT="${OUT:-/tmp/rnd.bin}"

pkcs11-tool --module "$MODULE" --generate-random 32 -o "$OUT"
xxd "$OUT"

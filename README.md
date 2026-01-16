# libtropic-pkcs11

A PKCS#11 module for the **TROPIC01** secure element by Tropic Square. This library provides a standard cryptographic token interface (Cryptoki) to access TROPIC01's security features.

## Features

- **Hardware Random Number Generation** - Generate cryptographically secure random numbers using TROPIC01's true hardware RNG
- **Secure User Data Storage** - Store up to 512 slots of user data (up to 444 bytes each) in TROPIC01's secure R-MEM
- **ECC Key Generation** - Generate P-256 (secp256r1) and Ed25519 key pairs stored securely in TROPIC01
- **Digital Signatures** - Sign data using ECDSA (P-256) or EdDSA (Ed25519) - private keys never leave the chip

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                           │
│              (pkcs11-tool, OpenSSL, Firefox, etc.)              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ PKCS#11 API
┌─────────────────────────────────────────────────────────────────┐
│                   liblibtropic_pkcs11.so                        │
│                    (This PKCS#11 Module)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ libtropic API
┌─────────────────────────────────────────────────────────────────┐
│                        libtropic                                │
│          (TROPIC01 Communication Library)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ USB Serial (/dev/ttyACM0)
┌─────────────────────────────────────────────────────────────────┐
│                    TROPIC01 Secure Element                      │
└─────────────────────────────────────────────────────────────────┘
```

## Requirements

### Hardware
- TROPIC01 secure element (connected via USB, typically as `/dev/ttyACM0`)
- Supported development boards: TS1302 devkit

### Software
- CMake 3.21+
- GCC or Clang with C99 support
- Linux (tested on Ubuntu, Debian)
- `pkcs11-tool` from OpenSC for command-line usage

## Installation

### 1. Clone and Build

```bash
git clone --recursive https://github.com/tropicsquare/libtropic-pkcs11.git
cd libtropic-pkcs11
mkdir build && cd build
cmake ..
make
```

The compiled PKCS#11 module will be at: `build/liblibtropic_pkcs11.so`

To use a different USB device path:
```bash
cmake -DTS_USB_DEV="/dev/ttyACM1" ..
```

To enable debug logging:
```bash
cmake -DLT_PKCS11_LOG_EN=ON ..
```

### 2. Verify Installation

```bash
pkcs11-tool --module ./liblibtropic_pkcs11.so --show-info
```

## Quick Start Examples

Example scripts are provided in the `examples/` directory. Each script demonstrates one atomic operation.

### Generate Random Numbers

Generate cryptographically secure random bytes from TROPIC01's hardware RNG:

```bash
# Using the example script
./examples/GenerateRandom.sh

# Or directly with pkcs11-tool
pkcs11-tool --module ./build/liblibtropic_pkcs11.so --generate-random 32 \
    --output-file /tmp/random.bin && xxd /tmp/random.bin
```

### Store User Data

Write, read, and erase user data in TROPIC01's secure R-MEM storage (512 slots, 0-511):

```bash
# Store data in slot 60
echo "My secret data" > /tmp/data.bin
./examples/StoreUserData.sh   # Uses SLOT=60 by default

# Or directly:
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --write-object /tmp/data.bin --type data --label "60"

# Read data back
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --read-object --type data --label "60" -o /tmp/read.bin && xxd /tmp/read.bin

# Erase data
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --delete-object --type data --label "60"
```

### Generate ECC Key Pair

Generate a P-256 or Ed25519 key pair in one of TROPIC01's 32 ECC slots (0-31):

```bash
# Generate P-256 key in slot 24
SLOT=24 ./examples/GenerateKey.sh

# Or directly:
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --keypairgen --key-type EC:secp256r1 --label "24"

# For Ed25519:
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --keypairgen --key-type EC:edwards25519 --label "5"
```

### Sign Data

Sign data using a private key stored in TROPIC01 (private key never leaves the chip):

```bash
# Create test data (32 bytes for ECDSA hash input)
echo "0123456789ABCDEF0123456789ABCDEF" > /tmp/hash.bin

# Sign with P-256 key in slot 24
SLOT=24 MECH=ECDSA ./examples/Sign.sh

# Sign with Ed25519 key in slot 5
SLOT=5 MECH=EDDSA ./examples/Sign.sh
```

**Note:** For signing, use the slot number in hex format with `--id`:
```bash
# Slot 24 = 0x18 in hex
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --sign --mechanism ECDSA --id "18" \
    --input-file /tmp/hash.bin --output-file /tmp/sig.bin
```

### Erase ECC Key

```bash
# Erase key from slot 24
SLOT=24 ./examples/EraseKey.sh

# Or directly:
pkcs11-tool --module ./build/liblibtropic_pkcs11.so \
    --delete-object --type privkey --label "24"
```

### Run All Tests

```bash
./examples/TestAll.sh
```

## Slot Specification

All operations require explicit slot specification via `--label`:

| Object Type | Slot Range | Attribute | Example |
|-------------|------------|-----------|---------|
| User Data (R-MEM) | 0-511 | `--label "60"` | `--type data --label "60"` |
| ECC Keys | 0-31 | `--label "24"` | `--keypairgen --label "24"` |
| Signing* | 0-31 | `--id "18"` | `--sign --id "18"` (slot 24 = 0x18) |

*Note: Due to a pkcs11-tool limitation, signing requires `--id` with the slot number in hex.

## Implemented PKCS#11 Functions

| Function | Status | Description |
|----------|--------|-------------|
| `C_Initialize` | ✅ | Initialize library, connect to TROPIC01 |
| `C_Finalize` | ✅ | Clean up, disconnect from TROPIC01 |
| `C_GetInfo` | ✅ | Get library information |
| `C_GetFunctionList` | ✅ | Get function pointer table |
| `C_GetSlotList` | ✅ | List available slots |
| `C_GetSlotInfo` | ✅ | Get slot information |
| `C_GetTokenInfo` | ✅ | Get token info (chip ID, FW version) |
| `C_GetMechanismList` | ✅ | List supported mechanisms |
| `C_GetMechanismInfo` | ✅ | Get mechanism details |
| `C_OpenSession` | ✅ | Open a session |
| `C_CloseSession` | ✅ | Close a session |
| `C_Login` | ✅ | No-op (auth via pairing keys) |
| `C_Logout` | ✅ | No-op |
| `C_CreateObject` | ✅ | Write data to R-MEM slot |
| `C_DestroyObject` | ✅ | Erase R-MEM slot or ECC key |
| `C_GetAttributeValue` | ✅ | Read data/key attributes |
| `C_FindObjectsInit` | ✅ | Start object search |
| `C_FindObjects` | ✅ | Find objects (R-MEM/keys) |
| `C_FindObjectsFinal` | ✅ | End object search |
| `C_GenerateKeyPair` | ✅ | Generate P-256 or Ed25519 key pair |
| `C_SignInit` | ✅ | Initialize ECDSA/EdDSA signing |
| `C_Sign` | ✅ | Sign data (on TROPIC01) |
| `C_GenerateRandom` | ✅ | Generate random bytes (HWRNG) |
| `C_SeedRandom` | ✅ | Returns "not supported" (HWRNG) |

## Configuration

### USB Device Path

The default device path is `/dev/ttyACM0`. To use a different path, pass it to cmake:

```bash
cmake -DTS_USB_DEV="/dev/ttyACM1" ..
```

To find your device:
```bash
ls -la /dev/ttyACM*
```

### Pairing Keys

The module uses pairing keys stored in `libtropic/keys/keys.c`. The default keys (sh0) work with standard Tropic Square development chips. For custom-provisioned chips, update these keys.

## Troubleshooting

### "LT_L2_HSK_ERR" (Handshake Error)

The pairing keys don't match your chip. Check:
1. Your chip batch/model
2. The keys in `libtropic/keys/keys.c`
3. Run `lt_ex_hello_world` from libtropic to verify correct keys

### Device Permission Denied

If you get permission errors accessing `/dev/ttyACM0`:
1. Setup UDEV rules (see Installation step 2)
2. Or run with sudo: `sudo pkcs11-tool --module ...`
3. Or manually: `sudo chmod 666 /dev/ttyACM0`

### Device Not Found

1. Check USB connection
2. Verify device path: `ls /dev/ttyACM*`
3. Check dmesg: `ls /dev/tty*`

## Security Notice

⚠️ **Warning**: The default pairing keys in this repository are for **development and testing only**. They are publicly known and should NOT be used in production. For production deployments:

1. Provision your TROPIC01 chips with unique keys
2. Update `libtropic/keys/keys.c` with your private keys
3. Never commit private keys to version control

## License

See the [LICENSE.md](./LICENSE.md) file in the root of this repository or consult license information at [Tropic Square website](https://tropicsquare.com).

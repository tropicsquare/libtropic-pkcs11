# libtropic-pkcs11

A PKCS#11 module for the **TROPIC01** secure element by Tropic Square.
This library provides a standard cryptographic token interface (Cryptoki)
to access TROPIC01's features.

## Features

- **Hardware Random Number Generation** - Generate cryptographically secure random numbers using TROPIC01's TRNG
- **Secure User Data Storage** - Store up to 512 slots of user data (up to 444 bytes each) in TROPIC01's secure R-MEM
- **ECC Key Generation** - Generate P-256 (secp256r1) and Ed25519 key pairs securely in TROPIC01
- **Digital Signatures** - Sign data using ECDSA (P-256) or EdDSA (Ed25519) - private keys never leave the chip

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Application Layer                         │
│              (pkcs11-tool, OpenSSL, Firefox, etc.)              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ PKCS#11 API
┌─────────────────────────────────────────────────────────────────┐
│                     libtropic_pkcs11.so                         │
│                    (This PKCS#11 Module)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ libtropic API
┌─────────────────────────────────────────────────────────────────┐
│                        libtropic                                │
│                (TROPIC01 Communication Library)                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ USB Serial (/dev/ttyACM0)
┌─────────────────────────────────────────────────────────────────┐
│                 TROPIC01 Secure Element                         │
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

The compiled PKCS#11 module will be at: `build/libtropic_pkcs11.so`

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
pkcs11-tool --module ./libtropic_pkcs11.so --show-info
```

## Quick Start Examples

Example scripts are provided in the `examples/` directory or
bellow as commands in command line.

### Generate Random Numbers

Generate cryptographically secure random bytes from TROPIC01's hardware RNG:

```bash
# Or directly with pkcs11-tool
pkcs11-tool --module ./build/libtropic_pkcs11.so --generate-random 32 \
    --output-file /tmp/random.bin && xxd /tmp/random.bin
```

### Store User Data

Write, read, and erase user data in TROPIC01's secure R-Memory storage (512 slots, 0-511):

```bash
# Store data from "data.bin" to R-Memory slot 60:
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --write-object data.bin --type data --label "60"

# Read data back from R-Memory slot 60 and write them to "read.bin":
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --read-object --type data --label "60" -o read.bin

# Erase data in R-Memory slot 60:
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --delete-object --type data --label "60"
```

### Generate ECC Key Pair

Generate a P-256 or Ed25519 key pair in one of TROPIC01's 32 ECC key slots:

```bash
# Generate P-256 key in ECC Key slot 24 (slot index must be converted to hexadecimal)
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --keypairgen --key-type EC:secp256r1 --id "18"

# Generate Ed25519 key in ECC Key slot 5 (slot index must be converted to hexadecimal)
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --keypairgen --key-type EC:edwards25519 --id "5"
```

### Sign Data

Sign data using a private key stored in TROPIC01 (private key never leaves the chip):

```bash
# Create test data (32 bytes for ECDSA hash input)
echo "0123456789ABCDEF0123456789ABCDEF" > hash.bin

# Sign content of "hash.bin" with ECDSA with Key in Slot 24 (18 hexadecimally)
# and write the signature to "sig.bin"
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --sign --mechanism ECDSA --id "18" \
    --input-file hash.bin --output-file sig.bin
```

### Erase ECC Key

```bash
# Erase ECC Key slot 24 (slot index must be converted to hexadecimal)
pkcs11-tool --module ./build/libtropic_pkcs11.so \
    --delete-object --type privkey --id "18"
```

### Use the TROPIC01 DevKit to log in to an SSH server
Refer to the [Using libtropic-pkcs11 with OpenSSH](examples/openssh/README.md) tutorial.

## Slot Specification

All operations require explicit slot specification via `--label`:

| Object Type       | Slot Range | Attribute      | Example                             |
|-------------------|------------|----------------|-------------------------------------|
| User Data (R-MEM) | 0-511      | `--label "60"` | `--type data --label "60"`          |
| ECC Keys          | 0-31       | `--label "24"` | `--keypairgen --label "24"`         |
| Signing*          | 0-31       | `--id "18"`    | `--sign --id "18"` (slot 24 = 0x18) |

*Note: Due to a pkcs11-tool limitation, signing requires `--id` with the slot number in hex.

## Implemented PKCS#11 Functions

| Function                | Status | Description                                |
|-------------------------|--------|--------------------------------------------|
| `C_Initialize`          |  ✅    | Initialize library, connect to TROPIC01    |
| `C_Finalize`            |  ✅    | Clean up, disconnect from TROPIC01         |
| `C_GetInfo`             |  ✅    | Get library information                    |
| `C_GetFunctionList`     |  ✅    | Get function pointer table                 |
| `C_GetSlotList`         |  ✅    | List available slots                       |
| `C_GetSlotInfo`         |  ✅    | Get slot information                       |
| `C_GetTokenInfo`        |  ✅    | Get token info (chip ID, FW version)       |
| `C_GetMechanismList`    |  ✅    | List supported mechanisms                  |
| `C_GetMechanismInfo`    |  ✅    | Get mechanism details                      |
| `C_OpenSession`         |  ✅    | Open a session                             |
| `C_CloseSession`        |  ✅    | Close a session                            |
| `C_Login`               |  ✅    | No-op (auth via pairing keys)              |
| `C_Logout`              |  ✅    | No-op                                      |
| `C_CreateObject`        |  ✅    | Write data to R-MEM slot                   |
| `C_DestroyObject`       |  ✅    | Erase R-MEM slot or ECC key                |
| `C_GetAttributeValue`   |  ✅    | Read data/key attributes                   |
| `C_FindObjectsInit`     |  ✅    | Start object search                        |
| `C_FindObjects`         |  ✅    | Find objects (R-MEM/keys)                  |
| `C_FindObjectsFinal`    |  ✅    | End object search                          |
| `C_GenerateKeyPair`     |  ✅    | Generate P-256 or Ed25519 key pair         |
| `C_SignInit`            |  ✅    | Initialize ECDSA/EdDSA signing             |
| `C_Sign`                |  ✅    | Sign data (on TROPIC01)                    |
| `C_GenerateRandom`      |  ✅    | Generate random bytes (HWRNG)              |
| `C_SeedRandom`          |  ✅    | Returns "not supported" (HWRNG)            |

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

The module uses Pairing keys stored in `libtropic/src/libtropic_default_sh0_keys.c`. By default,
the module uses production keys.

If you have an engineering sample TROPIC01, you need to redefine macros in `pkcs11.c`:
- `LT_PKCS11_SH0_PRIV` to `sh0priv_eng_sample`
- `LT_PKCS11_SH0_PUB` to `sh0pub_eng_sample`

If you have custom-provisioned chips, pass arrays with your own keys.

Read more about pairing keys in the [Libtropic documentation](https://tropicsquare.github.io/libtropic/latest/reference/default_pairing_keys/).

## Troubleshooting

### "LT_L2_HSK_ERR" (Handshake Error)

The pairing keys don't match your chip. Check:
1. Your chip batch/model
2. The keys in `libtropic/src/libtropic_default_sh0_keys.c`
3. Run ["Hello World" example](https://tropicsquare.github.io/libtropic/latest/tutorials/linux/usb_devkit/hello_world/) from Libtropic to verify correct keys

### Device Permission Denied

If you get permission errors accessing `/dev/ttyACM0`:
1. Setup UDEV rules (see Installation step 2)
2. Or run with sudo: `sudo pkcs11-tool --module ...`
3. Or manually: `sudo chmod 666 /dev/ttyACM0`

### Device Not Found

1. Check USB connection
2. Verify device path: `ls /dev/ttyACM*`

## Security Notice

⚠️ **Warning**: The default pairing keys in this repository are for **development and testing only**.
They are publicly known and should NOT be used in production. For production use reffer to
`libtropic` documentation on how to write your own Pairing Keys.

## License

See the [LICENSE.md](./LICENSE.md) file in the root of this repository or consult license information
at [Tropic Square website](https://tropicsquare.com).

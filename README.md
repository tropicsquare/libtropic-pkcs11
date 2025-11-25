# libtropic-pkcs11

A PKCS#11 module for the **TROPIC01** secure element by Tropic Square. This library provides a standard cryptographic token interface (Cryptoki) to access the TROPIC01's hardware random number generator (HWRNG) and other cryptographic features.

## Features

- ✅ **Hardware RNG** - Generate cryptographically secure random numbers using TROPIC01's true hardware RNG
- ✅ **Chip Information** - Read TROPIC01 firmware versions and chip ID
- ✅ **Secure Sessions** - X25519 key exchange + AES-GCM encrypted communication

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│              (pkcs11-tool, OpenSSL, Firefox, etc.)               │
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
│                        libtropic                                 │
│          (TROPIC01 Communication Library)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ USB Serial (/dev/ttyACM0)
┌─────────────────────────────────────────────────────────────────┐
│                    TROPIC01 Secure Element                       │
└─────────────────────────────────────────────────────────────────┘
```

## Requirements

### Hardware
- TROPIC01 secure element (connected via USB, typically as `/dev/ttyACM0`)
- Supported development boards: TS1302 devkit

### Software
- CMake 3.16+
- GCC or Clang with C99 support
- Linux (tested on Ubuntu, Debian)
- Optional: `pkcs11-tool` from OpenSC for testing

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/tropicsquare/libtropic-pkcs11.git
cd libtropic-pkcs11
```

### 2. Initialize Submodules

This project depends on the `libtropic-linux` library:

```bash
git submodule update --init --recursive
```

### 3. Build

```bash
mkdir build
cd build
cmake ..
make
```

The compiled PKCS#11 module will be at: `build/liblibtropic_pkcs11.so`

### 4. Verify Build

```bash
# Check that the library was built
ls -la build/liblibtropic_pkcs11.so

# Test with pkcs11-tool
pkcs11-tool --module build/liblibtropic_pkcs11.so --show-info
```

## Quick Start

### Generate Random Numbers

The main feature of this module is generating random numbers from TROPIC01's hardware RNG:

```bash
# Generate 32 random bytes
pkcs11-tool --module ./build/liblibtropic_pkcs11.so --generate-random 32

# Save to file and view as hex
pkcs11-tool --module ./build/liblibtropic_pkcs11.so --generate-random 32 \
    --output-file /tmp/random.bin && xxd /tmp/random.bin
```

**Example Output:**
```
>>> Random bytes (32 bytes):
0x26, 0xA9, 0x1B, 0x4F, 0x17, 0xE6, 0x2D, 0x5C,
0xF0, 0x9F, 0x44, 0xEB, 0x2C, 0xF8, 0xAE, 0x15,
0x40, 0x6C, 0x14, 0xE6, 0xE7, 0xAB, 0x24, 0xEE,
0xCD, 0x87, 0x16, 0xC3, 0x01, 0x31, 0x27, 0x75
```

### List Slots

```bash
pkcs11-tool --module ./build/liblibtropic_pkcs11.so --list-slots
```

### Show Module Info

```bash
pkcs11-tool --module ./build/liblibtropic_pkcs11.so --show-info
```

## Implemented PKCS#11 Functions

| Function | Status | Description |
|----------|--------|-------------|
| `C_Initialize` | ✅ | Initialize the library |
| `C_Finalize` | ✅ | Clean up the library |
| `C_GetInfo` | ✅ | Get library info + TROPIC01 chip info |
| `C_GetFunctionList` | ✅ | Get function pointer table |
| `C_GetSlotList` | ✅ | List available slots |
| `C_GetSlotInfo` | ✅ | Get slot information |
| `C_GetTokenInfo` | ✅ | Get token information |
| `C_OpenSession` | ✅ | Open a session |
| `C_CloseSession` | ✅ | Close a session |
| `C_GenerateRandom` | ✅ | **Generate random bytes (HWRNG)** |
| `C_SeedRandom` | ✅ | No-op (HWRNG doesn't need seeding) |
| All others | ❌ | Return `CKR_FUNCTION_NOT_SUPPORTED` |

## Configuration

### USB Device Path

By default, the module communicates with TROPIC01 at `/dev/ttyACM0`. If your device is at a different path, you may need to modify `src/pkcs11.c`.

To find your device:
```bash
ls -la /dev/ttyACM*
dmesg | grep ttyACM
```

### Pairing Keys

The module uses pairing keys stored in `libtropic/keys/keys.c`. The default keys (sh0) work with standard Tropic Square development chips. For custom-provisioned chips, you may need to update these keys.

## Using with OpenSSL

### OpenSSL 3.x (Provider)

1. Install the PKCS#11 provider:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install openssl-pkcs11-provider
   ```

2. Configure OpenSSL (create or edit `openssl.cnf`):
   ```ini
   openssl_conf = openssl_init
   
   [openssl_init]
   providers = provider_sect
   
   [provider_sect]
   default = default_sect
   pkcs11 = pkcs11_sect
   
   [default_sect]
   activate = 1
   
   [pkcs11_sect]
   identity = pkcs11prov
   module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11prov.so
   module-path = /path/to/build/liblibtropic_pkcs11.so
   activate = 1
   ```

3. Generate random data:
   ```bash
   OPENSSL_CONF=./openssl.cnf openssl rand -hex 32
   ```

### Test Script

A test script is provided for OpenSSL integration:
```bash
./test_ossl.sh
```

## Project Structure

```
libtropic-pkcs11/
├── src/
│   ├── pkcs11.c          # PKCS#11 function implementations (~1100 lines, documented)
│   └── pkcs11.h          # PKCS#11 type definitions (~600 lines, documented)
├── libtropic/            # libtropic library (submodule)
│   └── keys/
│       └── keys.c        # Pairing keys for secure session
├── CMakeLists.txt        # Build configuration
├── openssl.cnf           # OpenSSL configuration example
├── test_ossl.sh          # OpenSSL test script
├── WHATWASCHANGED.md     # Detailed development documentation
└── README.md             # This file
```

## Troubleshooting

### "undefined symbol: lt_port_init"
The USB port implementation wasn't linked. Ensure `libtropic_port_unix_usb_dongle.c` is in the CMakeLists.txt sources.

### "LT_L2_HSK_ERR" (Handshake Error)
The pairing keys don't match your chip. Check:
1. Your chip batch/model
2. The keys in `libtropic/keys/keys.c`
3. Try running `lt_ex_hello_world` from libtropic-linux to verify correct keys

### "Bus error" or "SIGBUS"
This usually indicates a misaligned `CK_FUNCTION_LIST` structure. The header file must have all 68 function pointers in the correct PKCS#11 2.40 order.

### Device not found (/dev/ttyACM0)
1. Check USB connection
2. Verify device path: `ls /dev/ttyACM*`
3. Check permissions: `sudo chmod 666 /dev/ttyACM0`
4. Add user to dialout group: `sudo usermod -a -G dialout $USER`

## Documentation

For detailed technical documentation including:
- Complete code explanations
- Problems encountered and solutions
- Build configuration details
- Future improvement suggestions

See: **[WHATWASCHANGED.md](./WHATWASCHANGED.md)**

## Security Notice

⚠️ **Warning**: The default pairing keys in this repository are for **development and testing only**. They are publicly known and should NOT be used in production. For production deployments:

1. Provision your TROPIC01 chips with unique keys
2. Update `libtropic/keys/keys.c` with your private keys
3. Never commit private keys to version control

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [PKCS#11 v2.40 Specification (OASIS)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [libtropic Documentation](https://github.com/tropicsquare/libtropic)
- [TROPIC01 Product Page](https://tropicsquare.com)
- [OpenSC pkcs11-tool](https://github.com/OpenSC/OpenSC/wiki/Using-pkcs11-tool)

## Contributing

Contributions are welcome! Please read the development documentation in `WHATWASCHANGED.md` for technical details about the implementation.

## Acknowledgments

- Tropic Square s.r.o. for the TROPIC01 secure element and libtropic library
- OpenSC project for `pkcs11-tool`
- OASIS for the PKCS#11 specification

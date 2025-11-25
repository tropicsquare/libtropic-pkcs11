# libp11

Instructions for compiling, installing, and using [libp11](https://github.com/OpenSC/libp11).

Official documentation, refer to the [original README](https://github.com/OpenSC/libp11/blob/master/README.md) and [INSTALL.md](https://github.com/OpenSC/libp11/blob/master/INSTALL.md).

## Setup and Dependencies

### Required Submodule

This project requires the TropicSquare libtropic library as a dependency. Before building, you need to add it as a git submodule:

```bash
git submodule add https://github.com/tropicsquare/libtropic.git
```

If you've already cloned the repository with submodules, initialize and update them:

```bash
git submodule update --init --recursive
```

### Building the Project

After adding the submodule, you can build the project using CMake:

```bash
mkdir build
cd build
cmake ..
make
```

The compiled PKCS#11 library will be located at `build/liblibtropic_pkcs11.so`.

### Installing Prerequisites

Before using the PKCS#11 library with OpenSSL, you need to install the PKCS#11 provider:

**On Debian/Ubuntu:**

```bash
# For OpenSSL 3.x
sudo apt-get install openssl-pkcs11-provider

# Or alternatively
sudo apt-get install libengine-pkcs11-openssl
```

**On macOS:**

```bash
brew install openssl
brew install opensc
```

## Understanding PKCS#11 Provider

### What is pkcs11prov?

The **pkcs11prov** (PKCS#11 provider) is an OpenSSL 3.x provider that allows OpenSSL to use PKCS#11 modules for cryptographic operations. It replaces the older "engine" API used in OpenSSL 1.x.


### OpenSSL Configuration File

This repository includes a pre-configured `openssl.cnf` file that sets up the PKCS#11 provider. The configuration file is located in the project root and contains the following key settings:

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
# Path to the OpenSSL PKCS#11 Provider dynamic module
module = /usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11prov.so
# Path to YOUR custom PKCS#11 library
module-path = /home/ales/Documents/PKCS11/libtropic-pkcs11/build/liblibtropic_pkcs11.so
activate = 1
```

**Important**: You need to update the `module-path` in `openssl.cnf` to point to your compiled PKCS#11 library:

```bash
# Edit openssl.cnf and update this line:
module-path = /path/to/your/build/liblibtropic_pkcs11.so
```

**Architecture Notes**:
- The `module` path (pkcs11prov.so) varies by architecture:
  - ARM64/aarch64: `/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11prov.so`
  - x86_64: `/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11prov.so`
- The provided `test_ossl.sh` script automatically detects and adjusts for your architecture

### Using the Configuration File

To use the provided configuration file:

```bash
export OPENSSL_CONF=$PWD/openssl.cnf
openssl list -providers
```

Or specify it on the command line:

```bash
openssl -config ./openssl.cnf list -providers
```

## Quick Testing with the Provided Script

This repository includes a test script (`test_ossl.sh`) that automatically configures and tests your PKCS#11 library with OpenSSL.

### Running the Test Script

```bash
chmod +x test_ossl.sh
./test_ossl.sh
```

The script will:
1. Detect your system architecture (aarch64 or x86_64)
2. Check if the PKCS#11 provider is installed
3. Automatically configure the correct provider path
4. Test loading the provider
5. Generate random data using your PKCS#11 library

**Example output:**

```
=== OpenSSL PKCS#11 Provider Test ===

Architecture: aarch64
Provider path: /usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11prov.so

✓ PKCS#11 provider found

OpenSSL version:
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

Using config: /path/to/openssl.cnf

=== Listing OpenSSL Providers ===
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.2
    status: active
  pkcs11
    name: PKCS#11 Provider
    version: 0.2
    status: active

✓ PKCS#11 provider is loaded!

=== Testing Random Generation with PKCS#11 ===
Generating 16 bytes...
[random hex output]

Generating 32 bytes...
[random hex output]

=== SUCCESS! ===
Your PKCS#11 library is working with OpenSSL!
```

## Testing the Installation

### 1. Verify Provider Installation

Check if the pkcs11prov provider is available:

```bash
openssl list -providers -verbose -provider pkcs11prov
```

Expected output:
```
Providers:
  pkcs11prov
    name: libp11 PKCS#11 provider (pkcs11prov)
    version: 0.4.16
    status: active
    ...
```

### 2. Verify Engine Installation (OpenSSL 1.x)

For OpenSSL 1.x, test the engine:

```bash
openssl engine pkcs11 -t
```

Expected output:
```
(pkcs11) pkcs11 engine
     [ available ]
```

### 3. Test Basic Functionality

A simple test that works without a token is generating random data:

```bash
# Using the provider (OpenSSL 3.x)
openssl rand -provider pkcs11prov -hex 32
```

**Note**: This command uses the PKCS#11 module's random number generator if available, but will fall back to OpenSSL's default RNG if no token is present.

## Basic Usage Examples

### Example 1: Generate Random Data

```bash
# Generate 64 random bytes in hexadecimal format
openssl rand -engine pkcs11 -hex 64

# Or with provider (OpenSSL 3.x)
openssl rand -provider pkcs11prov -hex 64
```

### Example 2: List Available Providers

```bash
openssl list -providers -verbose -provider pkcs11prov
```

### Example 3: Check OpenSSL Version and Modules

```bash
# Check OpenSSL version
openssl version -a

# List providers (OpenSSL 3.x)
openssl list -providers
```

## Using pkcs11-tool

The `pkcs11-tool` utility (part of OpenSC) provides a command-line interface for interacting with PKCS#11 modules directly. This is useful for testing and debugging your PKCS#11 library.

### Installation

```bash
# On Debian/Ubuntu
sudo apt-get install opensc

# On macOS
brew install opensc
```

### Example 1: List Available Slots

Use the `-L` flag to list all available slots in the PKCS#11 module:

```bash
pkcs11-tool --module /path/to/your/libpkcs11.so -L
```

**Example output:**

```
>>> LIBRARY CONSTRUCTOR CALLED - Installing segfault handler
========================================
>>> C_GetFunctionList (ppFunctionList=0xffffc8eb2cc0)
>>> LOADING TROPIC PKCS#11 LIBRARY
========================================
>>> C_GetFunctionList OK (function list returned at 0xf4939da00058)
>>> Function pointers: C_Initialize=0xf4939d9e100c, C_Finalize=0xf4939d9e10c0, C_GetInfo=0xf4939d9e11dc
>>> Function pointers: C_CloseSession=0xf4939d9e17fc, C_CloseAllSessions=0xf4939d9e1b04
>>> C_Initialize (pInitArgs=(nil))
>>> C_Initialize OK
>>> C_GetSlotList (tokenPresent=0, pSlotList=(nil), pulCount=0xb80a8f473700)
>>> Query mode: returning count=1
>>> C_GetSlotList OK (count=1)
>>> C_GetSlotList (tokenPresent=0, pSlotList=0xb80ac1e73390, pulCount=0xb80a8f473700)
>>> Filled slot list: slotID=1
>>> C_GetSlotList OK (count=1)
Available slots:
Slot 0 (0x1): >>> C_GetSlotInfo (slotID=1, pInfo=0xffffc8eb2ae0)
>>> C_GetSlotInfo OK (description='Tropic Slot', flags=0x5)
Tropic Slot
>>> C_GetTokenInfo (slotID=1, pInfo=0xffffc8eb29d0)
>>> C_GetTokenInfo OK (label='TROPIC-RNG', flags=0x8)
  token state:   uninitialized
>>> C_Finalize ENTRY (pReserved=(nil))
>>> C_Finalize (pReserved=(nil))
>>> C_Finalize OK
>>> C_Finalize DONE
```

### Example 2: List Tokens

Use the `-T` flag to list all tokens with detailed information:

```bash
pkcs11-tool --module /path/to/your/libpkcs11.so -T
```

**Example output:**

```
>>> LIBRARY CONSTRUCTOR CALLED - Installing segfault handler
========================================
>>> C_GetFunctionList (ppFunctionList=0xffffdd0e88c0)
>>> LOADING TROPIC PKCS#11 LIBRARY
========================================
>>> C_GetFunctionList OK (function list returned at 0xeabab0160058)
>>> Function pointers: C_Initialize=0xeabab014100c, C_Finalize=0xeabab01410c0, C_GetInfo=0xeabab01411dc
>>> Function pointers: C_CloseSession=0xeabab01417fc, C_CloseAllSessions=0xeabab0141b04
>>> C_Initialize (pInitArgs=(nil))
>>> C_Initialize OK
>>> C_GetSlotList (tokenPresent=1, pSlotList=(nil), pulCount=0xb994afe93700)
>>> Query mode: returning count=1
>>> C_GetSlotList OK (count=1)
>>> C_GetSlotList (tokenPresent=1, pSlotList=0xb994dfd9a390, pulCount=0xb994afe93700)
>>> Filled slot list: slotID=1
>>> C_GetSlotList OK (count=1)
Available slots:
Slot 0 (0x1): >>> C_GetSlotInfo (slotID=1, pInfo=0xffffdd0e86e0)
>>> C_GetSlotInfo OK (description='Tropic Slot', flags=0x5)
Tropic Slot
>>> C_GetTokenInfo (slotID=1, pInfo=0xffffdd0e85d0)
>>> C_GetTokenInfo OK (label='TROPIC-RNG', flags=0x8)
  token state:   uninitialized
>>> C_Finalize ENTRY (pReserved=(nil))
>>> C_Finalize (pReserved=(nil))
>>> C_Finalize OK
>>> C_Finalize DONE
```

### Example 3: Generate Random Data

Generate random data using the PKCS#11 module's RNG:

```bash
# Generate 16 bytes of random data
pkcs11-tool --module /path/to/your/libpkcs11.so --generate-random 16

# Generate 32 bytes of random data in hex format
pkcs11-tool --module /path/to/your/libpkcs11.so --generate-random 32 | xxd -p
```

### Example 4: Get Module Information

Display information about the PKCS#11 module:

```bash
pkcs11-tool --module /path/to/your/libpkcs11.so --show-info
```

### Common pkcs11-tool Options

| Option | Description |
|--------|-------------|
| `-L` or `--list-slots` | List available slots |
| `-T` or `--list-token-slots` | List slots with tokens |
| `-I` or `--show-info` | Show general token information |
| `-M` or `--list-mechanisms` | List supported mechanisms |
| `--generate-random N` | Generate N bytes of random data |
| `-O` or `--list-objects` | List objects on the token |
| `--slot N` | Specify slot number to use |

### Notes

- The verbose output shown in the examples above is from the debug logging in the PKCS#11 library
- Replace `/path/to/your/libpkcs11.so` with the actual path to your PKCS#11 module
- For this repository, after building, use the library at:
  ```bash
  pkcs11-tool --module ./build/liblibtropic_pkcs11.so -L
  ```
- Make sure to build the project first (see "Building the Project" section above)



- OpenSSL 1.x uses engines
- OpenSSL 3.x uses providers

## Resources

- **Official Repository**: https://github.com/OpenSC/libp11
- **Original README**: https://github.com/OpenSC/libp11/blob/master/README.md
- **Official INSTALL.md**: https://github.com/OpenSC/libp11/blob/master/INSTALL.md
- **Release Tarballs**: https://github.com/OpenSC/libp11/releases


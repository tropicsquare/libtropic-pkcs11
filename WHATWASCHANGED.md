# PKCS#11 TROPIC01 Hardware RNG Integration - Detailed Technical Documentation

## Project Goal

Create a PKCS#11 compliant shared library (`liblibtropic_pkcs11.so`) that exposes the TROPIC01 secure element's hardware random number generator (HWRNG) through the standard cryptographic token interface. This allows any PKCS#11-compatible application (like `pkcs11-tool`, OpenSSL, etc.) to use the TROPIC01 chip for cryptographically secure random number generation.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Files Modified](#files-modified)
3. [Code Documentation](#code-documentation)
4. [Detailed Changes](#detailed-changes)
5. [Problems Encountered and Solutions](#problems-encountered-and-solutions)
6. [Build Configuration](#build-configuration)
7. [Usage Examples](#usage-examples)
8. [Technical Notes](#technical-notes)
9. [Example Output](#example-output---successful-random-generation)
10. [Future Improvements](#future-improvements-and-cleanup-suggestions)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│                  (pkcs11-tool, OpenSSL, etc.)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ PKCS#11 API (C_GenerateRandom, etc.)
┌─────────────────────────────────────────────────────────────────┐
│                   liblibtropic_pkcs11.so                        │
│                      (Our PKCS#11 Module)                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ pkcs11.c - PKCS#11 function implementations             │   │
│  │ pkcs11.h - PKCS#11 type definitions & function list     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ libtropic API
┌─────────────────────────────────────────────────────────────────┐
│                        libtropic                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │ lt_init()       │  │ lt_random_      │  │ lt_verify_     │  │
│  │ lt_deinit()     │  │ value_get()     │  │ chip_and_start │  │
│  │ lt_get_info_*() │  │                 │  │ _secure_session│  │
│  └─────────────────┘  └─────────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ USB Serial Communication
┌─────────────────────────────────────────────────────────────────┐
│              libtropic_port_unix_usb_dongle.c                   │
│                    /dev/ttyACM0 @ 115200 baud                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    TROPIC01 Secure Element                       │
│                    (Hardware RNG, Crypto Engine)                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Files Modified

| File | Purpose | Changes |
|------|---------|---------|
| `src/pkcs11.h` | PKCS#11 type definitions | Fixed `CK_FUNCTION_LIST` structure to be PKCS#11 2.40 compliant. **Extensively documented (~600 lines) with explanations of every type, structure, constant, and function slot.** |
| `src/pkcs11.c` | PKCS#11 function implementations | Implemented `C_GetInfo`, `C_GenerateRandom` with libtropic integration. **Extensively documented with ~1100 lines including comprehensive comments.** |
| `libtropic/keys/keys.c` | Pairing key storage | Added sh0 keys for chip batch TR01-C2P-T101. **Added detailed documentation (~160 lines).** |
| `CMakeLists.txt` | Build configuration | Added `-fPIC`, source files, and include paths |

---

## Code Documentation

All source files have been extensively documented with comments suitable for developers who are new to PKCS#11 or the TROPIC01 chip.

### `src/pkcs11.h` Documentation Includes:

1. **File Header** (~60 lines)
   - What PKCS#11 (Cryptoki) is
   - Common PKCS#11 tokens (HSMs, smart cards, secure elements)
   - What the API allows applications to do
   - How PKCS#11 modules work (5-step process)
   - Why CK_FUNCTION_LIST order is critical
   - Reference to OASIS specification

2. **Basic Type Definitions Section**
   - Why PKCS#11 defines its own types
   - Each type documented with purpose and usage:
     - `CK_BYTE`, `CK_CHAR`, `CK_UTF8CHAR` - byte types
     - `CK_BBOOL` - boolean type
     - `CK_ULONG`, `CK_LONG` - integer types
     - `CK_FLAGS`, `CK_RV` - flags and return values
     - `CK_SLOT_ID`, `CK_SESSION_HANDLE`, `CK_OBJECT_HANDLE` - handles

3. **Object Classes and Key Types**
   - `CKO_*` constants explained
   - `CKK_*` key type constants

4. **Return Values (CK_RV)**
   - All error codes documented with meanings
   - Explanation of error code numbering scheme

5. **Mechanism and Attribute Constants**
   - `CKM_*` mechanism types
   - `CKA_*` attribute types
   - Session and token flags

6. **Structure Definitions**
   - `CK_VERSION` - version numbers
   - `CK_INFO` - library information
   - `CK_SLOT_INFO` - slot (reader) information
   - `CK_TOKEN_INFO` - token information (all 18 fields documented)
   - `CK_SESSION_INFO` - session state
   - `CK_ATTRIBUTE` - attribute type/value pairs
   - `CK_MECHANISM` - cryptographic mechanism specification

7. **CK_FUNCTION_LIST Documentation** (~250 lines)
   - Why this is the most important structure
   - Critical requirements for function order
   - Why order matters (offset calculation)
   - Function categories breakdown
   - Every single function slot (0-67) documented with:
     - Slot number
     - Purpose
     - Brief description
   - Special notes for:
     - Slots 63-64: Random number generation (our main feature)
     - Slots 65-67: Deprecated parallel functions

### `src/pkcs11.c` Documentation Includes:

1. **File Header** (~50 lines)
   - Explanation of what PKCS#11 is
   - How PKCS#11 modules work
   - What this specific module does
   - Architecture overview

2. **Include Section**
   - Purpose of each header file
   - Why libtropic headers are needed

3. **Debug Macro Documentation**
   - How the LOG() macro works
   - The do-while(0) idiom explanation

4. **Signal Handler Documentation**
   - What SIGSEGV and SIGBUS are
   - Why handlers were added (debugging)
   - Warning about removing for production

5. **Every Function Documented**
   - Purpose and behavior
   - All parameters explained
   - Return values listed
   - Step-by-step implementation breakdown
   - PKCS#11 spec references
   - TODO notes for improvements

6. **C_GenerateRandom() Deep Documentation** (~150 lines of comments)
   - 8-step breakdown of the process
   - Explanation of secure session establishment
   - Why hardware RNG is superior
   - X25519 key exchange explanation
   - AES-GCM channel setup
   - Maximum chunk size handling

7. **Function List Documentation**
   - Purpose of CK_FUNCTION_LIST
   - Why designated initializers are used
   - Comments for each function category
   - Explanation of NULL vs implemented functions

### `libtropic/keys/keys.c` Documentation Includes:

1. **File Header** (~60 lines)
   - What pairing keys are
   - How secure sessions work
   - Key format explanation (X25519)
   - Key provisioning process
   - Security warning about factory keys

2. **Each Key Slot Documented**
   - SH0: Full access, prod_C2S_T200 batch
   - SH1: Attestation key write access
   - SH2: Serial number read access
   - SH3: Application use
   - Source of keys (where they came from)

---

## Detailed Changes

### File: `src/pkcs11.h`

#### Problem
The original `CK_FUNCTION_LIST` structure was incomplete. It was missing 10 function pointers required by the PKCS#11 v2.40 specification. When `pkcs11-tool` loaded our library, it expected function pointers at specific offsets in the structure. Because our structure was shorter, `pkcs11-tool` would read garbage memory when trying to call functions, causing "Bus error (SIGBUS)" crashes.

#### What is `CK_FUNCTION_LIST`?
`CK_FUNCTION_LIST` is the central structure in PKCS#11. It contains pointers to ALL cryptographic functions the module supports. When an application loads a PKCS#11 module, it calls `C_GetFunctionList()` to get this structure, then uses the function pointers to call specific operations.

#### Original (Broken) Structure
The original structure was missing these functions (in order):
1. `C_SetPIN` - Should be between `C_InitPIN` and `C_OpenSession`
2. `C_CopyObject` - Should be between `C_CreateObject` and `C_DestroyObject`
3. `C_GetObjectSize` - Should be between `C_DestroyObject` and `C_GetAttributeValue`
4. `C_DigestEncryptUpdate` - Dual-function crypto operation
5. `C_DecryptDigestUpdate` - Dual-function crypto operation
6. `C_SignEncryptUpdate` - Dual-function crypto operation
7. `C_DecryptVerifyUpdate` - Dual-function crypto operation
8. `C_GenerateKey` - Should be before `C_GenerateKeyPair`
9. `C_GetFunctionStatus` - Legacy parallel function management
10. `C_CancelFunction` - Legacy parallel function management
11. `C_WaitForSlotEvent` - Slot event notification

Additionally, `C_SeedRandom` and `C_GenerateRandom` were in the **wrong order**.

#### Fixed Structure (Excerpt)
```c
struct CK_FUNCTION_LIST {
    CK_VERSION version;
    /* Slot and token management */
    CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
    CK_RV (*C_GetInfo)(CK_INFO_PTR pInfo);
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV (*C_GetSlotList)(...);
    CK_RV (*C_GetSlotInfo)(...);
    CK_RV (*C_GetTokenInfo)(...);
    CK_RV (*C_GetMechanismList)(...);
    CK_RV (*C_GetMechanismInfo)(...);
    CK_RV (*C_InitToken)(...);
    CK_RV (*C_InitPIN)(...);
    CK_RV (*C_SetPIN)(...);                    // <-- WAS MISSING
    /* Session management */
    CK_RV (*C_OpenSession)(...);
    CK_RV (*C_CloseSession)(...);
    // ... more functions ...
    /* Object management */
    CK_RV (*C_CreateObject)(...);
    CK_RV (*C_CopyObject)(...);                // <-- WAS MISSING
    CK_RV (*C_DestroyObject)(...);
    CK_RV (*C_GetObjectSize)(...);             // <-- WAS MISSING
    // ... more functions ...
    /* Dual-function cryptographic operations */
    CK_RV (*C_DigestEncryptUpdate)(...);       // <-- WAS MISSING
    CK_RV (*C_DecryptDigestUpdate)(...);       // <-- WAS MISSING
    CK_RV (*C_SignEncryptUpdate)(...);         // <-- WAS MISSING
    CK_RV (*C_DecryptVerifyUpdate)(...);       // <-- WAS MISSING
    /* Key management */
    CK_RV (*C_GenerateKey)(...);               // <-- WAS MISSING
    CK_RV (*C_GenerateKeyPair)(...);
    CK_RV (*C_WrapKey)(...);
    CK_RV (*C_UnwrapKey)(...);
    CK_RV (*C_DeriveKey)(...);
    /* Random number generation - ORDER WAS WRONG */
    CK_RV (*C_SeedRandom)(...);                // <-- WAS AFTER C_GenerateRandom
    CK_RV (*C_GenerateRandom)(...);            // <-- WAS BEFORE C_SeedRandom
    /* Parallel function management (deprecated) */
    CK_RV (*C_GetFunctionStatus)(...);         // <-- WAS MISSING
    CK_RV (*C_CancelFunction)(...);            // <-- WAS MISSING
    CK_RV (*C_WaitForSlotEvent)(...);          // <-- WAS MISSING
};
```

---

### File: `src/pkcs11.c`

#### Added Includes

```c
#include "libtropic.h"                        // Main libtropic API
#include "libtropic_common.h"                 // Common types and constants
#include "libtropic_examples.h"               // Example utilities
#include "libtropic_logging.h"                // Logging macros
#include "libtropic_port.h"                   // Hardware abstraction layer
#include "libtropic_port_unix_usb_dongle.h"   // Unix USB dongle implementation
```

**Why these includes?**
- `libtropic.h` - Provides `lt_init()`, `lt_deinit()`, `lt_random_value_get()`, etc.
- `libtropic_port_unix_usb_dongle.h` - Provides `lt_dev_unix_usb_dongle_t` structure for USB communication configuration

#### External Key Declarations

```c
extern uint8_t sh0priv[];
extern uint8_t sh0pub[];
```

**Why?**
The sh0 keys are defined in `libtropic/keys/keys.c` and linked into our shared library. We declare them as `extern` to use them in `pkcs11.c` for establishing secure sessions with the TROPIC01 chip.

---

#### Function: `C_GetInfo()`

**Purpose:** Returns information about the PKCS#11 library. We extended it to also read and display TROPIC01 chip information.

**Implementation Details:**

```c
CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    LOG(">>> C_GetInfo (pInfo=%p)", pInfo);
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }

    // Step 1: Set up USB device configuration
    lt_handle_t h = {0};                      // libtropic handle structure
    lt_dev_unix_usb_dongle_t device = {0};    // USB dongle configuration
    
    strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
    device.baud_rate = 115200;                // TROPIC01 communicates at 115200 baud
    device.rng_seed = (unsigned int)time(NULL); // Seed for software RNG fallback
    
    h.l2.device = &device;                    // Attach device config to handle

    // Step 2: Initialize communication with TROPIC01
    lt_ret_t ret = lt_init(&h);
    if (ret == LT_OK) {
        LOG(">>> TROPIC01 initialized successfully");
        
        // Step 3: Read RISC-V firmware version
        // The TROPIC01 has a RISC-V processor running application firmware
        uint8_t fw_ver[4] = {0};
        ret = lt_get_info_riscv_fw_ver(&h, fw_ver);
        if (ret == LT_OK) {
            LOG(">>> RISC-V FW version: %d.%d.%d.%d", 
                fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
        }
        
        // Step 4: Read SPECT firmware version
        // SPECT is the cryptographic coprocessor inside TROPIC01
        ret = lt_get_info_spect_fw_ver(&h, fw_ver);
        if (ret == LT_OK) {
            LOG(">>> SPECT FW version: %d.%d.%d.%d", 
                fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
        }
        
        // Step 5: Read and print chip ID
        // Contains serial number, batch ID, part number, etc.
        struct lt_chip_id_t chip_id = {0};
        ret = lt_get_info_chip_id(&h, &chip_id);
        if (ret == LT_OK) {
            LOG(">>> Chip ID:");
            lt_print_chip_id(&chip_id, printf);  // Pretty-prints all chip info
        }
        
        // Step 6: Clean up
        lt_deinit(&h);
    } else {
        LOG(">>> TROPIC01 init failed: %s", lt_ret_verbose(ret));
    }

    // Step 7: Fill in PKCS#11 library info (required by spec)
    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char*)pInfo->libraryDescription, "Tropic PKCS11", 32);
    
    return CKR_OK;
}
```

**Key Points:**
- Reading chip info does NOT require a secure session
- `lt_init()` establishes L1/L2 communication layers
- `lt_get_info_*()` functions work without authentication
- `lt_print_chip_id()` outputs detailed chip information including serial number, batch ID, firmware versions, etc.

---

#### Function: `C_GenerateRandom()`

**Purpose:** Generate cryptographically secure random bytes using TROPIC01's hardware RNG.

**Why Hardware RNG?**
Software random number generators (PRNGs) derive randomness from deterministic algorithms seeded with entropy. Hardware RNGs use physical phenomena (thermal noise, quantum effects) to generate true random numbers, making them superior for cryptographic applications.

**Implementation Details:**

```c
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    LOG(">>> C_GenerateRandom (hSession=0x%lx, pRandomData=%p, ulRandomLen=%lu)", 
        hSession, pRandomData, ulRandomLen);
    
    // Step 1: Validate parameters
    if (!pRandomData) {
        LOG(">>> pRandomData is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if (ulRandomLen == 0) {
        LOG(">>> ulRandomLen is 0 - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    // Step 2: Set up USB device configuration
    lt_handle_t h = {0};
    lt_dev_unix_usb_dongle_t device = {0};
    
    strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
    device.baud_rate = 115200;
    device.rng_seed = (unsigned int)time(NULL);
    
    h.l2.device = &device;

    // Step 3: Initialize communication
    LOG(">>> Initializing handle");
    lt_ret_t ret = lt_init(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to initialize handle: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    
    // Step 4: Establish secure session
    // IMPORTANT: Random number generation REQUIRES a secure session!
    // The secure session uses X25519 key exchange + AES-GCM encryption
    // to create an authenticated, encrypted channel to the chip.
    LOG(">>> Starting Secure Session with key %d", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    ret = lt_verify_chip_and_start_secure_session(
        &h, 
        sh0priv,                          // Our private key (32 bytes)
        sh0pub,                           // Chip's public key (32 bytes)
        TR01_PAIRING_KEY_SLOT_INDEX_0     // Key slot 0
    );
    if (ret != LT_OK) {
        LOG(">>> Failed to start Secure Session: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    LOG(">>> Secure session established");
    
    // Step 5: Get random bytes from hardware RNG
    // TROPIC01 can return max 255 bytes per request (TR01_RANDOM_VALUE_GET_LEN_MAX)
    // For larger requests, we loop and accumulate chunks
    CK_ULONG remaining = ulRandomLen;
    CK_BYTE_PTR ptr = pRandomData;
    
    while (remaining > 0) {
        uint16_t chunk_size = (remaining > TR01_RANDOM_VALUE_GET_LEN_MAX) ? 
                              TR01_RANDOM_VALUE_GET_LEN_MAX : (uint16_t)remaining;
        
        ret = lt_random_value_get(&h, ptr, chunk_size);
        if (ret != LT_OK) {
            LOG(">>> Failed to get random bytes: %s", lt_ret_verbose(ret));
            lt_session_abort(&h);
            lt_deinit(&h);
            return CKR_GENERAL_ERROR;
        }
        
        ptr += chunk_size;
        remaining -= chunk_size;
    }
    
    // Step 6: Clean up secure session
    LOG(">>> Aborting Secure Session");
    ret = lt_session_abort(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to abort Secure Session: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    
    // Step 7: Deinitialize handle
    LOG(">>> Deinitializing handle");
    ret = lt_deinit(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to deinitialize handle: %s", lt_ret_verbose(ret));
        return CKR_GENERAL_ERROR;
    }
    
    // Step 8: Print random bytes in hex format for debugging
    printf(">>> Random bytes (%lu bytes):\n", ulRandomLen);
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        printf("0x%02X", pRandomData[i]);
        if (i < ulRandomLen - 1) printf(", ");
        if ((i + 1) % 8 == 0) printf("\n");
    }
    if (ulRandomLen % 8 != 0) printf("\n");
    fflush(stdout);
    
    LOG(">>> C_GenerateRandom OK (generated %lu bytes from TROPIC01 hardware RNG)", ulRandomLen);
    return CKR_OK;
}
```

**Key Points:**
- `lt_random_value_get()` REQUIRES an established secure session
- Maximum chunk size is 255 bytes (`TR01_RANDOM_VALUE_GET_LEN_MAX`)
- We must call `lt_session_abort()` before `lt_deinit()` to properly close the session
- Each call to `C_GenerateRandom` establishes a new secure session (could be optimized)

---

#### Function List Initialization

**Purpose:** Provide `pkcs11-tool` and other applications with pointers to all supported functions.

```c
static CK_FUNCTION_LIST functionList = {
    .version = {2, 40},
    /* Slot and token management */
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = NULL,               // Not implemented
    .C_GetMechanismInfo = NULL,               // Not implemented
    .C_InitToken = NULL,                      // Not implemented
    .C_InitPIN = NULL,                        // Not implemented
    .C_SetPIN = NULL,                         // Not implemented (WAS MISSING!)
    /* Session management */
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = NULL,               // Not implemented
    // ... all other functions set to NULL or implemented ...
    /* Random number generation - CORRECT ORDER */
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,     // Our main implementation!
    /* Parallel function management (deprecated) - WERE MISSING */
    .C_GetFunctionStatus = NULL,
    .C_CancelFunction = NULL,
    .C_WaitForSlotEvent = NULL,
};
```

**Why designated initializers (`.member = value`)?**
Using designated initializers ensures:
1. Fields are set in the correct struct positions regardless of source code order
2. Unspecified fields are automatically initialized to zero/NULL
3. Code is more readable and maintainable

---

### File: `libtropic/keys/keys.c`

#### Problem
The file originally only contained sh1, sh2, and sh3 keys. These are default factory keys for "engineering samples 01". However, the chip being used (TR01-C2P-T101, batch prod_C2S_T200) required different sh0 keys.

#### How We Found the Correct Keys
1. Ran `lt_ex_hello_world` from libtropic-linux - it worked with key slot 0
2. Found generated keys: `find ~/Documents/PKCS11/libtropic-pkcs11/libtropic-linux -name "*sh0*" -type f`
3. Located: `/home/ales/.../TS1302_devkit/build/sh0_keys.c`
4. Copied the key values to our `keys.c`

#### Added Keys
```c
// SH0 keys (prod_C2S_T200 batch)
uint8_t sh0priv[] = {
    0x28, 0x3f, 0x5a, 0x0f, 0xfc, 0x41, 0xcf, 0x50, 
    0x98, 0xa8, 0xe1, 0x7d, 0xb6, 0x37, 0x2c, 0x3c,
    0xaa, 0xd1, 0xee, 0xee, 0xdf, 0x0f, 0x75, 0xbc, 
    0x3f, 0xbf, 0xcd, 0x9c, 0xab, 0x3d, 0xe9, 0x72
};
uint8_t sh0pub[] = {
    0xf9, 0x75, 0xeb, 0x3c, 0x2f, 0xd7, 0x90, 0xc9, 
    0x6f, 0x29, 0x4f, 0x15, 0x57, 0xa5, 0x03, 0x17,
    0x80, 0xc9, 0xaa, 0xfa, 0x14, 0x0d, 0xa2, 0x8f, 
    0x55, 0xe7, 0x51, 0x57, 0x37, 0xb2, 0x50, 0x2c
};
```

**What are these keys?**
- `sh0priv` - Our X25519 private key (32 bytes)
- `sh0pub` - The chip's corresponding public key (32 bytes)
- Together they enable Diffie-Hellman key exchange for secure session establishment

---

### File: `CMakeLists.txt`

#### Change 1: Position Independent Code

```cmake
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
```

**Why?**
When creating a shared library (`.so`), all code must be position-independent so it can be loaded at any memory address. The static libraries `libtropic.a` and `libtrezor_crypto.a` were compiled without `-fPIC`, causing linker errors:
```
relocation R_AARCH64_ADR_PREL_PG_HI21 against symbol ... can not be used when making a shared object; recompile with -fPIC
```

Setting `CMAKE_POSITION_INDEPENDENT_CODE ON` before `add_subdirectory()` ensures all targets (including libtropic and trezor_crypto) are compiled with `-fPIC`.

#### Change 2: Additional Source Files

```cmake
add_library(libtropic_pkcs11 SHARED
    src/pkcs11.h
    src/pkcs11.c
    ${PATH_LIBTROPIC}/hal/port/unix/libtropic_port_unix_usb_dongle.c  # Added
    ${PATH_LIBTROPIC}/keys/keys.c                                      # Added
)
```

**Why `libtropic_port_unix_usb_dongle.c`?**
This file implements `lt_port_init()`, `lt_port_deinit()`, and other hardware abstraction functions for Unix USB communication. Without it, we get:
```
undefined symbol: lt_port_init
```

**Why `keys.c`?**
Contains the sh0/sh1/sh2/sh3 pairing keys needed for secure session establishment.

#### Change 3: Include Directory

```cmake
target_include_directories(libtropic_pkcs11 PRIVATE 
    ${PATH_LIBTROPIC}/hal/port/unix
)
```

**Why?**
The header `libtropic_port_unix_usb_dongle.h` is located in this directory. Without this include path:
```
fatal error: libtropic_port_unix_usb_dongle.h: No such file or directory
```

---

## Problems Encountered and Solutions

### Problem 1: Bus Error (SIGBUS) on ARM64

**Symptom:**
```
Bus error (core dumped)
```
Occurred after `C_CloseSession` when running `pkcs11-tool --generate-random`.

**Root Cause:**
`CK_FUNCTION_LIST` structure in `pkcs11.h` was missing 10 function pointers. `pkcs11-tool` expected functions at specific offsets. When it tried to call a function that was at a different offset (or beyond our struct), it read invalid memory.

**Solution:**
Added all missing function pointers in the correct PKCS#11 2.40 order. Used designated initializers to ensure correct struct layout.

---

### Problem 2: `-fPIC` Linker Errors

**Symptom:**
```
relocation R_AARCH64_ADR_PREL_PG_HI21 against symbol `cfg_desc_table' which may bind externally can not be used when making a shared object; recompile with -fPIC
```

**Root Cause:**
Static libraries (`libtropic.a`, `libtrezor_crypto.a`) were compiled without Position Independent Code, but we were trying to link them into a shared library.

**Solution:**
Added `set(CMAKE_POSITION_INDEPENDENT_CODE ON)` BEFORE `add_subdirectory(libtropic)` and performed a clean rebuild:
```bash
rm -rf build/*
cd build
cmake ..
make
```

---

### Problem 3: `undefined symbol: lt_port_init`

**Symptom:**
```
sc_dlopen failed: .../liblibtropic_pkcs11.so: undefined symbol: lt_port_init
```

**Root Cause:**
The USB port implementation (`libtropic_port_unix_usb_dongle.c`) was not being compiled into our shared library.

**Solution:**
Added the source file to our `add_library()` command in CMakeLists.txt.

---

### Problem 4: `LT_FAIL` on Initialization

**Symptom:**
```
>>> TROPIC01 init failed: LT_FAIL
```

**Root Cause:**
The `lt_dev_unix_usb_dongle_t` structure was not configured with device path and baud rate.

**Solution:**
```c
strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
device.baud_rate = 115200;
device.rng_seed = (unsigned int)time(NULL);
```

---

### Problem 5: `LT_L2_HSK_ERR` (Handshake Error)

**Symptom:**
```
>>> Failed to start Secure Session: LT_L2_HSK_ERR
```

**Root Cause:**
The pairing keys in `keys.c` (sh1, sh2, sh3 for "engineering samples 01") did not match the keys provisioned on the chip (batch TR01-C2P-T101).

**Investigation:**
1. Verified chip info showed: P/N = TR01-C2P-T101, Batch = prod_C2S_T200
2. Tested `lt_ex_hello_world` from libtropic-linux - it worked with key slot 0
3. Found generated sh0 keys in libtropic-linux build directory

**Solution:**
Copied the correct sh0 keys from `libtropic-linux/TS1302_devkit/build/sh0_keys.c` to our `keys.c`.

---

### Problem 6: `undefined symbol: sh0priv`

**Symptom:**
```
sc_dlopen failed: .../liblibtropic_pkcs11.so: undefined symbol: sh0priv
```

**Root Cause:**
Initially tried using `sh0priv`/`sh0pub` from libtropic headers, but they weren't defined anywhere (generated at build time from PEM files).

**Solution:**
Added sh0 key definitions directly to `libtropic/keys/keys.c` and declared them as `extern` in `pkcs11.c`.

---

## Build Configuration

### Complete CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.31.6)
project(libtropic_pkcs11)

# CRITICAL: Must be set BEFORE add_subdirectory()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Path to libtropic
set(PATH_LIBTROPIC ${CMAKE_CURRENT_SOURCE_DIR}/libtropic-linux/libtropic/)

# Cryptography provider
set(LT_CRYPTO "trezor_crypto")

# Our PKCS#11 shared library
add_library(libtropic_pkcs11 SHARED
    src/pkcs11.h
    src/pkcs11.c
    ${PATH_LIBTROPIC}/hal/port/unix/libtropic_port_unix_usb_dongle.c
    ${PATH_LIBTROPIC}/keys/keys.c
)

# Add libtropic as subdirectory
add_subdirectory(${PATH_LIBTROPIC} "libtropic")

# Include paths
target_include_directories(libtropic_pkcs11 PRIVATE 
    ${PATH_LIBTROPIC}/hal/port/unix
)

# Link with libtropic
target_link_libraries(libtropic_pkcs11 PRIVATE tropic)
```

### Build Commands

```bash
# Initial build
mkdir build
cd build
cmake ..
make

# Clean rebuild (required after CMakeLists.txt changes)
rm -rf build/*
cd build
cmake ..
make
```

---

## Usage Examples

### Generate Random Bytes

```bash
# Generate 32 random bytes, save to file
pkcs11-tool --module /path/to/liblibtropic_pkcs11.so --generate-random 32 --output-file /tmp/random.bin

# View the random bytes
xxd /tmp/random.bin
```

### Show Library and Chip Info

```bash
pkcs11-tool --module /path/to/liblibtropic_pkcs11.so --show-info
```

### List Slots

```bash
pkcs11-tool --module /path/to/liblibtropic_pkcs11.so --list-slots
```

---

## Technical Notes

### Secure Session Lifecycle

```
lt_init()
    │
    ▼
lt_verify_chip_and_start_secure_session()
    │   - X25519 key exchange
    │   - Session key derivation
    │   - AES-GCM encrypted channel established
    ▼
lt_random_value_get() ← Can be called multiple times
    │
    ▼
lt_session_abort()
    │   - Session terminated
    │   - Keys wiped
    ▼
lt_deinit()
    │   - Communication closed
    ▼
Done
```

### Key Slots

TROPIC01 has 4 pairing key slots (SH0-SH3):
- **SH0**: Factory default, full access
- **SH1**: Attestation key write access
- **SH2**: Serial number read access
- **SH3**: Application use

Different chip batches have different keys. The keys are provisioned during manufacturing and must match for secure session establishment.

### Maximum Random Bytes Per Request

`TR01_RANDOM_VALUE_GET_LEN_MAX = 255 bytes`

For larger requests, our implementation loops and accumulates chunks.

### USB Device Path

Default: `/dev/ttyACM0`

This may vary depending on:
- Number of USB devices connected
- Order of device connection
- Linux distribution

To find the correct device:
```bash
ls -la /dev/ttyACM*
dmesg | grep ttyACM
```

---

## Implemented PKCS#11 Functions Summary

| Function | Implementation | Notes |
|----------|----------------|-------|
| `C_Initialize` | ✅ Full | Sets initialized flag |
| `C_Finalize` | ✅ Full | Clears initialized flag |
| `C_GetInfo` | ✅ Extended | Returns lib info + reads TROPIC01 chip info |
| `C_GetFunctionList` | ✅ Full | Returns function pointer table |
| `C_GetSlotList` | ✅ Full | Returns slot ID 1 |
| `C_GetSlotInfo` | ✅ Full | Returns "Tropic Slot" info |
| `C_GetTokenInfo` | ✅ Full | Returns "TROPIC-RNG" token |
| `C_OpenSession` | ✅ Basic | Returns fixed session handle |
| `C_CloseSession` | ✅ Basic | Always succeeds |
| `C_GenerateRandom` | ✅ Full | **Main feature - TROPIC01 HWRNG** |
| `C_SeedRandom` | ✅ Stub | No-op (HWRNG doesn't need seeding) |
| All other functions | ❌ NULL | Return CKR_FUNCTION_NOT_SUPPORTED |

---

## Example Output - Successful Random Generation

Below are two consecutive runs showing the TROPIC01 hardware RNG generating different random values each time:

### Run 1:
```
$ pkcs11-tool --module /home/ales/Documents/PKCS11/libtropic-pkcs11/build/liblibtropic_pkcs11.so --generate-random 32 --output-file /tmp/random.bin && xxd /tmp/random.bin

>>> LIBRARY CONSTRUCTOR CALLED - Installing signal handlers
========================================
>>> C_GetFunctionList (ppFunctionList=0xffffcb038170)
>>> LOADING TROPIC PKCS#11 LIBRARY
========================================
>>> C_GetFunctionList OK (function list returned at 0xe840aeb40b78)
>>> Function pointers: C_Initialize=0xe840aeabab0c, C_Finalize=0xe840aeababc0, C_GetInfo=0xe840aeabacdc
>>> Function pointers: C_OpenSession=0xe840aeabb568, C_CloseSession=0xe840aeabb698, C_CloseAllSessions=(nil)
>>> Actual function: C_OpenSession=0xe840aeabb568
>>> C_Initialize (pInitArgs=(nil))
>>> C_Initialize OK
>>> C_GetSlotList (tokenPresent=0, pSlotList=(nil), pulCount=0xc52187253700)
>>> Query mode: returning count=1
>>> C_GetSlotList OK (count=1)
>>> C_GetSlotList (tokenPresent=0, pSlotList=0xc521b023d440, pulCount=0xc52187253700)
>>> Filled slot list: slotID=1
>>> C_GetSlotList OK (count=1)
>>> C_GetSlotInfo ENTRY
>>> C_GetSlotInfo (slotID=1, pInfo=0xffffcb0381d0)
>>> C_GetSlotInfo OK (description='Tropic Slot', flags=0x5)
Using slot 0 with a present token (0x1)
>>> C_OpenSession ENTRY
>>> C_OpenSession (slotID=1, flags=0x4, pApplication=(nil), Notify=(nil), phSession=0xffffcb038110)
>>> C_OpenSession OK (session=0x12345678)
>>> C_GenerateRandom (hSession=0x12345678, pRandomData=0xc521b023e370, ulRandomLen=32)
>>> Initializing handle
>>> Starting Secure Session with key 0
>>> Secure session established
>>> Aborting Secure Session
>>> Deinitializing handle
>>> Random bytes (32 bytes):
0x26, 0xA9, 0x1B, 0x4F, 0x17, 0xE6, 0x2D, 0x5C, 
0xF0, 0x9F, 0x44, 0xEB, 0x2C, 0xF8, 0xAE, 0x15, 
0x40, 0x6C, 0x14, 0xE6, 0xE7, 0xAB, 0x24, 0xEE, 
0xCD, 0x87, 0x16, 0xC3, 0x01, 0x31, 0x27, 0x75
>>> C_GenerateRandom OK (generated 32 bytes from TROPIC01 hardware RNG)
>>> C_CloseSession (hSession=0x12345678)
>>> WARNING: This session was never opened by C_OpenSession!
>>> pkcs11-tool might be reusing a stale session or has a bug
>>> C_CloseSession OK (ignoring invalid session)
>>> C_Finalize ENTRY (pReserved=(nil))
>>> C_Finalize (pReserved=(nil))
>>> C_Finalize OK
>>> C_Finalize DONE
00000000: 26a9 1b4f 17e6 2d5c f09f 44eb 2cf8 ae15  &..O..-\..D.,...
00000010: 406c 14e6 e7ab 24ee cd87 16c3 0131 2775  @l....$......1'u
```

### Run 2 (Different Random Values):
```
$ pkcs11-tool --module /home/ales/Documents/PKCS11/libtropic-pkcs11/build/liblibtropic_pkcs11.so --generate-random 32 --output-file /tmp/random.bin && xxd /tmp/random.bin

>>> LIBRARY CONSTRUCTOR CALLED - Installing signal handlers
========================================
>>> C_GetFunctionList (ppFunctionList=0xffffd343cb50)
>>> LOADING TROPIC PKCS#11 LIBRARY
========================================
>>> C_GetFunctionList OK (function list returned at 0xf335faa40b78)
>>> Function pointers: C_Initialize=0xf335fa9bab0c, C_Finalize=0xf335fa9babc0, C_GetInfo=0xf335fa9bacdc
>>> Function pointers: C_OpenSession=0xf335fa9bb568, C_CloseSession=0xf335fa9bb698, C_CloseAllSessions=(nil)
>>> Actual function: C_OpenSession=0xf335fa9bb568
>>> C_Initialize (pInitArgs=(nil))
>>> C_Initialize OK
>>> C_GetSlotList (tokenPresent=0, pSlotList=(nil), pulCount=0xb2c59fc43700)
>>> Query mode: returning count=1
>>> C_GetSlotList OK (count=1)
>>> C_GetSlotList (tokenPresent=0, pSlotList=0xb2c5ae843440, pulCount=0xb2c59fc43700)
>>> Filled slot list: slotID=1
>>> C_GetSlotList OK (count=1)
>>> C_GetSlotInfo ENTRY
>>> C_GetSlotInfo (slotID=1, pInfo=0xffffd343cbb0)
>>> C_GetSlotInfo OK (description='Tropic Slot', flags=0x5)
Using slot 0 with a present token (0x1)
>>> C_OpenSession ENTRY
>>> C_OpenSession (slotID=1, flags=0x4, pApplication=(nil), Notify=(nil), phSession=0xffffd343caf0)
>>> C_OpenSession OK (session=0x12345678)
>>> C_GenerateRandom (hSession=0x12345678, pRandomData=0xb2c5ae844370, ulRandomLen=32)
>>> Initializing handle
>>> Starting Secure Session with key 0
>>> Secure session established
>>> Aborting Secure Session
>>> Deinitializing handle
>>> Random bytes (32 bytes):
0x45, 0x37, 0x22, 0x68, 0x0F, 0x6C, 0xC8, 0xF3, 
0xFA, 0xAD, 0x0E, 0x9A, 0x9D, 0x09, 0x4A, 0x4F, 
0x01, 0x94, 0xCB, 0x47, 0x87, 0x06, 0x01, 0x3E, 
0xC9, 0x84, 0x45, 0x26, 0xD1, 0x10, 0x3C, 0x52
>>> C_GenerateRandom OK (generated 32 bytes from TROPIC01 hardware RNG)
>>> C_CloseSession (hSession=0x12345678)
>>> WARNING: This session was never opened by C_OpenSession!
>>> pkcs11-tool might be reusing a stale session or has a bug
>>> C_CloseSession OK (ignoring invalid session)
>>> C_Finalize ENTRY (pReserved=(nil))
>>> C_Finalize (pReserved=(nil))
>>> C_Finalize OK
>>> C_Finalize DONE
00000000: 4537 2268 0f6c c8f3 faad 0e9a 9d09 4a4f  E7"h.l........JO
00000010: 0194 cb47 8706 013e c984 4526 d110 3c52  ...G...>..E&..<R
```

**Observation:** The random bytes are completely different between runs, confirming the hardware RNG is providing true random values.

---

## Future Improvements and Cleanup Suggestions

### 1. Code Cleanup - Remove Debug Logging

**Current State:** The code has extensive `LOG()` and `printf()` statements for debugging.

**Improvement:** Add a compile-time or runtime flag to control logging verbosity.

```c
// Add to pkcs11.c
#ifdef PKCS11_DEBUG
    #define LOG(...) do { printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)
#else
    #define LOG(...) do { } while(0)
#endif
```

Or use environment variable:
```c
static int debug_enabled = -1;  // -1 = not checked yet

#define LOG(...) do { \
    if (debug_enabled == -1) debug_enabled = (getenv("PKCS11_DEBUG") != NULL); \
    if (debug_enabled) { printf(__VA_ARGS__); printf("\n"); fflush(stdout); } \
} while(0)
```

### 2. Remove Signal Handlers

**Current State:** The library installs SIGSEGV and SIGBUS handlers in a constructor function.

**Why Remove:** 
- Signal handlers can interfere with the application's own handlers
- Not appropriate for production library code
- Were only added for debugging

**Code to Remove:**
```c
// DELETE THIS:
static void segfault_handler(int sig) { ... }

__attribute__((constructor))
static void library_init(void) {
    signal(SIGSEGV, segfault_handler);
    signal(SIGBUS, segfault_handler);
}
```

### 3. Persistent Secure Session

**Current State:** Each call to `C_GenerateRandom()` creates a new secure session, then destroys it.

**Problem:** 
- Secure session establishment is slow (~100-500ms)
- Wastes resources for multiple consecutive calls
- Unnecessary cryptographic operations

**Improvement:** Keep session alive between calls.

```c
// Global session state
static lt_handle_t g_handle = {0};
static lt_dev_unix_usb_dongle_t g_device = {0};
static CK_BBOOL g_session_active = CK_FALSE;

// Initialize session on first use
static lt_ret_t ensure_session(void) {
    if (g_session_active) return LT_OK;
    
    // Configure device (only once)
    if (g_device.dev_path[0] == '\0') {
        strncpy(g_device.dev_path, "/dev/ttyACM0", sizeof(g_device.dev_path) - 1);
        g_device.baud_rate = 115200;
        g_device.rng_seed = (unsigned int)time(NULL);
        g_handle.l2.device = &g_device;
    }
    
    lt_ret_t ret = lt_init(&g_handle);
    if (ret != LT_OK) return ret;
    
    ret = lt_verify_chip_and_start_secure_session(&g_handle, sh0priv, sh0pub, 
                                                   TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (ret != LT_OK) {
        lt_deinit(&g_handle);
        return ret;
    }
    
    g_session_active = CK_TRUE;
    return LT_OK;
}

// Close session in C_Finalize
CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (g_session_active) {
        lt_session_abort(&g_handle);
        lt_deinit(&g_handle);
        g_session_active = CK_FALSE;
    }
    initialized = CK_FALSE;
    return CKR_OK;
}
```

### 4. Configurable Device Path

**Current State:** Device path is hardcoded as `/dev/ttyACM0`.

**Problem:** Different systems may have different device paths.

**Improvement:** Read from environment variable or config file.

```c
static const char* get_device_path(void) {
    const char* env_path = getenv("TROPIC_DEVICE");
    if (env_path && env_path[0] != '\0') {
        return env_path;
    }
    return "/dev/ttyACM0";  // Default
}

// Usage:
strncpy(device.dev_path, get_device_path(), sizeof(device.dev_path) - 1);
```

**Usage:**
```bash
export TROPIC_DEVICE=/dev/ttyACM1
pkcs11-tool --module ... --generate-random 32
```

### 5. Proper Error Code Mapping

**Current State:** Most errors return `CKR_GENERAL_ERROR`.

**Improvement:** Map libtropic errors to appropriate PKCS#11 error codes.

```c
static CK_RV map_lt_error(lt_ret_t ret) {
    switch (ret) {
        case LT_OK:
            return CKR_OK;
        case LT_FAIL:
            return CKR_GENERAL_ERROR;
        case LT_L2_HSK_ERR:
            return CKR_PIN_INCORRECT;  // Key mismatch
        case LT_PARAM_ERR:
            return CKR_ARGUMENTS_BAD;
        case LT_HOST_NO_MEM:
            return CKR_HOST_MEMORY;
        case LT_L2_TIMEOUT:
            return CKR_DEVICE_ERROR;
        // Add more mappings...
        default:
            return CKR_GENERAL_ERROR;
    }
}
```

### 6. Proper Session Management

**Current State:** 
- `C_OpenSession` returns a fixed handle `0x12345678`
- `C_CloseSession` ignores the handle
- Warning message about "session never opened"

**Improvement:** Implement proper session tracking.

```c
#define MAX_SESSIONS 16

typedef struct {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    CK_FLAGS flags;
    CK_BBOOL active;
} session_info_t;

static session_info_t sessions[MAX_SESSIONS] = {0};
static CK_SESSION_HANDLE next_handle = 1;

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    
    // Find free slot
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            sessions[i].handle = next_handle++;
            sessions[i].slot = slotID;
            sessions[i].flags = flags;
            sessions[i].active = CK_TRUE;
            *phSession = sessions[i].handle;
            return CKR_OK;
        }
    }
    return CKR_SESSION_COUNT;  // Too many sessions
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && sessions[i].handle == hSession) {
            sessions[i].active = CK_FALSE;
            return CKR_OK;
        }
    }
    return CKR_SESSION_HANDLE_INVALID;
}
```

### 7. Thread Safety

**Current State:** No thread synchronization.

**Problem:** Multiple threads calling PKCS#11 functions simultaneously could cause race conditions.

**Improvement:** Add mutex protection.

```c
#include <pthread.h>

static pthread_mutex_t lib_mutex = PTHREAD_MUTEX_INITIALIZER;

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    pthread_mutex_lock(&lib_mutex);
    
    // ... existing implementation ...
    
    pthread_mutex_unlock(&lib_mutex);
    return result;
}
```

### 8. Remove Hex Output from C_GenerateRandom

**Current State:** Random bytes are printed to stdout in hex format.

**Problem:** This is debug output that pollutes stdout in production.

**Code to Remove or Conditionalize:**
```c
// Either remove entirely or wrap in debug flag:
#ifdef PKCS11_DEBUG
    printf(">>> Random bytes (%lu bytes):\n", ulRandomLen);
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        printf("0x%02X", pRandomData[i]);
        if (i < ulRandomLen - 1) printf(", ");
        if ((i + 1) % 8 == 0) printf("\n");
    }
    if (ulRandomLen % 8 != 0) printf("\n");
    fflush(stdout);
#endif
```

### 9. Implement Additional PKCS#11 Functions

**Priority Functions to Implement:**

| Function | Purpose | TROPIC01 Support |
|----------|---------|------------------|
| `C_Sign` | Digital signatures | Yes - ECC signing |
| `C_Verify` | Signature verification | Yes - ECC verify |
| `C_GenerateKeyPair` | Generate key pair | Yes - ECC key gen |
| `C_GetMechanismList` | List supported algorithms | Required for compliance |
| `C_GetMechanismInfo` | Algorithm details | Required for compliance |

### 10. Configuration File Support

**Improvement:** Read configuration from a file instead of hardcoded values.

```c
// /etc/tropic-pkcs11.conf or ~/.tropic-pkcs11.conf
/*
device_path = /dev/ttyACM0
baud_rate = 115200
key_slot = 0
debug = false
*/

typedef struct {
    char device_path[256];
    int baud_rate;
    int key_slot;
    int debug;
} pkcs11_config_t;

static pkcs11_config_t load_config(void) {
    pkcs11_config_t cfg = {
        .device_path = "/dev/ttyACM0",
        .baud_rate = 115200,
        .key_slot = 0,
        .debug = 0
    };
    
    // Try user config first, then system config
    FILE* f = fopen(getenv("HOME") ? 
                    strcat(strcpy(path, getenv("HOME")), "/.tropic-pkcs11.conf") : 
                    "/etc/tropic-pkcs11.conf", "r");
    if (f) {
        // Parse config file...
        fclose(f);
    }
    return cfg;
}
```

---

## Cleanup Checklist

Before deploying to production, complete these cleanup tasks:

- [ ] Remove or conditionalize all `LOG()` and `printf()` debug output
- [ ] Remove signal handler installation (`segfault_handler`, `library_init`)
- [ ] Remove the hex byte output from `C_GenerateRandom`
- [ ] Implement proper session management (replace fixed handle)
- [ ] Add thread safety with mutexes
- [ ] Implement configurable device path via environment variable
- [ ] Add proper error code mapping from libtropic to PKCS#11
- [ ] Consider persistent secure session for performance
- [ ] Test with multiple PKCS#11 applications (OpenSSL, Firefox, etc.)
- [ ] Add unit tests for PKCS#11 functions
- [ ] Document the API and configuration options

---

## References

- [PKCS#11 v2.40 Specification (OASIS)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [libtropic Documentation](https://github.com/tropicsquare/libtropic)
- [TROPIC01 Datasheet](https://tropicsquare.com)
- [OpenSC pkcs11-tool](https://github.com/OpenSC/OpenSC/wiki/Using-pkcs11-tool)

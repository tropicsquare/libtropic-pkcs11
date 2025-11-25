/**
 * @file pkcs11.c
 * @brief PKCS#11 Module for TROPIC01 Secure Element - Hardware Random Number Generator
 * 
 * ==================================================================================
 * WHAT IS THIS FILE?
 * ==================================================================================
 * 
 * This file implements a PKCS#11 module (also called "Cryptoki" module) that allows
 * applications to use the TROPIC01 chip's hardware random number generator (HWRNG).
 * 
 * PKCS#11 is a standard API (defined by OASIS) for cryptographic tokens like:
 * - Smart cards
 * - Hardware Security Modules (HSMs)
 * - USB crypto dongles
 * - Secure elements (like TROPIC01)
 * 
 * When compiled, this file becomes a shared library (.so file) that can be loaded
 * by any PKCS#11-compatible application (OpenSSL, Firefox, pkcs11-tool, etc.).
 * 
 * ==================================================================================
 * HOW PKCS#11 WORKS (SIMPLIFIED)
 * ==================================================================================
 * 
 * 1. Application loads our .so library using dlopen()
 * 2. Application calls C_GetFunctionList() to get pointers to all our functions
 * 3. Application calls C_Initialize() to initialize the library
 * 4. Application calls various functions like C_GenerateRandom() to use the token
 * 5. Application calls C_Finalize() when done
 * 
 * ==================================================================================
 * WHAT DOES THIS MODULE DO?
 * ==================================================================================
 * 
 * Main functionality:
 * - C_GenerateRandom(): Gets true random bytes from TROPIC01's hardware RNG
 * - C_GetInfo(): Reads and displays TROPIC01 chip information
 * 
 * The hardware RNG in TROPIC01 uses physical phenomena (thermal noise) to generate
 * true random numbers, which are superior to software pseudo-random generators
 * for cryptographic applications.
 * 
 * ==================================================================================
 * AUTHOR & LICENSE
 * ==================================================================================
 * 
 * Based on libtropic by Tropic Square s.r.o.
 * PKCS#11 integration for hardware RNG access.
 */

/* ==================================================================================
 * INCLUDE FILES
 * ==================================================================================
 * 
 * We need headers for:
 * - PKCS#11 types and constants (pkcs11.h)
 * - Standard C library functions (stdio, string, stdlib, time)
 * - libtropic API for communicating with TROPIC01 chip
 */

#include "pkcs11.h"           /* PKCS#11 type definitions (CK_RV, CK_INFO, etc.) */
#include <stdio.h>            /* printf(), fflush() for debug output */
#include <string.h>           /* strncpy(), memset() for string/memory operations */
#include <stdlib.h>           /* exit() */
#include <signal.h>           /* signal() for crash handler (debug only) */
#include <time.h>             /* time() for RNG seed */
#include <inttypes.h>         /* PRIu64 and similar format specifiers */

/* libtropic headers - these provide the API to communicate with TROPIC01 */
#include "libtropic.h"                      /* Main libtropic API: lt_init(), lt_random_value_get(), etc. */
#include "libtropic_common.h"               /* Common types: lt_ret_t, lt_handle_t, etc. */
#include "libtropic_examples.h"             /* Example utilities and key declarations */
#include "libtropic_logging.h"              /* Logging macros from libtropic */
#include "string.h"                         /* Additional string functions */
#include "libtropic_port.h"                 /* Hardware Abstraction Layer (HAL) interface */
#include "libtropic_port_unix_usb_dongle.h" /* Unix USB dongle HAL implementation */

/* ==================================================================================
 * DEBUG LOGGING MACRO
 * ==================================================================================
 * 
 * This macro prints debug messages to stdout with automatic newline.
 * The do-while(0) wrapper is a C idiom that makes the macro behave like a statement.
 * fflush(stdout) ensures output appears immediately (not buffered).
 * 
 * Usage: LOG("Value is %d", value);
 * Output: "Value is 42\n"
 * 
 * TODO: In production, this should be disabled or controlled by environment variable.
 */
#define LOG(...) do { printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)


/* ==================================================================================
 * GLOBAL STATE
 * ==================================================================================
 * 
 * PKCS#11 requires tracking whether the library has been initialized.
 * C_Initialize() sets this to CK_TRUE, C_Finalize() sets it to CK_FALSE.
 * 
 * CK_BBOOL is the PKCS#11 boolean type (typically unsigned char).
 * CK_TRUE and CK_FALSE are the PKCS#11 boolean constants.
 */
static CK_BBOOL initialized = CK_FALSE;

/* ==================================================================================
 * DEBUG SIGNAL HANDLERS (FOR DEVELOPMENT ONLY)
 * ==================================================================================
 * 
 * These handlers catch segmentation faults (SIGSEGV) and bus errors (SIGBUS).
 * They were added during development to help debug crashes.
 * 
 * SIGSEGV: Occurs when accessing invalid memory address
 * SIGBUS:  Occurs when accessing misaligned memory (common on ARM)
 * 
 * WARNING: Signal handlers in libraries can interfere with the application's
 * own handlers. Remove these for production use!
 * 
 * The __attribute__((constructor)) makes library_init() run automatically
 * when the shared library is loaded (before main() in the application).
 */

/**
 * @brief Signal handler that catches crashes and prints a message before exiting.
 * @param sig The signal number (SIGSEGV=11, SIGBUS=7 on most systems)
 * 
 * NOTE: This is for debugging only. Remove for production!
 */
static void segfault_handler(int sig) {
    printf("\n!!! SEGFAULT CAUGHT - signal %d !!!\n", sig);
    fflush(stdout);
    exit(1);
}

/**
 * @brief Library constructor - runs automatically when .so is loaded.
 * 
 * Installs signal handlers for catching crashes during development.
 * The __attribute__((constructor)) is a GCC extension that marks this
 * function to run at library load time.
 * 
 * NOTE: Remove this for production use!
 */
__attribute__((constructor))
static void library_init(void) {
    printf(">>> LIBRARY CONSTRUCTOR CALLED - Installing signal handlers\n");
    fflush(stdout);
    signal(SIGSEGV, segfault_handler);  /* Catch segmentation faults */
    signal(SIGBUS, segfault_handler);   /* Catch bus errors (memory alignment) */
}


/* ==================================================================================
 * PKCS#11 REQUIRED FUNCTIONS
 * ==================================================================================
 * 
 * Every PKCS#11 module must implement certain core functions. These are:
 * - C_Initialize: Called once when application starts using the module
 * - C_Finalize: Called once when application is done with the module
 * - C_GetInfo: Returns information about the PKCS#11 library itself
 * - C_GetFunctionList: Returns pointers to all functions (most important!)
 * - C_GetSlotList: Lists available "slots" (physical readers/ports)
 * - C_GetSlotInfo: Information about a specific slot
 * - C_GetTokenInfo: Information about the token (chip) in a slot
 * - C_OpenSession: Opens a session with a token
 * - C_CloseSession: Closes a session
 * 
 * All PKCS#11 functions return CK_RV (return value), which is an error code.
 * CKR_OK (0) means success, other values indicate specific errors.
 */

/**
 * @brief Initialize the PKCS#11 library.
 * 
 * This function MUST be called before any other PKCS#11 function (except
 * C_GetFunctionList). It performs global initialization.
 * 
 * @param pInitArgs Pointer to initialization arguments (CK_C_INITIALIZE_ARGS).
 *                  Can be NULL for default initialization.
 *                  We ignore this parameter in our implementation.
 * 
 * @return CKR_OK on success
 * @return CKR_CRYPTOKI_ALREADY_INITIALIZED if already initialized
 * 
 * PKCS#11 Spec: "If several applications need to use Cryptoki concurrently,
 * they should each call C_Initialize independently."
 */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    LOG(">>> C_Initialize (pInitArgs=%p)", pInitArgs);
    
    /* Check if already initialized - PKCS#11 forbids double initialization */
    if (initialized) {
        LOG(">>> Already initialized - returning CKR_CRYPTOKI_ALREADY_INITIALIZED");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    
    /* Mark as initialized */
    initialized = CK_TRUE;
    
    LOG(">>> C_Initialize OK");
    return CKR_OK;
}

/**
 * @brief Finalize (shut down) the PKCS#11 library.
 * 
 * This function releases all resources and prepares the library for unloading.
 * After calling this, no PKCS#11 functions should be called except
 * C_GetFunctionList and C_Initialize.
 * 
 * @param pReserved Reserved for future use. MUST be NULL in PKCS#11 2.40.
 * 
 * @return CKR_OK on success
 * @return CKR_CRYPTOKI_NOT_INITIALIZED if not initialized
 * 
 * NOTE: In a production implementation, we would close any open sessions
 * and release hardware resources here.
 */
CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    printf(">>> C_Finalize ENTRY (pReserved=%p)\n", pReserved);
    fflush(stdout);
    LOG(">>> C_Finalize (pReserved=%p)", pReserved);
    fflush(stdout);
    
    /* Can't finalize if not initialized */
    if (!initialized) {
        LOG(">>> Not initialized - returning CKR_CRYPTOKI_NOT_INITIALIZED");
        fflush(stdout);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Mark as not initialized */
    initialized = CK_FALSE;
    
    LOG(">>> C_Finalize OK");
    fflush(stdout);
    printf(">>> C_Finalize DONE\n");
    fflush(stdout);
    return CKR_OK;
}

/**
 * @brief Get information about the PKCS#11 library.
 * 
 * Returns general information about the Cryptoki library, including:
 * - Cryptoki version (2.40)
 * - Manufacturer ID ("TropicSquare")
 * - Library description ("Tropic PKCS11")
 * 
 * BONUS FEATURE: We also use this function to read and display TROPIC01
 * chip information (firmware versions, chip ID, serial number).
 * This doesn't require a secure session.
 * 
 * @param pInfo Pointer to CK_INFO structure to fill with library info.
 *              The structure has fixed-size char arrays (32/64 bytes).
 * 
 * @return CKR_OK on success
 * @return CKR_ARGUMENTS_BAD if pInfo is NULL
 */
CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    LOG(">>> C_GetInfo (pInfo=%p)", pInfo);
    
    /* Validate parameter */
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }

    /* =========================================================================
     * TROPIC01 CHIP INFO READING (BONUS FEATURE)
     * =========================================================================
     * 
     * Here we connect to the TROPIC01 chip and read its information.
     * This demonstrates basic libtropic usage and provides useful debug info.
     * 
     * NOTE: Reading chip info does NOT require a secure session.
     * The chip freely provides its ID, firmware versions, etc.
     */
    
    /* Step 1: Create handle and device configuration structures */
    lt_handle_t h = {0};                    /* libtropic handle - manages chip state */
    lt_dev_unix_usb_dongle_t device = {0};  /* USB dongle configuration */
    
    /* Step 2: Configure the USB device
     * 
     * dev_path: The Linux device file for the USB serial port.
     *           Usually /dev/ttyACM0 for the first USB ACM device.
     *           May be different if multiple USB devices are connected.
     * 
     * baud_rate: Serial communication speed (115200 baud for TROPIC01)
     * 
     * rng_seed: Seed for software RNG (used as fallback, not for our HWRNG)
     */
    strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
    device.baud_rate = 115200;
    device.rng_seed = (unsigned int)time(NULL);  /* Use current time as seed */
    
    /* Step 3: Attach device config to the handle's L2 (Layer 2) structure
     * 
     * libtropic uses a layered architecture:
     * - L1: Physical layer (SPI, I2C, USB)
     * - L2: Frame layer (packet framing, CRC)
     * - L3: Application layer (commands, responses)
     */
    h.l2.device = &device;

    /* Step 4: Initialize communication with the chip */
    lt_ret_t ret = lt_init(&h);
    if (ret == LT_OK) {
        LOG(">>> TROPIC01 initialized successfully");
        
        /* Read RISC-V firmware version
         * 
         * TROPIC01 has a RISC-V processor running application firmware.
         * Version format: major.minor.patch.build (stored in reverse order)
         */
        uint8_t fw_ver[4] = {0};
        
        ret = lt_get_info_riscv_fw_ver(&h, fw_ver);
        if (ret == LT_OK) {
            LOG(">>> RISC-V FW version: %d.%d.%d.%d", fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
        } else {
            LOG(">>> Failed to get RISC-V FW version: %s", lt_ret_verbose(ret));
        }
        
        /* Read SPECT firmware version
         * 
         * SPECT is the cryptographic coprocessor inside TROPIC01.
         * It handles all crypto operations (RNG, ECC, AES, etc.)
         */
        ret = lt_get_info_spect_fw_ver(&h, fw_ver);
        if (ret == LT_OK) {
            LOG(">>> SPECT FW version: %d.%d.%d.%d", fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
        } else {
            LOG(">>> Failed to get SPECT FW version: %s", lt_ret_verbose(ret));
        }
        
        /* Read chip ID
         * 
         * Contains detailed chip information:
         * - Serial number (unique per chip)
         * - Part number
         * - Batch ID
         * - Provisioning info
         * - Manufacturing date
         * - And more...
         */
        struct lt_chip_id_t chip_id = {0};
        ret = lt_get_info_chip_id(&h, &chip_id);
        if (ret == LT_OK) {
            LOG(">>> Chip ID:");
            /* lt_print_chip_id() formats and prints all chip info fields */
            lt_print_chip_id(&chip_id, printf);
        } else {
            LOG(">>> Failed to get chip ID: %s", lt_ret_verbose(ret));
        }
        
        /* Step 5: Clean up - always deinitialize when done */
        lt_deinit(&h);
    } else {
        LOG(">>> TROPIC01 init failed: %s", lt_ret_verbose(ret));
    }

    /* =========================================================================
     * FILL IN PKCS#11 LIBRARY INFO
     * =========================================================================
     * 
     * This is the actual PKCS#11 requirement - return info about the library.
     */
    
    /* Clear the structure first (PKCS#11 strings are space-padded, not null-terminated) */
    memset(pInfo, 0, sizeof(CK_INFO));
    
    /* Cryptoki version we implement: 2.40 */
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    
    /* Manufacturer and library description (max 32 chars each) */
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char*)pInfo->libraryDescription, "Tropic PKCS11", 32);
    
    LOG(">>> C_GetInfo OK (version=%d.%d, manufacturer=TropicSquare)", 
        pInfo->cryptokiVersion.major, pInfo->cryptokiVersion.minor);
    return CKR_OK;
}

/**
 * @brief Get list of available slots (token readers/interfaces).
 * 
 * In PKCS#11 terminology:
 * - SLOT: A physical reader or interface where a token can be inserted
 * - TOKEN: The cryptographic device (smart card, HSM, TROPIC01 chip)
 * 
 * Our implementation provides a single slot (ID=1) with TROPIC01 as the token.
 * 
 * This function can be called in two modes:
 * 1. Query mode (pSlotList=NULL): Just return count of available slots
 * 2. Fill mode (pSlotList!=NULL): Fill the array with slot IDs
 * 
 * @param tokenPresent If TRUE, only list slots with tokens present.
 *                     We ignore this since our token is always present.
 * @param pSlotList    Array to fill with slot IDs, or NULL for query mode.
 * @param pulCount     Pointer to slot count. On input (fill mode): size of array.
 *                     On output: number of slots available/returned.
 * 
 * @return CKR_OK on success
 * @return CKR_ARGUMENTS_BAD if pulCount is NULL
 * @return CKR_BUFFER_TOO_SMALL if pSlotList array is too small
 */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    LOG(">>> C_GetSlotList (tokenPresent=%d, pSlotList=%p, pulCount=%p)", 
        tokenPresent, pSlotList, pulCount);
    
    /* pulCount is required */
    if (!pulCount) {
        LOG(">>> pulCount is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    if (!pSlotList) {
        /* Query mode: application wants to know how many slots exist */
        *pulCount = 1;  /* We have exactly one slot */
        LOG(">>> Query mode: returning count=1");
    } else {
        /* Fill mode: application wants the actual slot IDs */
        if (*pulCount < 1) {
            /* Array too small to hold our slot */
            LOG(">>> Buffer too small (pulCount=%lu) - returning CKR_BUFFER_TOO_SMALL", *pulCount);
            return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[0] = 1;   /* Our slot has ID 1 */
        *pulCount = 1;      /* We returned 1 slot */
        LOG(">>> Filled slot list: slotID=1");
    }
    
    LOG(">>> C_GetSlotList OK (count=%lu)", *pulCount);
    return CKR_OK;
}

/**
 * @brief Get information about a specific slot.
 * 
 * Returns details about the slot (reader/interface), including:
 * - Description ("Tropic Slot")
 * - Manufacturer ("TropicSquare")
 * - Flags indicating capabilities
 * 
 * @param slotID The slot ID to query (must be 1 for our implementation)
 * @param pInfo  Pointer to CK_SLOT_INFO structure to fill
 * 
 * @return CKR_OK on success
 * @return CKR_SLOT_ID_INVALID if slotID is not 1
 * @return CKR_ARGUMENTS_BAD if pInfo is NULL
 * 
 * Flags we set:
 * - CKF_TOKEN_PRESENT: There is a token (TROPIC01) in the slot
 * - CKF_HW_SLOT: This is a hardware slot (not software emulation)
 */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    printf(">>> C_GetSlotInfo ENTRY\n"); fflush(stdout);
    LOG(">>> C_GetSlotInfo (slotID=%lu, pInfo=%p)", slotID, pInfo);
    
    /* We only support slot ID 1 */
    if (slotID != 1) { 
        LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    
    /* pInfo is required */
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Fill in slot information */
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    strncpy((char*)pInfo->slotDescription, "Tropic Slot", 64);    /* Max 64 chars */
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);    /* Max 32 chars */
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;               /* Token is present, hardware slot */
    
    LOG(">>> C_GetSlotInfo OK (description='Tropic Slot', flags=0x%lx)", pInfo->flags);
    return CKR_OK;
}

/**
 * @brief Get information about the token (TROPIC01 chip) in a slot.
 * 
 * Returns details about the cryptographic token, including:
 * - Label ("TROPIC-RNG")
 * - Manufacturer ("TropicSquare")
 * - Flags indicating capabilities
 * 
 * @param slotID The slot ID containing the token (must be 1)
 * @param pInfo  Pointer to CK_TOKEN_INFO structure to fill
 * 
 * @return CKR_OK on success
 * @return CKR_SLOT_ID_INVALID if slotID is not 1
 * @return CKR_ARGUMENTS_BAD if pInfo is NULL
 * 
 * Key flag:
 * - CKF_RNG: This token has a hardware Random Number Generator
 */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    printf(">>> C_GetTokenInfo ENTRY\n"); fflush(stdout);
    LOG(">>> C_GetTokenInfo (slotID=%lu, pInfo=%p)", slotID, pInfo);
    
    /* We only support slot ID 1 */
    if (slotID != 1) { 
        LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    
    /* pInfo is required */
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Fill in token information */
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    strncpy((char*)pInfo->label, "TROPIC-RNG", 32);           /* Token label, max 32 chars */
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32); /* Manufacturer, max 32 chars */
    pInfo->flags = CKF_RNG;  /* This token has a hardware RNG! */
    
    LOG(">>> C_GetTokenInfo OK (label='TROPIC-RNG', flags=0x%lx)", pInfo->flags);
    return CKR_OK;
}

/**
 * @brief Open a session with a token.
 * 
 * A session is a logical connection between an application and a token.
 * Sessions are used for cryptographic operations, object management, etc.
 * 
 * Our implementation is simplified:
 * - We always return a fixed session handle (0x12345678)
 * - We don't track sessions (no multi-session support)
 * 
 * @param slotID      Slot ID containing the token (must be 1)
 * @param flags       Session flags (we ignore these)
 *                    - CKF_SERIAL_SESSION: Required for PKCS#11 2.x
 *                    - CKF_RW_SESSION: Read-write session (vs read-only)
 * @param pApplication Application-defined pointer (passed to callbacks)
 * @param Notify      Callback function for session events (we ignore this)
 * @param phSession   Pointer to receive the session handle
 * 
 * @return CKR_OK on success
 * @return CKR_SLOT_ID_INVALID if slotID is not 1
 * @return CKR_ARGUMENTS_BAD if phSession is NULL
 * 
 * TODO: Implement proper session tracking for production use.
 */
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    printf(">>> C_OpenSession ENTRY\n");
    fflush(stdout);
    LOG(">>> C_OpenSession (slotID=%lu, flags=0x%lx, pApplication=%p, Notify=%p, phSession=%p)", 
        slotID, flags, pApplication, Notify, phSession);
    
    /* We only support slot ID 1 */
    if (slotID != 1) {
        LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    
    /* phSession is required - we need somewhere to return the handle */
    if (!phSession) {
        LOG(">>> phSession is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Return a fixed session handle
     * NOTE: In production, we should generate unique handles and track sessions */
    *phSession = 0x12345678;
    
    LOG(">>> C_OpenSession OK (session=0x%lx)", *phSession);
    return CKR_OK;
}

/**
 * @brief Close a session with a token.
 * 
 * Closes a session and releases associated resources.
 * 
 * Our implementation is simplified - we accept any handle and always succeed.
 * This is because we don't actually track sessions.
 * 
 * @param hSession The session handle to close
 * 
 * @return CKR_OK always (we don't validate the handle)
 * 
 * TODO: Implement proper session validation for production use.
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    LOG(">>> C_CloseSession (hSession=0x%lx)", hSession);
    
    /* NOTE: We print a warning because pkcs11-tool may call this with handles
     * we didn't create. This is not an error, just informational. */
    LOG(">>> WARNING: This session was never opened by C_OpenSession!");
    LOG(">>> pkcs11-tool might be reusing a stale session or has a bug");
    fflush(stdout);
    
    /* We don't crash on invalid sessions - just return OK */
    LOG(">>> C_CloseSession OK (ignoring invalid session)");
    fflush(stdout);
    return CKR_OK;
}


/* ==================================================================================
 * RANDOM NUMBER GENERATION FUNCTIONS
 * ==================================================================================
 * 
 * This is the main functionality of this PKCS#11 module!
 * 
 * We implement:
 * - C_GenerateRandom: Get random bytes from TROPIC01's hardware RNG
 * - C_SeedRandom: Add seed data to RNG (no-op for true HWRNG)
 */

/* External declaration of pairing keys
 * 
 * These keys are defined in libtropic/keys/keys.c and linked into our library.
 * They are used for establishing a secure session with TROPIC01.
 * 
 * sh0priv: Our private key (X25519, 32 bytes)
 * sh0pub:  The chip's public key (X25519, 32 bytes)
 * 
 * These are factory-provisioned keys. Different chip batches have different keys.
 * The keys enable mutual authentication and encrypted communication.
 */
extern uint8_t sh0priv[];
extern uint8_t sh0pub[];

/**
 * @brief Generate random bytes using TROPIC01's hardware RNG.
 * 
 * ==================================================================================
 * THIS IS THE MAIN FUNCTION OF THIS PKCS#11 MODULE!
 * ==================================================================================
 * 
 * This function retrieves true random bytes from the TROPIC01 chip's hardware
 * random number generator. Hardware RNGs use physical phenomena (thermal noise,
 * quantum effects) to generate true randomness, making them ideal for cryptographic
 * key generation, nonces, and other security-critical applications.
 * 
 * How it works:
 * 1. Open USB connection to TROPIC01
 * 2. Establish encrypted secure session (required to access RNG)
 * 3. Request random bytes from the chip
 * 4. Close session and return data to application
 * 
 * @param hSession    Session handle (we don't validate this)
 * @param pRandomData Pointer to buffer to fill with random bytes
 * @param ulRandomLen Number of random bytes to generate
 * 
 * @return CKR_OK on success
 * @return CKR_ARGUMENTS_BAD if pRandomData is NULL or ulRandomLen is 0
 * @return CKR_GENERAL_ERROR if communication with TROPIC01 fails
 * 
 * IMPORTANT: The secure session establishment takes ~100-500ms, so this function
 * is relatively slow. For high-performance applications, consider caching the
 * session (see improvement suggestions in WHATWASCHANGED.md).
 */
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    LOG(">>> C_GenerateRandom (hSession=0x%lx, pRandomData=%p, ulRandomLen=%lu)", 
        hSession, pRandomData, ulRandomLen);
    
    /* =========================================================================
     * STEP 1: VALIDATE PARAMETERS
     * =========================================================================
     * 
     * PKCS#11 requires us to validate all input parameters and return
     * appropriate error codes.
     */
    if (!pRandomData) {
        LOG(">>> pRandomData is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if (ulRandomLen == 0) {
        LOG(">>> ulRandomLen is 0 - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* =========================================================================
     * STEP 2: SET UP USB DEVICE CONFIGURATION
     * =========================================================================
     * 
     * We need to configure:
     * - Device path: Where the USB device appears in Linux filesystem
     * - Baud rate: Serial communication speed (must match chip config)
     * - RNG seed: For software fallback (not used for our HWRNG)
     */
    lt_handle_t h = {0};                    /* libtropic handle - manages chip state */
    lt_dev_unix_usb_dongle_t device = {0};  /* USB device configuration */
    
    strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
    device.baud_rate = 115200;              /* 115200 baud, standard for TROPIC01 */
    device.rng_seed = (unsigned int)time(NULL);  /* Seed for software RNG fallback */
    
    /* Attach device config to the handle */
    h.l2.device = &device;

    /* =========================================================================
     * STEP 3: INITIALIZE COMMUNICATION WITH TROPIC01
     * =========================================================================
     * 
     * lt_init() performs:
     * - Opens the serial port
     * - Sends initial handshake to verify chip is responding
     * - Sets up communication buffers
     */
    LOG(">>> Initializing handle");
    lt_ret_t ret = lt_init(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to initialize handle: %s", lt_ret_verbose(ret));
        lt_deinit(&h);  /* Clean up even on failure */
        return CKR_GENERAL_ERROR;
    }
    
    /* =========================================================================
     * STEP 4: ESTABLISH SECURE SESSION
     * =========================================================================
     * 
     * TROPIC01 requires an authenticated, encrypted session to access sensitive
     * operations like the hardware RNG. This is a security feature - it ensures
     * only authorized hosts can use the chip's cryptographic capabilities.
     * 
     * lt_verify_chip_and_start_secure_session() performs:
     * 1. X25519 key exchange (Diffie-Hellman) to establish shared secret
     * 2. Derives session encryption keys using HKDF
     * 3. Establishes AES-GCM encrypted channel
     * 4. Verifies chip authenticity using stored keys
     * 
     * Parameters:
     * - h: Our handle
     * - sh0priv: Our X25519 private key (32 bytes)
     * - sh0pub: Chip's X25519 public key (32 bytes)
     * - TR01_PAIRING_KEY_SLOT_INDEX_0: Which key slot to use (0-3)
     * 
     * Key slots have different access permissions - slot 0 typically has
     * full access, while others may be restricted.
     */
    LOG(">>> Starting Secure Session with key %d", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    ret = lt_verify_chip_and_start_secure_session(&h, sh0priv, sh0pub, TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (ret != LT_OK) {
        LOG(">>> Failed to start Secure Session: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    LOG(">>> Secure session established");
    
    /* =========================================================================
     * STEP 5: GET RANDOM BYTES FROM HARDWARE RNG
     * =========================================================================
     * 
     * TROPIC01 can return maximum 255 bytes per request (TR01_RANDOM_VALUE_GET_LEN_MAX).
     * For larger requests, we need to make multiple calls and accumulate the data.
     * 
     * The hardware RNG uses:
     * - True random noise sources (thermal noise)
     * - On-chip entropy conditioning
     * - NIST SP 800-90B compliant design
     */
    CK_ULONG remaining = ulRandomLen;   /* How many bytes we still need */
    CK_BYTE_PTR ptr = pRandomData;      /* Where to write next bytes */
    
    while (remaining > 0) {
        /* Calculate chunk size: either remaining bytes or max allowed, whichever is smaller */
        uint16_t chunk_size = (remaining > TR01_RANDOM_VALUE_GET_LEN_MAX) ? 
                              TR01_RANDOM_VALUE_GET_LEN_MAX : (uint16_t)remaining;
        
        /* Request random bytes from the chip */
        ret = lt_random_value_get(&h, ptr, chunk_size);
        if (ret != LT_OK) {
            LOG(">>> Failed to get random bytes: %s", lt_ret_verbose(ret));
            /* On error, clean up and return */
            lt_session_abort(&h);
            lt_deinit(&h);
            return CKR_GENERAL_ERROR;
        }
        
        /* Move pointer forward and decrease remaining count */
        ptr += chunk_size;
        remaining -= chunk_size;
    }
    
    /* =========================================================================
     * STEP 6: CLEAN UP - ABORT SESSION
     * =========================================================================
     * 
     * We must properly close the secure session. This:
     * - Notifies the chip that we're done
     * - Clears session keys from memory
     * - Allows new sessions to be established
     */
    LOG(">>> Aborting Secure Session");
    ret = lt_session_abort(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to abort Secure Session: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    
    /* =========================================================================
     * STEP 7: DEINITIALIZE - CLOSE USB CONNECTION
     * =========================================================================
     * 
     * lt_deinit() performs:
     * - Closes the serial port
     * - Frees allocated buffers
     * - Resets handle state
     */
    LOG(">>> Deinitializing handle");
    ret = lt_deinit(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to deinitialize handle: %s", lt_ret_verbose(ret));
        return CKR_GENERAL_ERROR;
    }
    
    /* =========================================================================
     * STEP 8: DEBUG OUTPUT - PRINT RANDOM BYTES IN HEX
     * =========================================================================
     * 
     * Print the generated random bytes for verification.
     * Format: 0xAA, 0xBB, 0xCC, ...
     * 
     * NOTE: Remove this for production use - it pollutes stdout.
     */
    printf(">>> Random bytes (%lu bytes):\n", ulRandomLen);
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        printf("0x%02X", pRandomData[i]);
        if (i < ulRandomLen - 1) printf(", ");
        if ((i + 1) % 8 == 0) printf("\n");  /* New line every 8 bytes */
    }
    if (ulRandomLen % 8 != 0) printf("\n");
    fflush(stdout);
    
    LOG(">>> C_GenerateRandom OK (generated %lu bytes from TROPIC01 hardware RNG)", ulRandomLen);
    return CKR_OK;
}

/**
 * @brief Seed the random number generator.
 * 
 * In PKCS#11, applications can provide additional entropy to seed the RNG.
 * However, for a TRUE hardware RNG like TROPIC01, seeding is not necessary
 * (and may not be supported by the hardware).
 * 
 * Our implementation accepts the seed but does nothing with it.
 * This is valid for a HWRNG - the randomness comes from physical sources,
 * not from a seeded algorithm.
 * 
 * @param hSession  Session handle (not validated)
 * @param pSeed     Pointer to seed data
 * @param ulSeedLen Length of seed data in bytes
 * 
 * @return CKR_OK always (we accept but ignore the seed)
 * @return CKR_ARGUMENTS_BAD if pSeed is NULL or ulSeedLen is 0
 */
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    LOG(">>> C_SeedRandom (hSession=0x%lx, pSeed=%p, ulSeedLen=%lu)", 
        hSession, pSeed, ulSeedLen);
    
    /* Validate parameters */
    if (!pSeed) {
        LOG(">>> pSeed is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if (ulSeedLen == 0) {
        LOG(">>> ulSeedLen is 0 - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Accept the seed but do nothing - HWRNG doesn't need external seeding */
    LOG(">>> C_SeedRandom OK (seeded with %lu bytes)", ulSeedLen);
    return CKR_OK;
}


/* ==================================================================================
 * FUNCTION LIST - THE HEART OF PKCS#11
 * ==================================================================================
 * 
 * C_GetFunctionList is the MOST IMPORTANT function in PKCS#11.
 * It's the ONLY function that applications call directly (by name).
 * All other functions are called through pointers in the function list.
 * 
 * The function list is a structure (CK_FUNCTION_LIST) containing pointers
 * to every PKCS#11 function. The order of fields is defined by the spec
 * and MUST be exact - any mismatch will cause crashes.
 * 
 * Functions we implement get their actual function pointer.
 * Functions we don't implement get NULL (returning CKR_FUNCTION_NOT_SUPPORTED).
 */

/**
 * @brief Get the list of all PKCS#11 function pointers.
 * 
 * This is typically the first function called by any PKCS#11 application.
 * The application loads our .so library, finds this function by name using
 * dlsym(), calls it to get pointers to all other functions.
 * 
 * @param ppFunctionList Pointer to receive the function list pointer.
 *                       After calling, *ppFunctionList points to our
 *                       static CK_FUNCTION_LIST structure.
 * 
 * @return CKR_OK on success
 * @return CKR_ARGUMENTS_BAD if ppFunctionList is NULL
 * 
 * IMPORTANT: The function list structure must match PKCS#11 2.40 exactly.
 * Any missing/extra fields or wrong order will cause crashes!
 */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    LOG("========================================");
    LOG(">>> C_GetFunctionList (ppFunctionList=%p)", ppFunctionList);
    LOG(">>> LOADING TROPIC PKCS#11 LIBRARY");
    LOG("========================================");
    
    /* Validate parameter */
    if (!ppFunctionList) {
        LOG(">>> ppFunctionList is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* =========================================================================
     * THE FUNCTION LIST
     * =========================================================================
     * 
     * This structure contains pointers to ALL PKCS#11 functions.
     * The structure is defined in pkcs11.h.
     * 
     * We use designated initializers (.member = value) for clarity and safety.
     * This ensures fields are set correctly regardless of declaration order.
     * 
     * Fields set to NULL indicate unimplemented functions. When called,
     * the application receives CKR_FUNCTION_NOT_SUPPORTED.
     */
    static CK_FUNCTION_LIST functionList = {
        /* Cryptoki version this library implements */
        .version = {2, 40},  /* PKCS#11 version 2.40 */
        
        /* =====================================================================
         * GENERAL PURPOSE FUNCTIONS
         * These are required for basic library operation.
         * ===================================================================== */
        .C_Initialize = C_Initialize,           /* Initialize library */
        .C_Finalize = C_Finalize,               /* Shut down library */
        .C_GetInfo = C_GetInfo,                 /* Get library info */
        .C_GetFunctionList = C_GetFunctionList, /* Get this function list */
        
        /* =====================================================================
         * SLOT AND TOKEN MANAGEMENT
         * Functions for discovering and querying slots/tokens.
         * ===================================================================== */
        .C_GetSlotList = C_GetSlotList,         /* List available slots */
        .C_GetSlotInfo = C_GetSlotInfo,         /* Get info about a slot */
        .C_GetTokenInfo = C_GetTokenInfo,       /* Get info about token in slot */
        .C_GetMechanismList = NULL,             /* List supported mechanisms (not implemented) */
        .C_GetMechanismInfo = NULL,             /* Get mechanism info (not implemented) */
        .C_InitToken = NULL,                    /* Initialize a token (not implemented) */
        .C_InitPIN = NULL,                      /* Initialize user PIN (not implemented) */
        .C_SetPIN = NULL,                       /* Change user PIN (not implemented) */
        
        /* =====================================================================
         * SESSION MANAGEMENT
         * Functions for managing sessions with tokens.
         * ===================================================================== */
        .C_OpenSession = C_OpenSession,         /* Open a session */
        .C_CloseSession = C_CloseSession,       /* Close a session */
        .C_CloseAllSessions = NULL,             /* Close all sessions (not implemented) */
        .C_GetSessionInfo = NULL,               /* Get session info (not implemented) */
        .C_GetOperationState = NULL,            /* Get crypto operation state (not implemented) */
        .C_SetOperationState = NULL,            /* Set crypto operation state (not implemented) */
        .C_Login = NULL,                        /* Log in to token (not implemented) */
        .C_Logout = NULL,                       /* Log out from token (not implemented) */
        
        /* =====================================================================
         * OBJECT MANAGEMENT
         * Functions for managing objects (keys, certs, data) on the token.
         * ===================================================================== */
        .C_CreateObject = NULL,                 /* Create an object (not implemented) */
        .C_CopyObject = NULL,                   /* Copy an object (not implemented) */
        .C_DestroyObject = NULL,                /* Delete an object (not implemented) */
        .C_GetObjectSize = NULL,                /* Get object size (not implemented) */
        .C_GetAttributeValue = NULL,            /* Get object attributes (not implemented) */
        .C_SetAttributeValue = NULL,            /* Set object attributes (not implemented) */
        .C_FindObjectsInit = NULL,              /* Start object search (not implemented) */
        .C_FindObjects = NULL,                  /* Continue object search (not implemented) */
        .C_FindObjectsFinal = NULL,             /* End object search (not implemented) */
        
        /* =====================================================================
         * ENCRYPTION FUNCTIONS
         * Functions for encrypting data.
         * ===================================================================== */
        .C_EncryptInit = NULL,                  /* Initialize encryption (not implemented) */
        .C_Encrypt = NULL,                      /* Encrypt data (not implemented) */
        .C_EncryptUpdate = NULL,                /* Continue multi-part encryption (not implemented) */
        .C_EncryptFinal = NULL,                 /* Finish multi-part encryption (not implemented) */
        
        /* =====================================================================
         * DECRYPTION FUNCTIONS
         * Functions for decrypting data.
         * ===================================================================== */
        .C_DecryptInit = NULL,                  /* Initialize decryption (not implemented) */
        .C_Decrypt = NULL,                      /* Decrypt data (not implemented) */
        .C_DecryptUpdate = NULL,                /* Continue multi-part decryption (not implemented) */
        .C_DecryptFinal = NULL,                 /* Finish multi-part decryption (not implemented) */
        
        /* =====================================================================
         * MESSAGE DIGESTING (HASHING) FUNCTIONS
         * Functions for computing hashes/digests of data.
         * ===================================================================== */
        .C_DigestInit = NULL,                   /* Initialize digest (not implemented) */
        .C_Digest = NULL,                       /* Compute digest (not implemented) */
        .C_DigestUpdate = NULL,                 /* Continue multi-part digest (not implemented) */
        .C_DigestKey = NULL,                    /* Include key in digest (not implemented) */
        .C_DigestFinal = NULL,                  /* Finish multi-part digest (not implemented) */
        
        /* =====================================================================
         * SIGNING AND MACING FUNCTIONS
         * Functions for creating digital signatures.
         * ===================================================================== */
        .C_SignInit = NULL,                     /* Initialize signing (not implemented) */
        .C_Sign = NULL,                         /* Create signature (not implemented) */
        .C_SignUpdate = NULL,                   /* Continue multi-part signing (not implemented) */
        .C_SignFinal = NULL,                    /* Finish multi-part signing (not implemented) */
        .C_SignRecoverInit = NULL,              /* Init signing with data recovery (not implemented) */
        .C_SignRecover = NULL,                  /* Sign with data recovery (not implemented) */
        
        /* =====================================================================
         * SIGNATURE VERIFICATION FUNCTIONS
         * Functions for verifying digital signatures.
         * ===================================================================== */
        .C_VerifyInit = NULL,                   /* Initialize verification (not implemented) */
        .C_Verify = NULL,                       /* Verify signature (not implemented) */
        .C_VerifyUpdate = NULL,                 /* Continue multi-part verification (not implemented) */
        .C_VerifyFinal = NULL,                  /* Finish multi-part verification (not implemented) */
        .C_VerifyRecoverInit = NULL,            /* Init verify with data recovery (not implemented) */
        .C_VerifyRecover = NULL,                /* Verify with data recovery (not implemented) */
        
        /* =====================================================================
         * DUAL-FUNCTION CRYPTOGRAPHIC OPERATIONS
         * Combined operations for efficiency.
         * ===================================================================== */
        .C_DigestEncryptUpdate = NULL,          /* Digest + encrypt combined (not implemented) */
        .C_DecryptDigestUpdate = NULL,          /* Decrypt + digest combined (not implemented) */
        .C_SignEncryptUpdate = NULL,            /* Sign + encrypt combined (not implemented) */
        .C_DecryptVerifyUpdate = NULL,          /* Decrypt + verify combined (not implemented) */
        
        /* =====================================================================
         * KEY MANAGEMENT FUNCTIONS
         * Functions for key generation and key wrapping.
         * ===================================================================== */
        .C_GenerateKey = NULL,                  /* Generate symmetric key (not implemented) */
        .C_GenerateKeyPair = NULL,              /* Generate asymmetric key pair (not implemented) */
        .C_WrapKey = NULL,                      /* Wrap (encrypt) a key (not implemented) */
        .C_UnwrapKey = NULL,                    /* Unwrap (decrypt) a key (not implemented) */
        .C_DeriveKey = NULL,                    /* Derive a key from another (not implemented) */
        
        /* =====================================================================
         * RANDOM NUMBER GENERATION - OUR MAIN FEATURE!
         * ===================================================================== */
        .C_SeedRandom = C_SeedRandom,           /* Seed the RNG (no-op for HWRNG) */
        .C_GenerateRandom = C_GenerateRandom,   /* *** GENERATE RANDOM BYTES FROM TROPIC01 *** */
        
        /* =====================================================================
         * PARALLEL FUNCTION MANAGEMENT (DEPRECATED)
         * Legacy functions, rarely used.
         * ===================================================================== */
        .C_GetFunctionStatus = NULL,            /* Get parallel operation status (deprecated) */
        .C_CancelFunction = NULL,               /* Cancel parallel operation (deprecated) */
        .C_WaitForSlotEvent = NULL,             /* Wait for slot events (not implemented) */
    };
    
    /* Return pointer to our function list */
    *ppFunctionList = &functionList;
    
    /* Log some info about the function pointers (for debugging) */
    LOG(">>> C_GetFunctionList OK (function list returned at %p)", *ppFunctionList);
    LOG(">>> Function pointers: C_Initialize=%p, C_Finalize=%p, C_GetInfo=%p", 
        functionList.C_Initialize, functionList.C_Finalize, functionList.C_GetInfo);
    LOG(">>> Function pointers: C_OpenSession=%p, C_CloseSession=%p, C_CloseAllSessions=%p",
        functionList.C_OpenSession, functionList.C_CloseSession, functionList.C_CloseAllSessions);
    LOG(">>> Actual function: C_OpenSession=%p", C_OpenSession);
    
    return CKR_OK;
}

/* End of pkcs11.c */

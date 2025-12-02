/**
 * @file pkcs11.c
 * @brief PKCS#11 Module for TROPIC01 Secure Element
 * @copyright Copyright (c) 2020-2025 Tropic Square s.r.o.
 *
 * @license For the license see file LICENSE.md file in the root directory of this source tree.
 **/

 #include "pkcs11.h"           /* PKCS#11 type definitions (CK_RV, CK_INFO, etc.) */
 #include <stdio.h>            /* printf(), fflush() for debug output */
 #include <string.h>           /* strncpy(), memset() for string/memory operations */
 #include <stdlib.h>           /* exit() */
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
  * PAIRING KEYS - External declaration
  * ==================================================================================
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
 
/* ==================================================================================
 * GLOBAL STATE - Context Structure
 * ==================================================================================
 * 
 * PKCS#11 requires tracking library and session state across function calls.
 * All global state is wrapped in a single context structure for better organization.
 * 
 * initialized: Whether C_Initialize() has been called
 * session_open: Whether a secure session is active (C_OpenSession called)
 * lt_handle: The libtropic handle - persists between function calls
 * lt_device: USB device configuration - persists between function calls
 * session_handle: The current session handle returned by C_OpenSession
 */
typedef struct {
    CK_BBOOL initialized;                   /* Whether library is initialized */
    CK_BBOOL session_open;                  /* Whether a session is open */
    lt_handle_t lt_handle;                  /* libtropic handle */
    lt_dev_unix_usb_dongle_t lt_device;     /* USB device configuration */
    CK_SESSION_HANDLE session_handle;       /* Current session handle */
} lt_pkcs11_ctx_t;

/* Single global context instance */
static lt_pkcs11_ctx_t pkcs11_ctx = {
    .initialized = CK_FALSE,
    .session_open = CK_FALSE,
    .lt_handle = {0},
    .lt_device = {0},
    .session_handle = 0
};
 
 
 
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
 
 
 CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
     LT_PKCS11_LOG(">>> C_Initialize (pInitArgs=%p)", pInitArgs);
     
     /* Check if already initialized - PKCS#11 forbids double initialization */
     if (pkcs11_ctx.initialized) {
         LT_PKCS11_LOG(">>> Already initialized - returning CKR_CRYPTOKI_ALREADY_INITIALIZED");
         return CKR_CRYPTOKI_ALREADY_INITIALIZED;
     }
     
     /* =========================================================================
      * STEP 1: CONFIGURE USB DEVICE
      * =========================================================================
      * 
      * Set up the USB dongle configuration that will be used for all
      * communication with TROPIC01.
      * 
      * dev_path: The Linux device file for the USB serial port.
      *           Usually /dev/ttyACM0 for the first USB ACM device.
      *           May be different if multiple USB devices are connected.
      * 
      * baud_rate: Serial communication speed (115200 baud for TROPIC01)
      * 
      * rng_seed: Seed for software RNG (used as fallback, not for our HWRNG)
      */
     memset(&pkcs11_ctx.lt_device, 0, sizeof(pkcs11_ctx.lt_device));
     strncpy(pkcs11_ctx.lt_device.dev_path, "/dev/ttyACM0", sizeof(pkcs11_ctx.lt_device.dev_path) - 1);
     pkcs11_ctx.lt_device.baud_rate = 115200;
     pkcs11_ctx.lt_device.rng_seed = (unsigned int)time(NULL);
     
     LT_PKCS11_LOG(">>> USB device configured: %s @ %d baud", pkcs11_ctx.lt_device.dev_path, pkcs11_ctx.lt_device.baud_rate);
     
     /* =========================================================================
      * STEP 2: INITIALIZE LIBTROPIC HANDLE
      * =========================================================================
      * 
      * Attach device config to the handle's L2 (Layer 2) structure.
      * 
      * libtropic uses a layered architecture:
      * - L1: Physical layer (SPI, UART)
      * - L2: Frame layer (packet framing, CRC)
      * - L3: Application layer (commands, responses)
      */
     memset(&pkcs11_ctx.lt_handle, 0, sizeof(pkcs11_ctx.lt_handle));
     pkcs11_ctx.lt_handle.l2.device = &pkcs11_ctx.lt_device;
     
     /* =========================================================================
      * STEP 3: INITIALIZE COMMUNICATION WITH TROPIC01
      * =========================================================================
      * 
      * lt_init() performs:
      * - Opens the serial port
      * - Sends initial handshake to verify chip is responding
      * - Sets up communication buffers
      */
     LT_PKCS11_LOG(">>> Initializing libtropic handle...");
     lt_ret_t ret = lt_init(&pkcs11_ctx.lt_handle);
     if (ret != LT_OK) {
         LT_PKCS11_LOG(">>> Failed to initialize libtropic: %s", lt_ret_verbose(ret));
         return CKR_DEVICE_ERROR;
     }
     
     LT_PKCS11_LOG(">>> TROPIC01 communication initialized successfully");
     
     /* Mark as initialized */
     pkcs11_ctx.initialized = CK_TRUE;
     pkcs11_ctx.session_open = CK_FALSE;
     pkcs11_ctx.session_handle = 0;
     
     LT_PKCS11_LOG(">>> C_Initialize OK");
     return CKR_OK;
 }
 
 
 CK_RV C_Finalize(CK_VOID_PTR pReserved) {
     LT_PKCS11_LOG(">>> C_Finalize (pReserved=%p)", pReserved);
     
     /* Can't finalize if not initialized */
     if (!pkcs11_ctx.initialized) {
         LT_PKCS11_LOG(">>> Not initialized - returning CKR_CRYPTOKI_NOT_INITIALIZED");
         return CKR_CRYPTOKI_NOT_INITIALIZED;
     }
     
     /* =========================================================================
      * STEP 1: CLOSE SECURE SESSION IF OPEN
      * =========================================================================
      * 
      * If a secure session is still active, abort it first.
      * This ensures clean shutdown even if C_CloseSession wasn't called.
      */
     if (pkcs11_ctx.session_open) {
         LT_PKCS11_LOG(">>> Aborting open secure session...");
         lt_ret_t ret = lt_session_abort(&pkcs11_ctx.lt_handle);
         if (ret != LT_OK) {
             LT_PKCS11_LOG(">>> Warning: Failed to abort session: %s", lt_ret_verbose(ret));
             /* Continue with finalization anyway */
         }
         pkcs11_ctx.session_open = CK_FALSE;
         pkcs11_ctx.session_handle = 0;
     }
     
     /* =========================================================================
      * STEP 2: DEINITIALIZE LIBTROPIC
      * =========================================================================
      * 
      * lt_deinit() performs:
      * - Closes the serial port
      * - Frees allocated buffers
      * - Resets handle state
      */
     LT_PKCS11_LOG(">>> Deinitializing libtropic...");
     lt_ret_t ret = lt_deinit(&pkcs11_ctx.lt_handle);
     if (ret != LT_OK) {
         LT_PKCS11_LOG(">>> Warning: Failed to deinitialize libtropic: %s", lt_ret_verbose(ret));
         /* Continue with finalization anyway */
     }
     
     /* Clear global state */
     memset(&pkcs11_ctx.lt_handle, 0, sizeof(pkcs11_ctx.lt_handle));
     memset(&pkcs11_ctx.lt_device, 0, sizeof(pkcs11_ctx.lt_device));
     pkcs11_ctx.initialized = CK_FALSE;
     
     LT_PKCS11_LOG(">>> C_Finalize OK");
     return CKR_OK;
 }
 
 CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
     LT_PKCS11_LOG(">>> C_GetInfo (pInfo=%p)", pInfo);
     
     /* Validate parameter */
     if (!pInfo) {
         LT_PKCS11_LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
 
     /* 
      * If the library is initialized, read chip info using the global handle.
      * This does NOT require a secure session - chip freely provides this info.
      */
     if (pkcs11_ctx.initialized) {
         LT_PKCS11_LOG(">>> Reading TROPIC01 chip info...");
         
         /* Read RISC-V firmware version
          * 
          * TROPIC01 has a RISC-V processor running application firmware.
          * Version format: major.minor.patch.build (stored in reverse order)
          */
         uint8_t fw_ver[4] = {0};
         lt_ret_t ret = lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
         if (ret == LT_OK) {
             LT_PKCS11_LOG(">>> RISC-V FW version: %d.%d.%d.%d", fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
         } else {
             LT_PKCS11_LOG(">>> Failed to get RISC-V FW version: %s", lt_ret_verbose(ret));
         }
         
         /* Read SPECT firmware version
          * 
          * SPECT is the cryptographic coprocessor inside TROPIC01.
          * It handles all crypto operations (RNG, ECC, AES, etc.)
          */
         ret = lt_get_info_spect_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
         if (ret == LT_OK) {
             LT_PKCS11_LOG(">>> SPECT FW version: %d.%d.%d.%d", fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
         } else {
             LT_PKCS11_LOG(">>> Failed to get SPECT FW version: %s", lt_ret_verbose(ret));
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
         ret = lt_get_info_chip_id(&pkcs11_ctx.lt_handle, &chip_id);
         if (ret == LT_OK) {
             LT_PKCS11_LOG(">>> Chip ID:");
             lt_print_chip_id(&chip_id, printf);
         } else {
             LT_PKCS11_LOG(">>> Failed to get chip ID: %s", lt_ret_verbose(ret));
         }
     } else {
         LT_PKCS11_LOG(">>> Library not initialized - skipping chip info");
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
     
     LT_PKCS11_LOG(">>> C_GetInfo OK (version=%d.%d, manufacturer=TropicSquare)", 
         pInfo->cryptokiVersion.major, pInfo->cryptokiVersion.minor);
     return CKR_OK;
 }
 
 CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
     LT_PKCS11_LOG(">>> C_GetSlotList (tokenPresent=%d, pSlotList=%p, pulCount=%p)", 
         tokenPresent, pSlotList, pulCount);
     
     /* pulCount is required */
     if (!pulCount) {
         LT_PKCS11_LOG(">>> pulCount is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     if (!pSlotList) {
         /* Query mode: application wants to know how many slots exist */
         *pulCount = 1;  /* We have exactly one slot */
         LT_PKCS11_LOG(">>> Query mode: returning count=1");
     } else {
         /* Fill mode: application wants the actual slot IDs */
         if (*pulCount < 1) {
             /* Array too small to hold our slot */
             LT_PKCS11_LOG(">>> Buffer too small (pulCount=%lu) - returning CKR_BUFFER_TOO_SMALL", *pulCount);
             return CKR_BUFFER_TOO_SMALL;
         }
         pSlotList[0] = 1;   /* Our slot has ID 1 */
         *pulCount = 1;      /* We returned 1 slot */
         LT_PKCS11_LOG(">>> Filled slot list: slotID=1");
     }
     
     LT_PKCS11_LOG(">>> C_GetSlotList OK (count=%lu)", *pulCount);
     return CKR_OK;
 }
 
 CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
     LT_PKCS11_LOG(">>> C_GetSlotInfo (slotID=%lu, pInfo=%p)", slotID, pInfo);
     
     /* We only support slot ID 1 */
     if (slotID != 1) { 
         LT_PKCS11_LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
         return CKR_SLOT_ID_INVALID;
     }
     
     /* pInfo is required */
     if (!pInfo) {
         LT_PKCS11_LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* Fill in slot information */
     memset(pInfo, 0, sizeof(CK_SLOT_INFO));
     strncpy((char*)pInfo->slotDescription, "TROPIC01 Secure Element USB Slot", 64);
     strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
     pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
     
     /* Read firmware version from chip if initialized */
     if (pkcs11_ctx.initialized) {
         uint8_t fw_ver[4] = {0};
         lt_ret_t ret = lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
         if (ret == LT_OK) {
             /* firmwareVersion: RISC-V FW (major.minor) */
             pInfo->firmwareVersion.major = fw_ver[3];
             pInfo->firmwareVersion.minor = fw_ver[2];
         }
         /* hardwareVersion: Use SPECT FW as hardware indicator */
         ret = lt_get_info_spect_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
         if (ret == LT_OK) {
             pInfo->hardwareVersion.major = fw_ver[3];
             pInfo->hardwareVersion.minor = fw_ver[2];
         }
     }
     
     LT_PKCS11_LOG(">>> C_GetSlotInfo OK (description='TROPIC01 Secure Element USB Slot', HW=%d.%d, FW=%d.%d)",
         pInfo->hardwareVersion.major, pInfo->hardwareVersion.minor,
         pInfo->firmwareVersion.major, pInfo->firmwareVersion.minor);
     return CKR_OK;
 }
 
 CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
     LT_PKCS11_LOG(">>> C_GetTokenInfo (slotID=%lu, pInfo=%p)", slotID, pInfo);
     
     /* We only support slot ID 1 */
     if (slotID != 1) { 
         LT_PKCS11_LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
         return CKR_SLOT_ID_INVALID;
     }
     
     /* pInfo is required */
     if (!pInfo) {
         LT_PKCS11_LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* Fill in token information */
     memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
     
     /* Manufacturer is always TropicSquare */
     strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
     
     /* Token capabilities */
     pInfo->flags = CKF_RNG;  /* This token has a hardware RNG! */
     
     /* Session limits */
     pInfo->ulMaxSessionCount = 1;      /* We support only one session at a time */
     pInfo->ulSessionCount = pkcs11_ctx.session_open ? 1 : 0;
     pInfo->ulMaxRwSessionCount = 1;
     pInfo->ulRwSessionCount = pkcs11_ctx.session_open ? 1 : 0;
     
     /* PIN is not used - we use pairing keys instead */
     pInfo->ulMaxPinLen = 0;
     pInfo->ulMinPinLen = 0;
     
     /* Memory info - we report unknown */
     pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
     pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
     pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
     pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
     
     /* Read chip info and populate dynamic fields */
     if (pkcs11_ctx.initialized) {
         /* Get firmware versions */
         uint8_t fw_ver[4] = {0};
         lt_ret_t ret = lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
         if (ret == LT_OK) {
             pInfo->firmwareVersion.major = fw_ver[3];
             pInfo->firmwareVersion.minor = fw_ver[2];
         }
         
         /* Get chip ID for label, model, serial number, etc. */
         struct lt_chip_id_t chip_id = {0};
         ret = lt_get_info_chip_id(&pkcs11_ctx.lt_handle, &chip_id);
         if (ret == LT_OK) {
             /* Hardware version from chip_id_ver array [major.minor.patch.build] */
             pInfo->hardwareVersion.major = chip_id.chip_id_ver[0];
             pInfo->hardwareVersion.minor = chip_id.chip_id_ver[1];
             
             /* Model from part_num_data (ASCII string with length prefix) */
             /* part_num_data contains something like "TR01-C2P-T101" prefixed with length byte */
             if (chip_id.part_num_data[0] > 0 && chip_id.part_num_data[0] < 16) {
                 uint8_t model_len = chip_id.part_num_data[0];
                 if (model_len > 15) model_len = 15;
                 memcpy(pInfo->model, &chip_id.part_num_data[1], model_len);
                 pInfo->model[model_len] = '\0';
             } else {
                 strncpy((char*)pInfo->model, "TROPIC01", 16);
             }
             
            /* Serial number from batch_id + lot_id (unique per chip) */
            /* Note: 7 bytes = 14 hex chars + null terminator = 15 bytes, fits in 16-byte field */
            snprintf((char*)pInfo->serialNumber, 16, "%02X%02X%02X%02X%02X%02X%02X",
                chip_id.batch_id[0], chip_id.batch_id[1], chip_id.batch_id[2],
                chip_id.batch_id[3], chip_id.batch_id[4],
                chip_id.ser_num.lot_id[0], chip_id.ser_num.lot_id[1]);
             
             /* Label: Model + last 4 hex chars of serial for uniqueness */
             /* e.g., "TR01-C2P-T101-048D" */
             if (pInfo->model[0] != '\0') {
                 snprintf((char*)pInfo->label, 32, "%s-%02X%02X",
                     pInfo->model,
                     chip_id.ser_num.lot_id[1], chip_id.ser_num.lot_id[2]);
             } else {
                 strncpy((char*)pInfo->label, "TROPIC01", 32);
             }
         } else {
             /* Fallback if chip_id read fails */
             strncpy((char*)pInfo->label, "TROPIC01", 32);
             strncpy((char*)pInfo->model, "TROPIC01", 16);
             strncpy((char*)pInfo->serialNumber, "0000000000000000", 16);
         }
     } else {
         /* Fallback if not initialized */
         strncpy((char*)pInfo->label, "TROPIC01", 32);
         strncpy((char*)pInfo->model, "TROPIC01", 16);
         strncpy((char*)pInfo->serialNumber, "0000000000000000", 16);
     }
     
     LT_PKCS11_LOG(">>> C_GetTokenInfo OK (label='%.32s', model='%.16s', serial='%.16s', HW=%d.%d, FW=%d.%d)",
         pInfo->label, pInfo->model, pInfo->serialNumber,
         pInfo->hardwareVersion.major, pInfo->hardwareVersion.minor,
         pInfo->firmwareVersion.major, pInfo->firmwareVersion.minor);
     return CKR_OK;
 }
 
 CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                     CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
     LT_PKCS11_LOG(">>> C_OpenSession (slotID=%lu, flags=0x%lx, pApplication=%p, Notify=%p, phSession=%p)", 
         slotID, flags, pApplication, Notify, phSession);
     
     /* Library must be initialized first */
     if (!pkcs11_ctx.initialized) {
         LT_PKCS11_LOG(">>> Library not initialized - returning CKR_CRYPTOKI_NOT_INITIALIZED");
         return CKR_CRYPTOKI_NOT_INITIALIZED;
     }
     
     /* We only support slot ID 1 */
     if (slotID != 1) {
         LT_PKCS11_LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
         return CKR_SLOT_ID_INVALID;
     }
     
     /* phSession is required - we need somewhere to return the handle */
     if (!phSession) {
         LT_PKCS11_LOG(">>> phSession is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* Check if session is already open - we only support one session at a time */
     if (pkcs11_ctx.session_open) {
         LT_PKCS11_LOG(">>> Session already open - returning existing session handle");
         *phSession = pkcs11_ctx.session_handle;
         return CKR_OK;
     }
     
     /* =========================================================================
      * ESTABLISH SECURE SESSION WITH TROPIC01
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
      * - pkcs11_ctx.lt_handle: Our global handle
      * - sh0priv: Our X25519 private key (32 bytes)
      * - sh0pub: Chip's X25519 public key (32 bytes)
      * - TR01_PAIRING_KEY_SLOT_INDEX_0: Which key slot to use (0-3)
      * 
      * Key slots have different access permissions - slot 0 typically has
      * full access, while others may be restricted.
      */
     LT_PKCS11_LOG(">>> Starting Secure Session with key slot %d", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
     lt_ret_t ret = lt_verify_chip_and_start_secure_session(&pkcs11_ctx.lt_handle, sh0priv, sh0pub, TR01_PAIRING_KEY_SLOT_INDEX_0);
     if (ret != LT_OK) {
         LT_PKCS11_LOG(">>> Failed to start Secure Session: %s", lt_ret_verbose(ret));
         return CKR_DEVICE_ERROR;
     }
     
     LT_PKCS11_LOG(">>> Secure session established successfully");
     
     /* Generate a session handle and mark session as open */
     pkcs11_ctx.session_handle = 0x12345678;  /* Fixed handle for simplicity */
     pkcs11_ctx.session_open = CK_TRUE;
     *phSession = pkcs11_ctx.session_handle;
     
     LT_PKCS11_LOG(">>> C_OpenSession OK (session=0x%lx)", *phSession);
     return CKR_OK;
 }
 
 CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
     LT_PKCS11_LOG(">>> C_CloseSession (hSession=0x%lx)", hSession);
     
     /* Library must be initialized */
     if (!pkcs11_ctx.initialized) {
         LT_PKCS11_LOG(">>> Library not initialized - returning CKR_CRYPTOKI_NOT_INITIALIZED");
         return CKR_CRYPTOKI_NOT_INITIALIZED;
     }
     
     /* Check if session is open */
     if (!pkcs11_ctx.session_open) {
         LT_PKCS11_LOG(">>> No session open - returning CKR_SESSION_HANDLE_INVALID");
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* Verify session handle matches */
     if (hSession != pkcs11_ctx.session_handle) {
         LT_PKCS11_LOG(">>> Invalid session handle 0x%lx (expected 0x%lx) - returning CKR_SESSION_HANDLE_INVALID", 
             hSession, pkcs11_ctx.session_handle);
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* =========================================================================
      * ABORT SECURE SESSION
      * =========================================================================
      * 
      * lt_session_abort() performs:
      * - Notifies the chip that we're done
      * - Clears session keys from memory
      * - Allows new sessions to be established
      */
     LT_PKCS11_LOG(">>> Aborting Secure Session...");
     lt_ret_t ret = lt_session_abort(&pkcs11_ctx.lt_handle);
     if (ret != LT_OK) {
         LT_PKCS11_LOG(">>> Warning: Failed to abort Secure Session: %s", lt_ret_verbose(ret));
         /* Continue anyway - mark session as closed */
     }
     
     /* Mark session as closed */
     pkcs11_ctx.session_open = CK_FALSE;
     pkcs11_ctx.session_handle = 0;
     
     LT_PKCS11_LOG(">>> C_CloseSession OK");
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
 
 CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
     LT_PKCS11_LOG(">>> C_GenerateRandom (hSession=0x%lx, pRandomData=%p, ulRandomLen=%lu)", 
         hSession, pRandomData, ulRandomLen);
     
     /* =========================================================================
      * STEP 1: VALIDATE STATE AND PARAMETERS
      * =========================================================================
      */
     
     /* Library must be initialized */
     if (!pkcs11_ctx.initialized) {
         LT_PKCS11_LOG(">>> Library not initialized - returning CKR_CRYPTOKI_NOT_INITIALIZED");
         return CKR_CRYPTOKI_NOT_INITIALIZED;
     }
     
     /* Session must be open (secure session established) */
     if (!pkcs11_ctx.session_open) {
         LT_PKCS11_LOG(">>> No session open - returning CKR_SESSION_HANDLE_INVALID");
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* Verify session handle */
     if (hSession != pkcs11_ctx.session_handle) {
         LT_PKCS11_LOG(">>> Invalid session handle 0x%lx (expected 0x%lx) - returning CKR_SESSION_HANDLE_INVALID", 
             hSession, pkcs11_ctx.session_handle);
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* Validate output buffer */
     if (!pRandomData) {
         LT_PKCS11_LOG(">>> pRandomData is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     if (ulRandomLen == 0) {
         LT_PKCS11_LOG(">>> ulRandomLen is 0 - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* =========================================================================
      * STEP 2: GET RANDOM BYTES FROM HARDWARE RNG
      * =========================================================================
      * 
      * TROPIC01 can return maximum 255 bytes per request (TR01_RANDOM_VALUE_GET_LEN_MAX).
      * For larger requests, we need to make multiple calls and accumulate the data.
      * 
      * The hardware RNG uses:
      * - True random noise sources (thermal noise)
      * - On-chip entropy conditioning
      * - NIST SP 800-90B compliant design
      * 
      * The secure session was already established in C_OpenSession, so we can
      * directly request random bytes here.
      */
     CK_ULONG remaining = ulRandomLen;   /* How many bytes we still need */
     CK_BYTE_PTR ptr = pRandomData;      /* Where to write next bytes */
     
     while (remaining > 0) {
         /* Calculate chunk size: either remaining bytes or max allowed, whichever is smaller */
         uint16_t chunk_size = (remaining > TR01_RANDOM_VALUE_GET_LEN_MAX) ? 
                               TR01_RANDOM_VALUE_GET_LEN_MAX : (uint16_t)remaining;
         
         /* Request random bytes from the chip */
         lt_ret_t ret = lt_random_value_get(&pkcs11_ctx.lt_handle, ptr, chunk_size);
         if (ret != LT_OK) {
             LT_PKCS11_LOG(">>> Failed to get random bytes: %s", lt_ret_verbose(ret));
             return CKR_DEVICE_ERROR;
         }
         
         /* Move pointer forward and decrease remaining count */
         ptr += chunk_size;
         remaining -= chunk_size;
     }
     
     /* =========================================================================
      * STEP 3: DEBUG OUTPUT - PRINT RANDOM BYTES IN HEX
      * =========================================================================
      * 
      * Print the generated random bytes for verification.
      * Format: 0xAA, 0xBB, 0xCC, ...
      * 
      * NOTE: Remove this for production use - it pollutes stdout.
      */
     LT_PKCS11_LOG(">>> Random bytes (%lu bytes):", ulRandomLen);
     for (CK_ULONG i = 0; i < ulRandomLen; i++) {
         LT_PKCS11_LOG("0x%02X", pRandomData[i]);
     }
     
     LT_PKCS11_LOG(">>> C_GenerateRandom OK (generated %lu bytes from TROPIC01 hardware RNG)", ulRandomLen);
     return CKR_OK;
 }
 
 CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
     LT_PKCS11_LOG(">>> C_SeedRandom (hSession=0x%lx, pSeed=%p, ulSeedLen=%lu)", 
         hSession, pSeed, ulSeedLen);
     
     /* Validate parameters */
     if (!pSeed) {
         LT_PKCS11_LOG(">>> pSeed is NULL - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     if (ulSeedLen == 0) {
         LT_PKCS11_LOG(">>> ulSeedLen is 0 - returning CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* Accept the seed but do nothing - HWRNG doesn't need external seeding */
     LT_PKCS11_LOG(">>> C_SeedRandom OK (seeded with %lu bytes)", ulSeedLen);
     return CKR_OK;
 }
 
 CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
     LT_PKCS11_LOG("========================================");
     LT_PKCS11_LOG(">>> C_GetFunctionList (ppFunctionList=%p)", ppFunctionList);
     LT_PKCS11_LOG(">>> LOADING TROPIC PKCS#11 LIBRARY");
     LT_PKCS11_LOG("========================================");
     
     /* Validate parameter */
     if (!ppFunctionList) {
         LT_PKCS11_LOG(">>> ppFunctionList is NULL - returning CKR_ARGUMENTS_BAD");
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
     LT_PKCS11_LOG(">>> C_GetFunctionList OK (function list returned at %p)", *ppFunctionList);
     LT_PKCS11_LOG(">>> Function pointers: C_Initialize=%p, C_Finalize=%p, C_GetInfo=%p", 
         functionList.C_Initialize, functionList.C_Finalize, functionList.C_GetInfo);
     LT_PKCS11_LOG(">>> Function pointers: C_OpenSession=%p, C_CloseSession=%p, C_CloseAllSessions=%p",
         functionList.C_OpenSession, functionList.C_CloseSession, functionList.C_CloseAllSessions);
     LT_PKCS11_LOG(">>> Actual function: C_OpenSession=%p", C_OpenSession);
     
     return CKR_OK;
 }
 
 /* End of pkcs11.c */
 
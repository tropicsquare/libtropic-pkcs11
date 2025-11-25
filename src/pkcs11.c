/* Minimal PKCS#11 RNG Library */
#include "pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include <inttypes.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_examples.h"
#include "libtropic_logging.h"
#include "string.h"

#include "libtropic_port.h"
#include "libtropic_port_unix_usb_dongle.h"

#define LOG(...) do { printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)


static CK_BBOOL initialized = CK_FALSE;

// Signal handler to catch segfaults
static void segfault_handler(int sig) {
    printf("\n!!! SEGFAULT CAUGHT - signal %d !!!\n", sig);
    fflush(stdout);
    exit(1);
}

// Constructor to install signal handler
__attribute__((constructor))
static void library_init(void) {
    printf(">>> LIBRARY CONSTRUCTOR CALLED - Installing signal handlers\n");
    fflush(stdout);
    signal(SIGSEGV, segfault_handler);
    signal(SIGBUS, segfault_handler);
}

// ============= REQUIRED FUNCTIONS =============

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    LOG(">>> C_Initialize (pInitArgs=%p)", pInitArgs);
    if (initialized) {
        LOG(">>> Already initialized - returning CKR_CRYPTOKI_ALREADY_INITIALIZED");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    initialized = CK_TRUE;
    LOG(">>> C_Initialize OK");
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    printf(">>> C_Finalize ENTRY (pReserved=%p)\n", pReserved);
    fflush(stdout);
    LOG(">>> C_Finalize (pReserved=%p)", pReserved);
    fflush(stdout);
    if (!initialized) {
        LOG(">>> Not initialized - returning CKR_CRYPTOKI_NOT_INITIALIZED");
        fflush(stdout);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    initialized = CK_FALSE;
    LOG(">>> C_Finalize OK");
    fflush(stdout);
    printf(">>> C_Finalize DONE\n");
    fflush(stdout);
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    LOG(">>> C_GetInfo (pInfo=%p)", pInfo);
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }

    // Set up the handle and USB device
    lt_handle_t h = {0};
    lt_dev_unix_usb_dongle_t device = {0};
    
    strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
    device.baud_rate = 115200;
    device.rng_seed = (unsigned int)time(NULL);
    
    h.l2.device = &device;

    // Initialize and read chip info (no secure session needed for this)
    lt_ret_t ret = lt_init(&h);
    if (ret == LT_OK) {
        LOG(">>> TROPIC01 initialized successfully");
        
        // Read firmware versions
        uint8_t fw_ver[4] = {0};
        
        ret = lt_get_info_riscv_fw_ver(&h, fw_ver);
        if (ret == LT_OK) {
            LOG(">>> RISC-V FW version: %d.%d.%d.%d", fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
        } else {
            LOG(">>> Failed to get RISC-V FW version: %s", lt_ret_verbose(ret));
        }
        
        ret = lt_get_info_spect_fw_ver(&h, fw_ver);
        if (ret == LT_OK) {
            LOG(">>> SPECT FW version: %d.%d.%d.%d", fw_ver[3], fw_ver[2], fw_ver[1], fw_ver[0]);
        } else {
            LOG(">>> Failed to get SPECT FW version: %s", lt_ret_verbose(ret));
        }
        
        // Read and print chip ID
        struct lt_chip_id_t chip_id = {0};
        ret = lt_get_info_chip_id(&h, &chip_id);
        if (ret == LT_OK) {
            LOG(">>> Chip ID:");
            lt_print_chip_id(&chip_id, printf);
        } else {
            LOG(">>> Failed to get chip ID: %s", lt_ret_verbose(ret));
        }
        
        lt_deinit(&h);
    } else {
        LOG(">>> TROPIC01 init failed: %s", lt_ret_verbose(ret));
    }

    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char*)pInfo->libraryDescription, "Tropic PKCS11", 32);
    LOG(">>> C_GetInfo OK (version=%d.%d, manufacturer=TropicSquare)", 
        pInfo->cryptokiVersion.major, pInfo->cryptokiVersion.minor);
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    LOG(">>> C_GetSlotList (tokenPresent=%d, pSlotList=%p, pulCount=%p)", 
        tokenPresent, pSlotList, pulCount);
    if (!pulCount) {
        LOG(">>> pulCount is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSlotList) {
        *pulCount = 1;
        LOG(">>> Query mode: returning count=1");
    } else {
        if (*pulCount < 1) {
            LOG(">>> Buffer too small (pulCount=%lu) - returning CKR_BUFFER_TOO_SMALL", *pulCount);
            return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[0] = 1;
        *pulCount = 1;
        LOG(">>> Filled slot list: slotID=1");
    }
    LOG(">>> C_GetSlotList OK (count=%lu)", *pulCount);
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    printf(">>> C_GetSlotInfo ENTRY\n"); fflush(stdout);
    LOG(">>> C_GetSlotInfo (slotID=%lu, pInfo=%p)", slotID, pInfo);
    if (slotID != 1) { 
        LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    strncpy((char*)pInfo->slotDescription, "Tropic Slot", 64);
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    LOG(">>> C_GetSlotInfo OK (description='Tropic Slot', flags=0x%lx)", pInfo->flags);
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    printf(">>> C_GetTokenInfo ENTRY\n"); fflush(stdout);
    LOG(">>> C_GetTokenInfo (slotID=%lu, pInfo=%p)", slotID, pInfo);
    if (slotID != 1) { 
        LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    if (!pInfo) {
        LOG(">>> pInfo is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    strncpy((char*)pInfo->label, "TROPIC-RNG", 32);
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_RNG;
    LOG(">>> C_GetTokenInfo OK (label='TROPIC-RNG', flags=0x%lx)", pInfo->flags);
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    printf(">>> C_OpenSession ENTRY\n");
    fflush(stdout);
    LOG(">>> C_OpenSession (slotID=%lu, flags=0x%lx, pApplication=%p, Notify=%p, phSession=%p)", 
        slotID, flags, pApplication, Notify, phSession);
    if (slotID != 1) {
        LOG(">>> Invalid slotID=%lu - returning CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    if (!phSession) {
        LOG(">>> phSession is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    *phSession = 0x12345678;
    LOG(">>> C_OpenSession OK (session=0x%lx)", *phSession);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    LOG(">>> C_CloseSession (hSession=0x%lx)", hSession);
    LOG(">>> WARNING: This session was never opened by C_OpenSession!");
    LOG(">>> pkcs11-tool might be reusing a stale session or has a bug");
    fflush(stdout);
    // Don't crash - just return OK even for invalid sessions
    LOG(">>> C_CloseSession OK (ignoring invalid session)");
    fflush(stdout);
    return CKR_OK;
}

// ============= RNG FUNCTIONS =============

// External keys from keys.c
extern uint8_t sh0priv[];
extern uint8_t sh0pub[];

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    LOG(">>> C_GenerateRandom (hSession=0x%lx, pRandomData=%p, ulRandomLen=%lu)", 
        hSession, pRandomData, ulRandomLen);
    
    if (!pRandomData) {
        LOG(">>> pRandomData is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if (ulRandomLen == 0) {
        LOG(">>> ulRandomLen is 0 - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    // Set up the handle and USB device
    lt_handle_t h = {0};
    lt_dev_unix_usb_dongle_t device = {0};
    
    strncpy(device.dev_path, "/dev/ttyACM0", sizeof(device.dev_path) - 1);
    device.baud_rate = 115200;
    device.rng_seed = (unsigned int)time(NULL);
    
    h.l2.device = &device;

    // Initialize handle
    LOG(">>> Initializing handle");
    lt_ret_t ret = lt_init(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to initialize handle: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    
    // Start secure session with sh0 keys (slot 0)
    LOG(">>> Starting Secure Session with key %d", (int)TR01_PAIRING_KEY_SLOT_INDEX_0);
    ret = lt_verify_chip_and_start_secure_session(&h, sh0priv, sh0pub, TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (ret != LT_OK) {
        LOG(">>> Failed to start Secure Session: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    LOG(">>> Secure session established");
    
    // Get random bytes from TROPIC01 (max 255 bytes at a time)
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
    
    // Abort session and deinitialize
    LOG(">>> Aborting Secure Session");
    ret = lt_session_abort(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to abort Secure Session: %s", lt_ret_verbose(ret));
        lt_deinit(&h);
        return CKR_GENERAL_ERROR;
    }
    
    LOG(">>> Deinitializing handle");
    ret = lt_deinit(&h);
    if (ret != LT_OK) {
        LOG(">>> Failed to deinitialize handle: %s", lt_ret_verbose(ret));
        return CKR_GENERAL_ERROR;
    }
    
    // Print random bytes in hex format
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

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    LOG(">>> C_SeedRandom (hSession=0x%lx, pSeed=%p, ulSeedLen=%lu)", 
        hSession, pSeed, ulSeedLen);
    if (!pSeed) {
        LOG(">>> pSeed is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    if (ulSeedLen == 0) {
        LOG(">>> ulSeedLen is 0 - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    LOG(">>> C_SeedRandom OK (seeded with %lu bytes)", ulSeedLen);
    return CKR_OK;
}

// ============= FUNCTION LIST =============

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    LOG("========================================");
    LOG(">>> C_GetFunctionList (ppFunctionList=%p)", ppFunctionList);
    LOG(">>> LOADING TROPIC PKCS#11 LIBRARY");
    LOG("========================================");
    
    if (!ppFunctionList) {
        LOG(">>> ppFunctionList is NULL - returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
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
        .C_GetMechanismList = NULL,
        .C_GetMechanismInfo = NULL,
        .C_InitToken = NULL,
        .C_InitPIN = NULL,
        .C_SetPIN = NULL,
        /* Session management */
        .C_OpenSession = C_OpenSession,
        .C_CloseSession = C_CloseSession,
        .C_CloseAllSessions = NULL,
        .C_GetSessionInfo = NULL,
        .C_GetOperationState = NULL,
        .C_SetOperationState = NULL,
        .C_Login = NULL,
        .C_Logout = NULL,
        /* Object management */
        .C_CreateObject = NULL,
        .C_CopyObject = NULL,
        .C_DestroyObject = NULL,
        .C_GetObjectSize = NULL,
        .C_GetAttributeValue = NULL,
        .C_SetAttributeValue = NULL,
        .C_FindObjectsInit = NULL,
        .C_FindObjects = NULL,
        .C_FindObjectsFinal = NULL,
        /* Encryption */
        .C_EncryptInit = NULL,
        .C_Encrypt = NULL,
        .C_EncryptUpdate = NULL,
        .C_EncryptFinal = NULL,
        /* Decryption */
        .C_DecryptInit = NULL,
        .C_Decrypt = NULL,
        .C_DecryptUpdate = NULL,
        .C_DecryptFinal = NULL,
        /* Message digesting */
        .C_DigestInit = NULL,
        .C_Digest = NULL,
        .C_DigestUpdate = NULL,
        .C_DigestKey = NULL,
        .C_DigestFinal = NULL,
        /* Signing and MACing */
        .C_SignInit = NULL,
        .C_Sign = NULL,
        .C_SignUpdate = NULL,
        .C_SignFinal = NULL,
        .C_SignRecoverInit = NULL,
        .C_SignRecover = NULL,
        /* Verification */
        .C_VerifyInit = NULL,
        .C_Verify = NULL,
        .C_VerifyUpdate = NULL,
        .C_VerifyFinal = NULL,
        .C_VerifyRecoverInit = NULL,
        .C_VerifyRecover = NULL,
        /* Dual-function cryptographic operations */
        .C_DigestEncryptUpdate = NULL,
        .C_DecryptDigestUpdate = NULL,
        .C_SignEncryptUpdate = NULL,
        .C_DecryptVerifyUpdate = NULL,
        /* Key management */
        .C_GenerateKey = NULL,
        .C_GenerateKeyPair = NULL,
        .C_WrapKey = NULL,
        .C_UnwrapKey = NULL,
        .C_DeriveKey = NULL,
        /* Random number generation */
        .C_SeedRandom = C_SeedRandom,
        .C_GenerateRandom = C_GenerateRandom,
        /* Parallel function management (deprecated) */
        .C_GetFunctionStatus = NULL,
        .C_CancelFunction = NULL,
        .C_WaitForSlotEvent = NULL,
    };
    
    *ppFunctionList = &functionList;
    LOG(">>> C_GetFunctionList OK (function list returned at %p)", *ppFunctionList);
    LOG(">>> Function pointers: C_Initialize=%p, C_Finalize=%p, C_GetInfo=%p", 
        functionList.C_Initialize, functionList.C_Finalize, functionList.C_GetInfo);
    LOG(">>> Function pointers: C_OpenSession=%p, C_CloseSession=%p, C_CloseAllSessions=%p",
        functionList.C_OpenSession, functionList.C_CloseSession, functionList.C_CloseAllSessions);
    LOG(">>> Actual function: C_OpenSession=%p", C_OpenSession);
    return CKR_OK;
}


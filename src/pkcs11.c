/* Minimal PKCS#11 RNG Library */
#include "pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

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
    printf(">>> LIBRARY CONSTRUCTOR CALLED - Installing segfault handler\n");
    fflush(stdout);
    signal(SIGSEGV, segfault_handler);
}

// Stub for unimplemented functions - will catch unknown calls
static CK_RV not_supported(void) {
    printf(">>> STUB FUNCTION CALLED - returning CKR_FUNCTION_NOT_SUPPORTED\n");
    fflush(stdout);
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    
    // Generate dummy pattern
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        pRandomData[i] = (CK_BYTE)(i & 0xFF);
    }
    
    LOG(">>> C_GenerateRandom OK (generated %lu bytes)", ulRandomLen);
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

// ============= ADDITIONAL STUBS =============

// Add specific stubs that will show which function is being called
static CK_RV stub_GetMechanismList(void) {
    printf(">>> C_GetMechanismList STUB CALLED\n");
    fflush(stdout);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV stub_CloseAllSessions(void) {
    printf(">>> C_CloseAllSessions STUB CALLED\n");
    fflush(stdout);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV stub_GetSessionInfo(void) {
    printf(">>> C_GetSessionInfo STUB CALLED\n");
    fflush(stdout);
    return CKR_FUNCTION_NOT_SUPPORTED;
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
        {2, 40},  // version
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        (void*)stub_GetMechanismList,  // C_GetMechanismList
        (void*)not_supported,  // C_GetMechanismInfo
        (void*)not_supported,  // C_InitToken
        (void*)not_supported,  // C_InitPIN
        C_OpenSession,
        C_CloseSession,
        (void*)stub_CloseAllSessions,  // C_CloseAllSessions
        (void*)stub_GetSessionInfo,  // C_GetSessionInfo
        (void*)not_supported,  // C_GetOperationState
        (void*)not_supported,  // C_SetOperationState
        (void*)not_supported,  // C_Login
        (void*)not_supported,  // C_Logout
        (void*)not_supported,  // C_CreateObject
        (void*)not_supported,  // C_DestroyObject
        (void*)not_supported,  // C_GetAttributeValue
        (void*)not_supported,  // C_SetAttributeValue
        (void*)not_supported,  // C_FindObjectsInit
        (void*)not_supported,  // C_FindObjects
        (void*)not_supported,  // C_FindObjectsFinal
        (void*)not_supported,  // C_EncryptInit
        (void*)not_supported,  // C_Encrypt
        (void*)not_supported,  // C_EncryptUpdate
        (void*)not_supported,  // C_EncryptFinal
        (void*)not_supported,  // C_DecryptInit
        (void*)not_supported,  // C_Decrypt
        (void*)not_supported,  // C_DecryptUpdate
        (void*)not_supported,  // C_DecryptFinal
        (void*)not_supported,  // C_DigestInit
        (void*)not_supported,  // C_Digest
        (void*)not_supported,  // C_DigestUpdate
        (void*)not_supported,  // C_DigestKey
        (void*)not_supported,  // C_DigestFinal
        (void*)not_supported,  // C_SignInit
        (void*)not_supported,  // C_Sign
        (void*)not_supported,  // C_SignUpdate
        (void*)not_supported,  // C_SignFinal
        (void*)not_supported,  // C_SignRecoverInit
        (void*)not_supported,  // C_SignRecover
        (void*)not_supported,  // C_VerifyInit
        (void*)not_supported,  // C_Verify
        (void*)not_supported,  // C_VerifyUpdate
        (void*)not_supported,  // C_VerifyFinal
        (void*)not_supported,  // C_VerifyRecoverInit
        (void*)not_supported,  // C_VerifyRecover
        C_GenerateRandom,
        C_SeedRandom,
        (void*)not_supported,  // C_GenerateKeyPair
        (void*)not_supported,  // C_WrapKey
        (void*)not_supported,  // C_UnwrapKey
        (void*)not_supported   // C_DeriveKey
    };
    
    *ppFunctionList = &functionList;
    LOG(">>> C_GetFunctionList OK (function list returned at %p)", *ppFunctionList);
    LOG(">>> Function pointers: C_Initialize=%p, C_Finalize=%p, C_GetInfo=%p", 
        functionList.C_Initialize, functionList.C_Finalize, functionList.C_GetInfo);
    LOG(">>> Function pointers: C_CloseSession=%p, C_CloseAllSessions=%p",
        functionList.C_CloseSession, functionList.C_CloseAllSessions);
    return CKR_OK;
}



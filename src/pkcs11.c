/* Minimal PKCS#11 RNG Library */
#include "pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG(...) do { printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)

static CK_BBOOL initialized = CK_FALSE;

// Stub for unimplemented functions
static CK_RV not_supported(void) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// ============= REQUIRED FUNCTIONS =============

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    LOG(">>> C_Initialize");
    initialized = CK_TRUE;
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    LOG(">>> C_Finalize");
    initialized = CK_FALSE;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    LOG(">>> C_GetInfo");
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char*)pInfo->libraryDescription, "Tropic PKCS11", 32);
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    LOG(">>> C_GetSlotList");
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (!pSlotList) {
        *pulCount = 1;
    } else {
        if (*pulCount < 1) return CKR_BUFFER_TOO_SMALL;
        pSlotList[0] = 1;
        *pulCount = 1;
    }
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    LOG(">>> C_GetSlotInfo");
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    strncpy((char*)pInfo->slotDescription, "Tropic Slot", 64);
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    LOG(">>> C_GetTokenInfo");
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    strncpy((char*)pInfo->label, "TROPIC-RNG", 32);
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_RNG;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, 
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    LOG(">>> C_OpenSession");
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    *phSession = 0x12345678;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    LOG(">>> C_CloseSession");
    return CKR_OK;
}

// ============= RNG FUNCTIONS =============

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    LOG(">>> C_GenerateRandom: %lu bytes", ulRandomLen);
    if (!pRandomData) return CKR_ARGUMENTS_BAD;
    
    // Generate dummy pattern
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        pRandomData[i] = (CK_BYTE)(i & 0xFF);
    }
    
    return CKR_OK;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    LOG(">>> C_SeedRandom: %lu bytes", ulSeedLen);
    return CKR_OK;
}

// ============= FUNCTION LIST =============

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    LOG("========================================");
    LOG(">>> C_GetFunctionList - LOADING LIBRARY");
    LOG("========================================");
    
    static CK_FUNCTION_LIST functionList = {
        {2, 40},  // version
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        (void*)not_supported,  // C_GetMechanismList
        (void*)not_supported,  // C_GetMechanismInfo
        (void*)not_supported,  // C_InitToken
        (void*)not_supported,  // C_InitPIN
        C_OpenSession,
        C_CloseSession,
        (void*)not_supported,  // C_CloseAllSessions
        (void*)not_supported,  // C_GetSessionInfo
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
    
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &functionList;
    return CKR_OK;
}



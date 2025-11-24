#include "pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// CRITICAL: Add fflush after printf to see output immediately
#define LOG(msg, ...) do { printf(msg "\n", ##__VA_ARGS__); fflush(stdout); } while(0)

// Minimal state
static CK_BBOOL initialized = CK_FALSE;

// PKCS#11 Function Implementations
CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    LOG(">>> C_Initialize CALLED <<<");
    initialized = CK_TRUE;
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    LOG(">>> C_Finalize CALLED <<<");
    initialized = CK_FALSE;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    LOG(">>> C_GetInfo CALLED <<<");
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    
    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char*)pInfo->libraryDescription, "Tropic PKCS11", 32);
    
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    LOG(">>> C_GetSlotList CALLED (tokenPresent=%d) <<<", tokenPresent);
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    
    if (pSlotList == NULL) {
        *pulCount = 1; // We have 1 slot
    } else {
        if (*pulCount < 1) return CKR_BUFFER_TOO_SMALL;
        pSlotList[0] = 1; // Slot ID = 1
        *pulCount = 1;
    }
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    LOG(">>> C_GetSlotInfo CALLED (slotID=%lu) <<<", slotID);
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    strncpy((char*)pInfo->slotDescription, "Tropic Slot 1", 64);
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    LOG(">>> C_GetTokenInfo CALLED (slotID=%lu) <<<", slotID);
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    strncpy((char*)pInfo->label, "TROPIC-TOKEN", 32);
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    LOG(">>> C_OpenSession CALLED (slotID=%lu, flags=0x%lx) <<<", slotID, flags);
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    
    *phSession = 0x12345678; // Dummy session handle
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    LOG(">>> C_CloseSession CALLED (session=0x%lx) <<<", hSession);
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    LOG(">>> C_Login CALLED (session=0x%lx, userType=%lu) <<<", hSession, userType);
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    LOG(">>> C_Logout CALLED (session=0x%lx) <<<", hSession);
    return CKR_OK;
}

// RNG Functions - THE IMPORTANT ONES!
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    LOG(">>> C_SeedRandom CALLED (session=0x%lx, seedLen=%lu) <<<", hSession, ulSeedLen);
    return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    LOG(">>> C_GenerateRandom CALLED (session=0x%lx, length=%lu) <<<", hSession, ulRandomLen);
    
    if (!pRandomData) return CKR_ARGUMENTS_BAD;
    
    // Generate dummy random data (just a pattern for testing)
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        pRandomData[i] = (CK_BYTE)(i & 0xFF);
    }
    
    LOG(">>> C_GenerateRandom: Generated %lu bytes <<<", ulRandomLen);
    return CKR_OK;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    LOG(">>> C_GenerateKeyPair CALLED <<<");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    LOG(">>> C_SignInit CALLED <<<");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    LOG(">>> C_Sign CALLED <<<");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// Stub implementations for other required functions
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    LOG(">>> C_GetMechanismList CALLED <<<");
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    *pulCount = 0; // No mechanisms supported yet
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    LOG(">>> C_GetMechanismInfo CALLED <<<");
    return CKR_MECHANISM_INVALID;
}

// CRITICAL: C_GetFunctionList - Entry point for PKCS#11 provider
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    LOG("========================================");
    LOG(">>> C_GetFunctionList CALLED <<<");
    LOG(">>> YOUR PKCS11 LIBRARY IS LOADING <<<");
    LOG("========================================");
    
    static CK_FUNCTION_LIST functionList = {
        {2, 40}, // version
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        C_GetMechanismList,
        C_GetMechanismInfo,
        NULL, // C_InitToken
        NULL, // C_InitPIN
        C_OpenSession,
        C_CloseSession,
        NULL, // C_CloseAllSessions
        NULL, // C_GetSessionInfo
        NULL, // C_GetOperationState
        NULL, // C_SetOperationState
        C_Login,
        C_Logout,
        NULL, // C_CreateObject
        NULL, // C_DestroyObject
        NULL, // C_GetAttributeValue
        NULL, // C_SetAttributeValue
        NULL, // C_FindObjectsInit
        NULL, // C_FindObjects
        NULL, // C_FindObjectsFinal
        NULL, // C_EncryptInit
        NULL, // C_Encrypt
        NULL, // C_EncryptUpdate
        NULL, // C_EncryptFinal
        NULL, // C_DecryptInit
        NULL, // C_Decrypt
        NULL, // C_DecryptUpdate
        NULL, // C_DecryptFinal
        NULL, // C_DigestInit
        NULL, // C_Digest
        NULL, // C_DigestUpdate
        NULL, // C_DigestKey
        NULL, // C_DigestFinal
        C_SignInit,
        C_Sign,
        NULL, // C_SignUpdate
        NULL, // C_SignFinal
        NULL, // C_SignRecoverInit
        NULL, // C_SignRecover
        NULL, // C_VerifyInit
        NULL, // C_Verify
        NULL, // C_VerifyUpdate
        NULL, // C_VerifyFinal
        NULL, // C_VerifyRecoverInit
        NULL, // C_VerifyRecover
        C_GenerateRandom,
        C_SeedRandom,
        C_GenerateKeyPair,
        NULL, // C_WrapKey
        NULL, // C_UnwrapKey
        NULL  // C_DeriveKey
    };
    
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    
    *ppFunctionList = &functionList;
    return CKR_OK;
}
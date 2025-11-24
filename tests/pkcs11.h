/* pkcs11.h
 * Simplified PKCS#11 header focusing on ECDSA operations
 */

 #ifndef _PKCS11_H_
 #define _PKCS11_H_
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 /* PKCS#11 Version */
 #define CRYPTOKI_VERSION_MAJOR 2
 #define CRYPTOKI_VERSION_MINOR 40
 
/* Basic Types */
typedef unsigned char     CK_BYTE;
typedef unsigned char     CK_CHAR;
typedef unsigned char     CK_UTF8CHAR;
typedef unsigned char     CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int          CK_LONG;
typedef CK_ULONG          CK_FLAGS;
typedef CK_ULONG          CK_RV;
typedef CK_ULONG          CK_SLOT_ID;
typedef CK_ULONG          CK_SESSION_HANDLE;
typedef CK_ULONG          CK_OBJECT_HANDLE;
typedef CK_ULONG          CK_USER_TYPE;
typedef CK_ULONG          CK_MECHANISM_TYPE;
typedef void*             CK_VOID_PTR;
typedef CK_BYTE*          CK_BYTE_PTR;
typedef CK_CHAR*          CK_CHAR_PTR;
typedef CK_UTF8CHAR*      CK_UTF8CHAR_PTR;
typedef CK_ULONG*         CK_ULONG_PTR;
typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR;
typedef void*             CK_MECHANISM_INFO_PTR;
 
 /* Notification Types */
 typedef CK_ULONG CK_NOTIFICATION;
 typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE session, CK_NOTIFICATION event, CK_VOID_PTR application);
 
 /* Object Classes */
 typedef CK_ULONG CK_OBJECT_CLASS;
 #define CKO_DATA            0x00000000
 #define CKO_CERTIFICATE     0x00000001
 #define CKO_PUBLIC_KEY      0x00000002
 #define CKO_PRIVATE_KEY     0x00000003
 #define CKO_SECRET_KEY      0x00000004
 #define CKO_VENDOR_DEFINED  0x80000000
 
 /* Key Types */
 typedef CK_ULONG CK_KEY_TYPE;
 #define CKK_RSA             0x00000000
 #define CKK_DSA             0x00000001
 #define CKK_DH              0x00000002
 #define CKK_EC              0x00000003
 #define CKK_VENDOR_DEFINED  0x80000000
 
 /* User types */
 #define CKU_SO              0UL
 #define CKU_USER            1UL
 #define CKU_CONTEXT_SPECIFIC 2UL
 
 /* Constants */
 #define CK_TRUE  1
 #define CK_FALSE 0
 
/* Return Values */
#define CKR_OK                                  0x00000000
#define CKR_GENERAL_ERROR                       0x00000005
#define CKR_ARGUMENTS_BAD                       0x00000007
#define CKR_HOST_MEMORY                         0x00000002
#define CKR_SLOT_ID_INVALID                     0x00000003
#define CKR_TOKEN_NOT_PRESENT                   0x000000E0
#define CKR_SESSION_HANDLE_INVALID              0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED      0x000000B4
#define CKR_SESSION_COUNT                       0x000000B1
#define CKR_USER_NOT_LOGGED_IN                  0x00000101
#define CKR_KEY_HANDLE_INVALID                  0x00000060
#define CKR_KEY_TYPE_INCONSISTENT               0x00000063
#define CKR_MECHANISM_INVALID                   0x00000070
#define CKR_BUFFER_TOO_SMALL                    0x00000150
#define CKR_SIGNATURE_INVALID                   0x000000C0
#define CKR_FUNCTION_NOT_SUPPORTED              0x00000054
#define CKR_CRYPTOKI_NOT_INITIALIZED            0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED        0x00000191
#define CKR_VENDOR_DEFINED                      0x80000000
 
 /* Mechanisms */
 #define CKM_EC_KEY_PAIR_GEN                     0x00001040
 #define CKM_ECDSA                               0x00001041
 
 /* Attributes */
 #define CKA_CLASS                               0x00000000
 #define CKA_TOKEN                               0x00000001
 #define CKA_PRIVATE                             0x00000002
 #define CKA_LABEL                               0x00000003
 #define CKA_KEY_TYPE                            0x00000100
 #define CKA_EC_PARAMS                           0x00000180
 #define CKA_SIGN                                0x00000108
 #define CKA_VERIFY                              0x0000010A
 
 /* Session Flags */
 #define CKF_RW_SESSION                          0x00000002
 #define CKF_SERIAL_SESSION                      0x00000004
 
/* Token Flags */
#define CKF_TOKEN_PRESENT                       0x00000001
#define CKF_HW_SLOT                             0x00000004
#define CKF_RNG                                 0x00000008
#define CKF_LOGIN_REQUIRED                      0x00000100
#define CKF_USER_PIN_INITIALIZED                0x00000400
 
 /* Structures */
 typedef struct CK_VERSION {
     CK_BYTE major;
     CK_BYTE minor;
 } CK_VERSION;
 
 typedef struct CK_INFO {
     CK_VERSION    cryptokiVersion;
     CK_UTF8CHAR   manufacturerID[32];
     CK_FLAGS      flags;
     CK_UTF8CHAR   libraryDescription[32];
     CK_VERSION    libraryVersion;
 } CK_INFO;
 
 typedef struct CK_SLOT_INFO {
     CK_UTF8CHAR   slotDescription[64];
     CK_UTF8CHAR   manufacturerID[32];
     CK_FLAGS      flags;
     CK_VERSION    hardwareVersion;
     CK_VERSION    firmwareVersion;
 } CK_SLOT_INFO;
 
 typedef struct CK_TOKEN_INFO {
     CK_UTF8CHAR   label[32];
     CK_UTF8CHAR   manufacturerID[32];
     CK_UTF8CHAR   model[16];
     CK_CHAR       serialNumber[16];
     CK_FLAGS      flags;
     CK_ULONG      ulMaxSessionCount;
     CK_ULONG      ulSessionCount;
     CK_ULONG      ulMaxRwSessionCount;
     CK_ULONG      ulRwSessionCount;
     CK_ULONG      ulMaxPinLen;
     CK_ULONG      ulMinPinLen;
     CK_ULONG      ulTotalPublicMemory;
     CK_ULONG      ulFreePublicMemory;
     CK_ULONG      ulTotalPrivateMemory;
     CK_ULONG      ulFreePrivateMemory;
     CK_VERSION    hardwareVersion;
     CK_VERSION    firmwareVersion;
     CK_CHAR       utcTime[16];
 } CK_TOKEN_INFO;
 
 typedef struct CK_SESSION_INFO {
     CK_SLOT_ID    slotID;
     CK_ULONG      state;
     CK_FLAGS      flags;
     CK_ULONG      ulDeviceError;
 } CK_SESSION_INFO;
 
 typedef struct CK_ATTRIBUTE {
     CK_ULONG      type;
     void*         pValue;
     CK_ULONG      ulValueLen;
 } CK_ATTRIBUTE;
 
 typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;
 
 typedef struct CK_MECHANISM {
     CK_ULONG      mechanism;
     void*         pParameter;
     CK_ULONG      ulParameterLen;
 } CK_MECHANISM;
 
typedef CK_MECHANISM* CK_MECHANISM_PTR;

/* Forward declaration for function list */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR* CK_FUNCTION_LIST_PTR_PTR;

/* Pointer types (after structure definitions) */
typedef CK_INFO* CK_INFO_PTR;
typedef CK_SLOT_INFO* CK_SLOT_INFO_PTR;
typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;
typedef CK_SLOT_ID* CK_SLOT_ID_PTR;
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;
 
/* Function Prototypes */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

/* CK_FUNCTION_LIST structure definition */
struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
    CK_RV (*C_GetInfo)(CK_INFO_PTR pInfo);
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV (*C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
    CK_RV (*C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (*C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID slotID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE hSession, void* pInfo);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
    CK_RV (*C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulCount);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
    CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
};
 
 #ifdef __cplusplus
 }
 #endif
 
 #endif /* _PKCS11_H_ */
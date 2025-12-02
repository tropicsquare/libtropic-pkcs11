/**
 * @file pkcs11.h
 * @brief PKCS#11 (Cryptoki) Type Definitions and Function Declarations
 * 
 * ============================================================================
 * WHAT IS PKCS#11?
 * ============================================================================
 * 
 * PKCS#11 (Public-Key Cryptography Standards #11), also known as "Cryptoki" 
 * (Cryptographic Token Interface), is a platform-independent API standard 
 * for accessing cryptographic hardware devices (tokens).
 * 
 * Common PKCS#11 tokens include:
 * - Hardware Security Modules (HSMs)
 * - Smart cards
 * - USB security keys
 * - Secure elements (like TROPIC01)
 * 
 * The API allows applications to:
 * - Generate and store cryptographic keys
 * - Perform encryption/decryption
 * - Create and verify digital signatures
 * - Generate random numbers
 * - Manage certificates and objects
 * 
 * ============================================================================
 * HOW PKCS#11 MODULES WORK
 * ============================================================================
 * 
 * 1. Application loads the shared library (.so on Linux, .dll on Windows)
 * 2. Application calls C_GetFunctionList() to get pointers to all functions
 * 3. Application calls C_Initialize() to initialize the library
 * 4. Application interacts with tokens through the function pointers
 * 5. Application calls C_Finalize() to clean up
 * 
 * ============================================================================
 * ABOUT THIS HEADER FILE
 * ============================================================================
 * 
 * This is a simplified PKCS#11 v2.40 header focused on the functionality 
 * needed for TROPIC01 integration. It includes:
 * - Basic type definitions (CK_BYTE, CK_ULONG, etc.)
 * - Return value constants (CKR_OK, CKR_GENERAL_ERROR, etc.)
 * - Key structures (CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, etc.)
 * - The CK_FUNCTION_LIST structure with all 68 standard function pointers
 * 
 * This file must be PKCS#11 v2.40 compliant to work with standard tools
 * like pkcs11-tool, OpenSSL, Firefox, etc.
 * 
 * ============================================================================
 * IMPORTANT: CK_FUNCTION_LIST STRUCTURE ORDER
 * ============================================================================
 * 
 * The CK_FUNCTION_LIST structure MUST contain function pointers in the exact
 * order specified by the PKCS#11 standard. Applications expect functions at
 * specific byte offsets. If the order is wrong or functions are missing,
 * applications will call the wrong functions or crash.
 * 
 * Reference: OASIS PKCS#11 Cryptographic Token Interface Base Specification v2.40
 * https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
 * 
 * @version 2.40 (PKCS#11 specification version)
 * @author Tropic Square s.r.o.
 */

#ifndef _PKCS11_H_
#define _PKCS11_H_

#ifdef __cplusplus
extern "C" {
#endif


/** @brief Dummy macro used when no logging is configured. */
#define LT_PKCS11_LOG_DISABLED(...)                              \
    do {                                                         \
        if (0) {                                                 \
            /* Validates format string at compile time */        \
            printf(__VA_ARGS__);                                 \
        }                                                        \
    } while (0)

#if LT_PKCS11_LOG_EN
    #define LT_PKCS11_LOG(...) do { printf(__VA_ARGS__); printf("\n"); } while(0)
#else
    #define LT_PKCS11_LOG(...) LT_PKCS11_LOG_DISABLED(__VA_ARGS__)
#endif

/* ============================================================================
 * PKCS#11 VERSION CONSTANTS
 * ============================================================================
 * These define which version of the PKCS#11 specification we implement.
 * Version 2.40 is widely supported and includes all modern cryptographic
 * operations.
 */
#define CRYPTOKI_VERSION_MAJOR 2
#define CRYPTOKI_VERSION_MINOR 40

/* ============================================================================
 * BASIC TYPE DEFINITIONS
 * ============================================================================
 * PKCS#11 defines its own types to ensure portability across different
 * platforms and compilers. These types have specific sizes and meanings.
 * 
 * Why not use standard C types directly?
 * - PKCS#11 was designed before C99 standardized fixed-width types
 * - Ensures consistent behavior across all platforms
 * - Makes the API self-documenting (CK_BYTE is clearly a byte)
 */

/**
 * CK_BYTE: An unsigned 8-bit value (0-255)
 * Used for: Raw data, random bytes, keys, etc.
 */
typedef unsigned char     CK_BYTE;

/**
 * CK_CHAR: An unsigned 8-bit value for ASCII characters
 * Used for: Strings in ISO-8859-1 (Latin-1) encoding
 */
typedef unsigned char     CK_CHAR;

/**
 * CK_UTF8CHAR: An unsigned 8-bit value for UTF-8 characters
 * Used for: Unicode strings (labels, descriptions, etc.)
 */
typedef unsigned char     CK_UTF8CHAR;

/**
 * CK_BBOOL: Boolean type (CK_TRUE or CK_FALSE)
 * Note: Uses unsigned char, not int, for size consistency
 */
typedef unsigned char     CK_BBOOL;

/**
 * CK_ULONG: Unsigned integer, at least 32 bits
 * Used for: Counts, sizes, flags, handles, etc.
 * Note: On 64-bit systems, this is typically 64 bits
 */
typedef unsigned long int CK_ULONG;

/**
 * CK_LONG: Signed integer, at least 32 bits
 * Used for: Values that might be negative (rare in PKCS#11)
 */
typedef long int          CK_LONG;

/**
 * CK_FLAGS: Bit flags (typically OR'ed together)
 * Example: CKF_RW_SESSION | CKF_SERIAL_SESSION
 */
typedef CK_ULONG          CK_FLAGS;

/**
 * CK_RV: Return value from PKCS#11 functions
 * Always check this! CKR_OK (0) means success.
 */
typedef CK_ULONG          CK_RV;

/**
 * CK_SLOT_ID: Identifies a slot (physical or logical reader)
 * A slot holds a token. Think of it like a card reader that can hold a smart card.
 */
typedef CK_ULONG          CK_SLOT_ID;

/**
 * CK_SESSION_HANDLE: Identifies an open session with a token
 * Sessions are like connections - you open one, do operations, then close it.
 */
typedef CK_ULONG          CK_SESSION_HANDLE;

/**
 * CK_OBJECT_HANDLE: Identifies an object stored on the token
 * Objects include: keys, certificates, data blobs, etc.
 */
typedef CK_ULONG          CK_OBJECT_HANDLE;

/**
 * CK_USER_TYPE: Type of user logging in
 * CKU_SO = Security Officer (admin)
 * CKU_USER = Normal user
 */
typedef CK_ULONG          CK_USER_TYPE;

/**
 * CK_MECHANISM_TYPE: Identifies a cryptographic mechanism (algorithm)
 * Example: CKM_ECDSA for ECDSA signing
 */
typedef CK_ULONG          CK_MECHANISM_TYPE;

/* Pointer types for basic types */
typedef void*             CK_VOID_PTR;      /**< Generic pointer (like void*) */
typedef CK_BYTE*          CK_BYTE_PTR;      /**< Pointer to byte array */
typedef CK_CHAR*          CK_CHAR_PTR;      /**< Pointer to character string */
typedef CK_UTF8CHAR*      CK_UTF8CHAR_PTR;  /**< Pointer to UTF-8 string */
typedef CK_ULONG*         CK_ULONG_PTR;     /**< Pointer to unsigned long */
typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR; /**< Pointer to mechanism type */
typedef void*             CK_MECHANISM_INFO_PTR;  /**< Pointer to mechanism info */

/* ============================================================================
 * NOTIFICATION TYPES
 * ============================================================================
 * Notifications are callbacks the token can use to inform the application
 * of events (like token removal). Rarely used in practice.
 */
typedef CK_ULONG CK_NOTIFICATION;
typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE session, CK_NOTIFICATION event, CK_VOID_PTR application);

/* ============================================================================
 * OBJECT CLASSES
 * ============================================================================
 * Every object on a token has a class that defines what kind of object it is.
 * This determines what attributes are valid and what operations can be performed.
 */
typedef CK_ULONG CK_OBJECT_CLASS;

#define CKO_DATA            0x00000000  /**< Arbitrary data (files, etc.) */
#define CKO_CERTIFICATE     0x00000001  /**< X.509 certificate */
#define CKO_PUBLIC_KEY      0x00000002  /**< Public key (RSA, EC, etc.) */
#define CKO_PRIVATE_KEY     0x00000003  /**< Private key (protected!) */
#define CKO_SECRET_KEY      0x00000004  /**< Symmetric key (AES, etc.) */
#define CKO_VENDOR_DEFINED  0x80000000  /**< Vendor-specific object types */

/* ============================================================================
 * KEY TYPES
 * ============================================================================
 * Specifies the cryptographic algorithm a key is used for.
 */
typedef CK_ULONG CK_KEY_TYPE;

#define CKK_RSA             0x00000000  /**< RSA key */
#define CKK_DSA             0x00000001  /**< DSA key */
#define CKK_DH              0x00000002  /**< Diffie-Hellman key */
#define CKK_EC              0x00000003  /**< Elliptic Curve key (ECDSA, ECDH) */
#define CKK_VENDOR_DEFINED  0x80000000  /**< Vendor-specific key types */

/* ============================================================================
 * USER TYPES
 * ============================================================================
 * Different user roles have different privileges on the token.
 */
#define CKU_SO              0UL  /**< Security Officer - can initialize token, set PINs */
#define CKU_USER            1UL  /**< Normal User - can use keys after login */
#define CKU_CONTEXT_SPECIFIC 2UL /**< Context-specific login for specific operations */

/* ============================================================================
 * BOOLEAN CONSTANTS
 * ============================================================================
 */
#define CK_TRUE  1   /**< Boolean true */
#define CK_FALSE 0   /**< Boolean false */

/* ============================================================================
 * RETURN VALUES (CK_RV)
 * ============================================================================
 * Every PKCS#11 function returns one of these values.
 * Always check the return value! CKR_OK means success.
 * 
 * The values are carefully chosen:
 * - 0x00000000 = Success (so "if (rv)" catches all errors)
 * - Lower numbers = General errors
 * - Higher numbers = Specific conditions
 * - 0x80000000+ = Vendor-defined errors
 */
#define CKR_OK                                  0x00000000  /**< Success! */
#define CKR_HOST_MEMORY                         0x00000002  /**< Out of host memory */
#define CKR_SLOT_ID_INVALID                     0x00000003  /**< Invalid slot ID */
#define CKR_GENERAL_ERROR                       0x00000005  /**< Unspecified error */
#define CKR_ARGUMENTS_BAD                       0x00000007  /**< Invalid argument(s) */
#define CKR_FUNCTION_NOT_SUPPORTED              0x00000054  /**< Function not implemented */
#define CKR_KEY_HANDLE_INVALID                  0x00000060  /**< Invalid key handle */
#define CKR_KEY_TYPE_INCONSISTENT               0x00000063  /**< Key type doesn't match */
#define CKR_MECHANISM_INVALID                   0x00000070  /**< Invalid mechanism */
#define CKR_SESSION_COUNT                       0x000000B1  /**< Too many sessions */
#define CKR_SESSION_HANDLE_INVALID              0x000000B3  /**< Invalid session handle */
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED      0x000000B4  /**< Parallel sessions not supported */
#define CKR_SIGNATURE_INVALID                   0x000000C0  /**< Signature verification failed */
#define CKR_TOKEN_NOT_PRESENT                   0x000000E0  /**< Token not in slot */
#define CKR_USER_NOT_LOGGED_IN                  0x00000101  /**< Must login first */
#define CKR_BUFFER_TOO_SMALL                    0x00000150  /**< Output buffer too small */
#define CKR_CRYPTOKI_NOT_INITIALIZED            0x00000190  /**< C_Initialize not called */
#define CKR_CRYPTOKI_ALREADY_INITIALIZED        0x00000191  /**< C_Initialize called twice */
#define CKR_VENDOR_DEFINED                      0x80000000  /**< Start of vendor-defined errors */

/* ============================================================================
 * CRYPTOGRAPHIC MECHANISMS
 * ============================================================================
 * Mechanisms specify which cryptographic algorithm and mode to use.
 * Example: CKM_ECDSA means "use ECDSA for signing/verification"
 */
#define CKM_EC_KEY_PAIR_GEN                     0x00001040  /**< Generate EC key pair */
#define CKM_ECDSA                               0x00001041  /**< ECDSA sign/verify */

/* ============================================================================
 * OBJECT ATTRIBUTES
 * ============================================================================
 * Attributes describe properties of objects. Each attribute has a type
 * (like CKA_CLASS) and a value.
 * 
 * When creating or searching objects, you provide a template - an array
 * of attribute type/value pairs.
 */
#define CKA_CLASS                               0x00000000  /**< Object class (CKO_*) */
#define CKA_TOKEN                               0x00000001  /**< True if stored on token */
#define CKA_PRIVATE                             0x00000002  /**< True if login required */
#define CKA_LABEL                               0x00000003  /**< Human-readable name */
#define CKA_KEY_TYPE                            0x00000100  /**< Key type (CKK_*) */
#define CKA_SIGN                                0x00000108  /**< True if key can sign */
#define CKA_VERIFY                              0x0000010A  /**< True if key can verify */
#define CKA_EC_PARAMS                           0x00000180  /**< EC curve parameters (DER) */

/* ============================================================================
 * SESSION FLAGS
 * ============================================================================
 * Flags passed to C_OpenSession() to specify session properties.
 */
#define CKF_RW_SESSION                          0x00000002  /**< Read-write session (can modify) */
#define CKF_SERIAL_SESSION                      0x00000004  /**< Required flag (legacy) */

/* ============================================================================
 * SLOT AND TOKEN FLAGS
 * ============================================================================
 * Flags in CK_SLOT_INFO.flags and CK_TOKEN_INFO.flags describing
 * capabilities and state.
 */
#define CKF_TOKEN_PRESENT                       0x00000001  /**< Token is in the slot */
#define CKF_HW_SLOT                             0x00000004  /**< Hardware slot (not virtual) */
#define CKF_RNG                                 0x00000008  /**< Token has RNG */
#define CKF_LOGIN_REQUIRED                      0x00000100  /**< Login required for private objects */
#define CKF_USER_PIN_INITIALIZED                0x00000400  /**< User PIN has been set */

/* ============================================================================
 * STRUCTURES
 * ============================================================================
 * These structures are filled by the token and returned to the application.
 */

/**
 * CK_VERSION - Version number (major.minor)
 * Used in: CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, CK_FUNCTION_LIST
 */
typedef struct CK_VERSION {
    CK_BYTE major;  /**< Major version (e.g., 2 for PKCS#11 2.40) */
    CK_BYTE minor;  /**< Minor version (e.g., 40 for PKCS#11 2.40) */
} CK_VERSION;

/**
 * CK_INFO - Library-wide information
 * Returned by: C_GetInfo()
 * 
 * Contains general information about the PKCS#11 library itself,
 * not about any specific token.
 */
typedef struct CK_INFO {
    CK_VERSION    cryptokiVersion;       /**< PKCS#11 version supported */
    CK_UTF8CHAR   manufacturerID[32];    /**< Library manufacturer (padded with spaces) */
    CK_FLAGS      flags;                 /**< Reserved, must be 0 */
    CK_UTF8CHAR   libraryDescription[32];/**< Library description (padded with spaces) */
    CK_VERSION    libraryVersion;        /**< Library version */
} CK_INFO;

/**
 * CK_SLOT_INFO - Information about a slot (reader)
 * Returned by: C_GetSlotInfo()
 * 
 * A slot represents a logical or physical device that can hold a token.
 * Think of it like a USB port that can hold a security key.
 */
typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR   slotDescription[64];   /**< Slot description (padded with spaces) */
    CK_UTF8CHAR   manufacturerID[32];    /**< Slot manufacturer (padded with spaces) */
    CK_FLAGS      flags;                 /**< Slot flags (CKF_TOKEN_PRESENT, etc.) */
    CK_VERSION    hardwareVersion;       /**< Slot hardware version */
    CK_VERSION    firmwareVersion;       /**< Slot firmware version */
} CK_SLOT_INFO;

/**
 * CK_TOKEN_INFO - Information about a token
 * Returned by: C_GetTokenInfo()
 * 
 * A token is the actual cryptographic device (smart card, HSM, etc.).
 * This structure contains detailed information about its capabilities.
 */
typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR   label[32];             /**< Token label (user-settable name) */
    CK_UTF8CHAR   manufacturerID[32];    /**< Token manufacturer */
    CK_UTF8CHAR   model[16];             /**< Token model name */
    CK_CHAR       serialNumber[16];      /**< Token serial number */
    CK_FLAGS      flags;                 /**< Token flags (CKF_RNG, etc.) */
    CK_ULONG      ulMaxSessionCount;     /**< Max simultaneous sessions (0=unlimited) */
    CK_ULONG      ulSessionCount;        /**< Current session count */
    CK_ULONG      ulMaxRwSessionCount;   /**< Max R/W sessions */
    CK_ULONG      ulRwSessionCount;      /**< Current R/W session count */
    CK_ULONG      ulMaxPinLen;           /**< Max PIN length */
    CK_ULONG      ulMinPinLen;           /**< Min PIN length */
    CK_ULONG      ulTotalPublicMemory;   /**< Total public memory (bytes) */
    CK_ULONG      ulFreePublicMemory;    /**< Free public memory */
    CK_ULONG      ulTotalPrivateMemory;  /**< Total private memory */
    CK_ULONG      ulFreePrivateMemory;   /**< Free private memory */
    CK_VERSION    hardwareVersion;       /**< Token hardware version */
    CK_VERSION    firmwareVersion;       /**< Token firmware version */
    CK_CHAR       utcTime[16];           /**< Current time (YYYYMMDDHHMMSS00) */
} CK_TOKEN_INFO;

/**
 * CK_SESSION_INFO - Information about an open session
 * Returned by: C_GetSessionInfo()
 */
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID    slotID;        /**< Slot this session is connected to */
    CK_ULONG      state;         /**< Session state (logged in, etc.) */
    CK_FLAGS      flags;         /**< Session flags */
    CK_ULONG      ulDeviceError; /**< Device-specific error code */
} CK_SESSION_INFO;

/**
 * CK_ATTRIBUTE - An attribute type/value pair
 * Used in: Templates for creating, finding, and reading objects
 * 
 * Example:
 *   CK_ATTRIBUTE attr = { CKA_CLASS, &class_value, sizeof(class_value) };
 */
typedef struct CK_ATTRIBUTE {
    CK_ULONG      type;       /**< Attribute type (CKA_*) */
    void*         pValue;     /**< Pointer to value */
    CK_ULONG      ulValueLen; /**< Length of value in bytes */
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

/**
 * CK_MECHANISM - Specifies a cryptographic mechanism and its parameters
 * Used in: C_SignInit, C_EncryptInit, C_GenerateKeyPair, etc.
 * 
 * Example:
 *   CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
 */
typedef struct CK_MECHANISM {
    CK_ULONG      mechanism;     /**< Mechanism type (CKM_*) */
    void*         pParameter;    /**< Mechanism-specific parameters (or NULL) */
    CK_ULONG      ulParameterLen;/**< Length of parameters */
} CK_MECHANISM;

typedef CK_MECHANISM* CK_MECHANISM_PTR;

/* ============================================================================
 * FUNCTION LIST FORWARD DECLARATIONS
 * ============================================================================
 * The CK_FUNCTION_LIST structure contains pointers to all PKCS#11 functions.
 * We need to forward-declare it before defining the pointer types.
 */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR* CK_FUNCTION_LIST_PTR_PTR;

/* Structure pointer types */
typedef CK_INFO* CK_INFO_PTR;
typedef CK_SLOT_INFO* CK_SLOT_INFO_PTR;
typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;
typedef CK_SLOT_ID* CK_SLOT_ID_PTR;
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================
 * These are the actual function declarations that our module implements.
 * Not all functions need to be implemented - unimplemented ones return
 * CKR_FUNCTION_NOT_SUPPORTED.
 */

/* --- Library Management --- */
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
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);

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

CK_RV C_Finalize(CK_VOID_PTR pReserved);

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
CK_RV C_GetInfo(CK_INFO_PTR pInfo);


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
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* --- Slot and Token Management --- */

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
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

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
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);

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
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

/* --- Session Management --- */

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
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);

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
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, void* pInfo);

/* --- Login/Logout --- */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);

/* --- Object Management --- */
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulCount);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

/* --- Signing --- */
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/* --- Key Generation --- */
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);

/* --- Random Number Generation --- */
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
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);

/**
 * @brief Generate random bytes using TROPIC01's hardware RNG.
 * 
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
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

/* ============================================================================
 * CK_FUNCTION_LIST STRUCTURE
 * ============================================================================
 * 
 * This is the MOST IMPORTANT structure in PKCS#11!
 * 
 * When an application loads our library, it calls C_GetFunctionList() to get
 * a pointer to this structure. The application then uses these function
 * pointers to call our implementation.
 * 
 * CRITICAL REQUIREMENTS:
 * 1. ALL 68 function pointers must be present in the EXACT order below
 * 2. The order matches the PKCS#11 2.40 specification
 * 3. Unimplemented functions must be NULL (not missing!)
 * 4. If any function is missing or out of order, applications will crash
 * 
 * WHY THE ORDER MATTERS:
 * Applications calculate function addresses by offset from the start of
 * the structure. If C_OpenSession is supposed to be at offset 96 bytes
 * but we put it at offset 88 bytes, the application will call the wrong
 * function (or crash with SIGBUS/SIGSEGV).
 * 
 * FUNCTION CATEGORIES:
 * - Slots 0-3:   Library management (Initialize, Finalize, GetInfo, GetFunctionList)
 * - Slots 4-11:  Slot/Token management (GetSlotList, GetSlotInfo, InitToken, etc.)
 * - Slots 12-19: Session management (OpenSession, CloseSession, Login, etc.)
 * - Slots 20-27: Object management (CreateObject, FindObjects, GetAttribute, etc.)
 * - Slots 28-35: Encryption functions
 * - Slots 36-40: Message digesting (hashing)
 * - Slots 41-47: Signing and MACing
 * - Slots 48-54: Signature verification
 * - Slots 55-58: Dual-function operations
 * - Slots 59-64: Key management (GenerateKey, WrapKey, DeriveKey)
 * - Slots 65-66: Random number generation (SeedRandom, GenerateRandom)
 * - Slots 67-69: Parallel function management (deprecated, but required)
 */
struct CK_FUNCTION_LIST {
    /**
     * Version of this structure (should be {2, 40} for PKCS#11 v2.40)
     */
    CK_VERSION version;
    
    /* ========================================================================
     * GENERAL PURPOSE FUNCTIONS (Slots 0-3)
     * These are called first to initialize the library and get capabilities.
     * ======================================================================== */
    
    /** Slot 0: Initialize the library. Must be called before any other function. */
    CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
    
    /** Slot 1: Clean up the library. Must be called when done. */
    CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
    
    /** Slot 2: Get general information about the library. */
    CK_RV (*C_GetInfo)(CK_INFO_PTR pInfo);
    
    /** Slot 3: Get the function list pointer. Entry point for loading the module. */
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    
    /* ========================================================================
     * SLOT AND TOKEN MANAGEMENT (Slots 4-11)
     * Functions to enumerate slots and get information about tokens.
     * ======================================================================== */
    
    /** Slot 4: Get list of slot IDs in the system. */
    CK_RV (*C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    
    /** Slot 5: Get information about a specific slot. */
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    
    /** Slot 6: Get information about the token in a slot. */
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
    
    /** Slot 7: Get list of mechanisms (algorithms) supported by token. */
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    
    /** Slot 8: Get information about a specific mechanism. */
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
    
    /** Slot 9: Initialize a token (format/wipe it). */
    CK_RV (*C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    
    /** Slot 10: Initialize the user PIN. */
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    
    /** Slot 11: Change the user PIN. */
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
    
    /* ========================================================================
     * SESSION MANAGEMENT (Slots 12-19)
     * Functions to open/close sessions and manage authentication.
     * ======================================================================== */
    
    /** Slot 12: Open a session with a token. */
    CK_RV (*C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
    
    /** Slot 13: Close a session. */
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE hSession);
    
    /** Slot 14: Close all sessions for a slot. */
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID slotID);
    
    /** Slot 15: Get information about a session. */
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE hSession, void* pInfo);
    
    /** Slot 16: Save cryptographic operation state. */
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
    
    /** Slot 17: Restore cryptographic operation state. */
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
    
    /** Slot 18: Log into the token. */
    CK_RV (*C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    
    /** Slot 19: Log out of the token. */
    CK_RV (*C_Logout)(CK_SESSION_HANDLE hSession);
    
    /* ========================================================================
     * OBJECT MANAGEMENT (Slots 20-27)
     * Functions to create, find, and manipulate objects on the token.
     * ======================================================================== */
    
    /** Slot 20: Create a new object. */
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    
    /** Slot 21: Copy an object. */
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
    
    /** Slot 22: Destroy an object. */
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    
    /** Slot 23: Get the size of an object. */
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
    
    /** Slot 24: Get attribute values from an object. */
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    
    /** Slot 25: Modify attribute values of an object. */
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    
    /** Slot 26: Initialize a search for objects. */
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    
    /** Slot 27: Continue a search for objects. */
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulCount);
    
    /** Slot 28: Finish a search for objects. */
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
    
    /* ========================================================================
     * ENCRYPTION FUNCTIONS (Slots 29-35)
     * Functions for symmetric and asymmetric encryption.
     * ======================================================================== */
    
    /** Slot 29: Initialize an encryption operation. */
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    
    /** Slot 30: Encrypt data in a single operation. */
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    
    /** Slot 31: Continue a multi-part encryption. */
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    
    /** Slot 32: Finish a multi-part encryption. */
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    
    /* ========================================================================
     * DECRYPTION FUNCTIONS (Slots 33-36)
     * Functions for symmetric and asymmetric decryption.
     * ======================================================================== */
    
    /** Slot 33: Initialize a decryption operation. */
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    
    /** Slot 34: Decrypt data in a single operation. */
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    
    /** Slot 35: Continue a multi-part decryption. */
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    
    /** Slot 36: Finish a multi-part decryption. */
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    
    /* ========================================================================
     * MESSAGE DIGESTING / HASHING (Slots 37-41)
     * Functions for computing hash/digest of data.
     * ======================================================================== */
    
    /** Slot 37: Initialize a digest (hash) operation. */
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
    
    /** Slot 38: Digest data in a single operation. */
    CK_RV (*C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    
    /** Slot 39: Continue a multi-part digest. */
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    
    /** Slot 40: Include key value in digest. */
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
    
    /** Slot 41: Finish a multi-part digest. */
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    
    /* ========================================================================
     * SIGNING AND MACING (Slots 42-48)
     * Functions for creating digital signatures and MACs.
     * ======================================================================== */
    
    /** Slot 42: Initialize a signing operation. */
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    
    /** Slot 43: Sign data in a single operation. */
    CK_RV (*C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    
    /** Slot 44: Continue a multi-part signing operation. */
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    
    /** Slot 45: Finish a multi-part signing operation. */
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    
    /** Slot 46: Initialize signing with data recovery. */
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    
    /** Slot 47: Sign with data recovery. */
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    
    /* ========================================================================
     * SIGNATURE VERIFICATION (Slots 48-54)
     * Functions for verifying digital signatures.
     * ======================================================================== */
    
    /** Slot 48: Initialize a verification operation. */
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    
    /** Slot 49: Verify a signature in a single operation. */
    CK_RV (*C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    
    /** Slot 50: Continue a multi-part verification. */
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    
    /** Slot 51: Finish a multi-part verification. */
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    
    /** Slot 52: Initialize verification with data recovery. */
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    
    /** Slot 53: Verify with data recovery. */
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    
    /* ========================================================================
     * DUAL-FUNCTION CRYPTOGRAPHIC OPERATIONS (Slots 54-57)
     * These perform two operations at once (e.g., digest while encrypting).
     * Rarely implemented.
     * ======================================================================== */
    
    /** Slot 54: Digest and encrypt data. */
    CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    
    /** Slot 55: Decrypt and digest data. */
    CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    
    /** Slot 56: Sign and encrypt data. */
    CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    
    /** Slot 57: Decrypt and verify signature. */
    CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    
    /* ========================================================================
     * KEY MANAGEMENT (Slots 58-63)
     * Functions for generating, wrapping, and deriving keys.
     * ======================================================================== */
    
    /** Slot 58: Generate a symmetric key. */
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
    
    /** Slot 59: Generate a public/private key pair. */
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
    
    /** Slot 60: Wrap (encrypt) a key for export. */
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
    
    /** Slot 61: Unwrap (decrypt) a wrapped key. */
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    
    /** Slot 62: Derive a key from another key. */
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    
    /* ========================================================================
     * RANDOM NUMBER GENERATION (Slots 63-64)
     * Functions for seeding and getting random numbers from the token's RNG.
     * 
     * THIS IS OUR MAIN IMPLEMENTED FEATURE!
     * C_GenerateRandom uses the TROPIC01 hardware RNG.
     * ======================================================================== */
    
    /** 
     * Slot 63: Add entropy to the token's RNG.
     * Note: Hardware RNGs typically ignore this (they have their own entropy).
     */
    CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
    
    /** 
     * Slot 64: Generate random bytes from the token's RNG.
     * THIS IS OUR MAIN FEATURE - uses TROPIC01 hardware RNG!
     */
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
    
    /* ========================================================================
     * PARALLEL FUNCTION MANAGEMENT (Slots 65-67)
     * These are DEPRECATED in PKCS#11 v2.40 but must still be present!
     * They were used for managing parallel cryptographic operations.
     * Modern tokens should return CKR_FUNCTION_NOT_PARALLEL.
     * ======================================================================== */
    
    /** Slot 65: Get status of parallel operation (DEPRECATED). */
    CK_RV (*C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
    
    /** Slot 66: Cancel a parallel operation (DEPRECATED). */
    CK_RV (*C_CancelFunction)(CK_SESSION_HANDLE hSession);
    
    /** 
     * Slot 67: Wait for a slot event (token insertion/removal).
     * This is the LAST function in the structure - DO NOT add anything after!
     */
    CK_RV (*C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
};

#ifdef __cplusplus
}
#endif

#endif /* _PKCS11_H_ */

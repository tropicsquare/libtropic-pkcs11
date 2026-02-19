/**
 * @file pkcs11.c
 * @brief PKCS#11 Cryptoki module for TROPIC01 Secure Element
 * @copyright Copyright (c) 2020-2025 Tropic Square s.r.o.
 * @license See LICENSE.md in the root directory
 */

#include "pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_examples.h"
#include "libtropic_logging.h"
#include "libtropic_port.h"
#include "libtropic_port_unix_usb_dongle.h"


/**************************************************************************************************
 * TROPIC01 specifics
 *************************************************************************************************/

/* Pairing keys for secure session (defined in libtropic/keys/keys.c) */
extern uint8_t sh0priv[];
extern uint8_t sh0pub[];


/**************************************************************************************************
 * PKCS11 context and helpers
 *************************************************************************************************/

/*
 * Object handle encoding:  (TYPE << 16) | SLOT_INDEX
 * R-MEM:                   512 slots (0-511), 1-444 bytes each
 * ECC:                     32 slots (0-31), P256 or Ed25519
 */
#define PKCS11_HANDLE_TYPE_RMEM_DATA    0x0001
#define PKCS11_HANDLE_TYPE_ECC_PRIVKEY  0x0002
#define PKCS11_HANDLE_TYPE_ECC_PUBKEY   0x0003

#define PKCS11_MAKE_HANDLE(type, slot)     (((CK_OBJECT_HANDLE)(type) << 16) | (slot))
#define PKCS11_HANDLE_GET_TYPE(h)          (((h) >> 16) & 0xFFFF)
#define PKCS11_HANDLE_GET_SLOT(h)          ((h) & 0xFFFF)

#define PKCS11_IS_VALID_RMEM_HANDLE(h) \
    (PKCS11_HANDLE_GET_TYPE(h) == PKCS11_HANDLE_TYPE_RMEM_DATA && \
     PKCS11_HANDLE_GET_SLOT(h) <= TR01_R_MEM_DATA_SLOT_MAX)

#define PKCS11_IS_VALID_ECC_PRIV_HANDLE(h) \
    (PKCS11_HANDLE_GET_TYPE(h) == PKCS11_HANDLE_TYPE_ECC_PRIVKEY && \
     PKCS11_HANDLE_GET_SLOT(h) <= TR01_ECC_SLOT_31)

#define PKCS11_IS_VALID_ECC_PUB_HANDLE(h) \
    (PKCS11_HANDLE_GET_TYPE(h) == PKCS11_HANDLE_TYPE_ECC_PUBKEY && \
     PKCS11_HANDLE_GET_SLOT(h) <= TR01_ECC_SLOT_31)

#define TRIM_LENGTH(v, maxlen) ((v < maxlen) ? v : maxlen)

/* Module context - all global state in one place */
typedef struct {
    CK_BBOOL                    initialized;
    CK_BBOOL                    session_open;
    lt_handle_t                 lt_handle;
    lt_dev_unix_usb_dongle_t    lt_device;
    CK_SESSION_HANDLE           session_handle;

    /* C_FindObjects state */
    CK_BBOOL                    find_active;
    uint16_t                    find_rmem_index;
    uint8_t                     find_ecc_index;
    CK_BBOOL                    find_ecc_done;
    CK_OBJECT_CLASS             find_class;
    CK_BBOOL                    find_class_set;
    CK_BBOOL                    find_slot_set;
    CK_ULONG                    find_slot;

    /* C_Sign state */
    CK_BBOOL                    sign_active;
    CK_MECHANISM_TYPE           sign_mechanism;
    uint8_t                     sign_key_slot;
    lt_ecc_curve_type_t         sign_key_curve;
} lt_pkcs11_ctx_t;

static lt_pkcs11_ctx_t pkcs11_ctx = {0};


/**************************************************************************************************
 * Logging macros
 *************************************************************************************************/

#define LT_PKCS11_LOG_DISABLED(...)                             \
    do {                                                        \
        if (0) {                                                \
            /* Validates format string at compile time */       \
            printf(__VA_ARGS__);                                \
        }                                                       \
    } while (0)

#if LT_PKCS11_LOG_EN
    #define LT_PKCS11_LOG(...)                                  \
        do {                                                    \
            printf("%s: ", __func__);                           \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
        } while(0)
#else
    #define LT_PKCS11_LOG(...) LT_PKCS11_LOG_DISABLED(__VA_ARGS__)
#endif

#define LT_PKCS11_RETURN(val)                                   \
            do {                                                \
                LT_PKCS11_LOG(#val);                            \
                return val;                                     \
            } while (0)


/**************************************************************************************************
 * Core PKCS#11 Functions
 *************************************************************************************************/

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    LT_PKCS11_LOG("(pInitArgs=%p)", pInitArgs);

    (void)pInitArgs;

    if (pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_ALREADY_INITIALIZED);
    }

    /* Configure USB device passed from build as TS_USB_DEV option */
    memset(&pkcs11_ctx.lt_device, 0, sizeof(pkcs11_ctx.lt_device));
    strncpy(pkcs11_ctx.lt_device.dev_path, TS_USB_DEV,
            sizeof(pkcs11_ctx.lt_device.dev_path) - 1);
    pkcs11_ctx.lt_device.baud_rate = 115200;

    /* Initialize libtropic handle */
    memset(&pkcs11_ctx.lt_handle, 0, sizeof(pkcs11_ctx.lt_handle));
    pkcs11_ctx.lt_handle.l2.device = &pkcs11_ctx.lt_device;

    lt_ret_t ret = lt_init(&pkcs11_ctx.lt_handle);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_init failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    pkcs11_ctx.initialized = CK_TRUE;

    LT_PKCS11_RETURN(CKR_OK);
}


CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    LT_PKCS11_LOG("(pReserved=%p)", pReserved);

    if (pReserved != NULL) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Close secure session if still open */
    if (pkcs11_ctx.session_open) {
        lt_session_abort(&pkcs11_ctx.lt_handle);
        pkcs11_ctx.session_open = CK_FALSE;
    }

    lt_deinit(&pkcs11_ctx.lt_handle);
    memset(&pkcs11_ctx, 0, sizeof(pkcs11_ctx));

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("(pInfo=%p)", pInfo);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (!pInfo) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strncpy((char *)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char *)pInfo->libraryDescription, "Tropic PKCS11", 32);

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    LT_PKCS11_LOG("(tokenPresen=%d pSlotList=%p pulCount=%p)",
                  tokenPresent, pSlotList, pulCount);

    (void)tokenPresent;

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (!pulCount) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    if (!pSlotList) {
        *pulCount = 1;
    } else if (*pulCount < 1) {
        LT_PKCS11_RETURN(CKR_BUFFER_TOO_SMALL);
    } else {
        pSlotList[0] = 0;
        *pulCount = 1;
    }

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("(slotID=%lu, pInfo=%p)", slotID, pInfo);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (slotID != 0) {
        LT_PKCS11_RETURN(CKR_SLOT_ID_INVALID);
    }

    if (!pInfo) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    strncpy((char *)pInfo->slotDescription, "TROPIC01 Secure Element USB Slot", 64);
    strncpy((char *)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    /* Read firmware versions from chip */
    uint8_t fw_ver[4] = {0};

    lt_ret_t ret = lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_get_info_riscv_fw_ver failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    pInfo->firmwareVersion.major = fw_ver[3];
    pInfo->firmwareVersion.minor = fw_ver[2];

    ret = lt_get_info_spect_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_get_info_spect_fw_ver failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    pInfo->hardwareVersion.major = fw_ver[3];
    pInfo->hardwareVersion.minor = fw_ver[2];

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("(slotID=%lu, pInfo=%p)", slotID, pInfo);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (slotID != 0) {
        LT_PKCS11_RETURN(CKR_SLOT_ID_INVALID);
    }

    if (!pInfo) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    strncpy((char*)pInfo->manufacturerID, "TropicSquare", 32);

    /* Token capabilities - mark as fully initialized with RNG */
    pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;

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

    /* Get firmware version */
    uint8_t fw_ver[4] = {0};
    lt_ret_t ret = lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_get_info_riscv_fw_ver failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    pInfo->firmwareVersion.major = fw_ver[3];
    pInfo->firmwareVersion.minor = fw_ver[2];

    /* Get chip ID and get token info */
    struct lt_chip_id_t chip_id = {0};
    ret = lt_get_info_chip_id(&pkcs11_ctx.lt_handle, &chip_id);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_get_info_chip_id failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_TOKEN_NOT_PRESENT);
    }

    /* Hardware version from chip_id_ver array [major.minor.patch.build] */
    pInfo->hardwareVersion.major = chip_id.chip_id_ver[0];
    pInfo->hardwareVersion.minor = chip_id.chip_id_ver[1];

    /* Model from part_num_data (ASCII string with length prefix) */
    /* part_num_data contains something like "TR01-C2P-T101" prefixed with length byte */
    if (chip_id.part_num_data[0] > 0 && chip_id.part_num_data[0] < 16) {
        uint8_t model_len = chip_id.part_num_data[0];
        if (model_len > 15) {
            model_len = 15;
        }

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
        snprintf((char*)pInfo->label, 32, "%s-%02X%02X", pInfo->model,
                 chip_id.ser_num.lot_id[1], chip_id.ser_num.lot_id[2]);
    } else {
        strncpy((char*)pInfo->label, "TROPIC01", 32);
    }

    LT_PKCS11_LOG("(label='%.32s', model='%.16s', serial='%.16s', HW=%d.%d, FW=%d.%d)",
                  pInfo->label, pInfo->model, pInfo->serialNumber,
                  pInfo->hardwareVersion.major, pInfo->hardwareVersion.minor,
                  pInfo->firmwareVersion.major, pInfo->firmwareVersion.minor);

    LT_PKCS11_RETURN(CKR_OK);
 }

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    LT_PKCS11_LOG("(slotID=%lu, flags=0x%lx, pApplication=%p, Notify=%p, phSession=%p)",
                  slotID, flags, pApplication, Notify, phSession);

    (void)pApplication;
    (void)Notify;

    /* Library must be initialized first */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* We only support slot ID 1 */
    if (slotID != 0) {
        LT_PKCS11_RETURN(CKR_SLOT_ID_INVALID);
    }

    /* phSession is required - we need somewhere to return the handle */
    if (!phSession) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    /* CKF_SERIAL_SESSION must be set for legacy reasons (PKCS#11 v2.40 spec) */
    if (!(flags & CKF_SERIAL_SESSION)) {
        LT_PKCS11_RETURN(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }

    /* Check if session is already open - we only support one session at a time */
    if (pkcs11_ctx.session_open) {
        LT_PKCS11_RETURN(CKR_SESSION_COUNT);
    }

    /* Establish authenticated encrypted session with TROPIC01 */
    lt_ret_t ret = lt_verify_chip_and_start_secure_session(&pkcs11_ctx.lt_handle, sh0priv,
                    sh0pub, TR01_PAIRING_KEY_SLOT_INDEX_0);

    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_verify_chip_and_start_secure_session failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    pkcs11_ctx.session_handle = (CK_SESSION_HANDLE)&pkcs11_ctx.lt_handle;
    pkcs11_ctx.session_open = CK_TRUE;
    *phSession = pkcs11_ctx.session_handle;

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    LT_PKCS11_LOG("(hSession=0x%lx)", hSession);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (!pkcs11_ctx.session_open) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    if (hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    lt_ret_t ret = lt_session_abort(&pkcs11_ctx.lt_handle);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_session_abort failed with %s", lt_ret_verbose(ret));

        pkcs11_ctx.session_open = CK_FALSE;
        pkcs11_ctx.session_handle = 0;

        LT_PKCS11_RETURN(CKR_GENERAL_ERROR);
    }

    pkcs11_ctx.session_open = CK_FALSE;
    pkcs11_ctx.session_handle = 0;

    LT_PKCS11_RETURN(CKR_OK);
}


/* ---------------------------------------------------------------------------
 * OBJECT MANAGEMENT FUNCTIONS
 * --------------------------------------------------------------------------
 *
 * These functions implement storage and retrieval of data objects using
 * TROPIC01's R-MEM (Reversible Memory).
 * R-MEM provides 512 slots (0-511), each storing 1-444 bytes.
 *
 * PKCS#11 Object Type Mapping:
 * - CKO_DATA → R-MEM data slots
 *
 * Object handles encode the type and slot: handle = (type << 16) | slot_index
 */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pTemplate=%p, ulCount=%lu, phObject=%p)",
                   hSession, pTemplate, ulCount, phObject);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Validate parameters */
    if (!pTemplate || ulCount == 0 || !phObject) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    /* Parse template to find required attributes */
    CK_OBJECT_CLASS obj_class = CK_UNAVAILABLE_INFORMATION;
    CK_BYTE_PTR data_value = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG slot_id = CK_UNAVAILABLE_INFORMATION;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
        case CKA_CLASS:
            if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
                obj_class = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
                LT_PKCS11_LOG("CKA_CLASS = 0x%lx", obj_class);
            }
            break;

        case CKA_VALUE:
            data_value = (CK_BYTE_PTR)pTemplate[i].pValue;
            data_len = pTemplate[i].ulValueLen;
            LT_PKCS11_LOG("CKA_VALUE = %lu bytes", data_len);
            break;

        case CKA_LABEL:
            /* Use CKA_LABEL as slot number for User Data (R-Mem)*/
            if (pTemplate[i].pValue && pTemplate[i].ulValueLen > 0) {
                char temp[16] = {0};
                memcpy(temp, pTemplate[i].pValue, TRIM_LENGTH(pTemplate[i].ulValueLen, 15));
                slot_id = (CK_ULONG) atoi(pTemplate[i].pValue);
                LT_PKCS11_LOG("CKA_LABEL = '%s' (slot %lu)", temp, slot_id);
            }
            break;

        default:
            break;
        }
    }

    LT_PKCS11_LOG("obj_class=0x%lx, data_len=%lu, slot_id=%lu", obj_class, data_len, slot_id);

    /* We only support CKO_DATA objects */
    if (obj_class != CKO_DATA) {
        LT_PKCS11_RETURN(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    /* CKA_VALUE is required for data objects */
    if (!data_value || data_len == 0) {
        LT_PKCS11_RETURN(CKR_TEMPLATE_INCOMPLETE);
    }

    /* Validate data size */
    if (data_len < TR01_R_MEM_DATA_SIZE_MIN || data_len > TR01_R_MEM_DATA_SIZE_MAX) {
        LT_PKCS11_RETURN(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    /* Slot must be specified */
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        LT_PKCS11_RETURN(CKR_TEMPLATE_INCOMPLETE);
    }

    /* Validate slot ID */
    if (slot_id > TR01_R_MEM_DATA_SLOT_MAX) {
        LT_PKCS11_RETURN(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    LT_PKCS11_LOG("Writing %lu bytes to slot: %lu", data_len, slot_id);

    lt_ret_t ret = lt_r_mem_data_write(&pkcs11_ctx.lt_handle, (uint16_t)slot_id, data_value,
                                       (uint16_t)data_len);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_r_mem_data_write failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    *phObject = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_RMEM_DATA, slot_id);

    LT_PKCS11_LOG("(handle=0x%lx, slot=%lu)", *phObject, slot_id);
    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    LT_PKCS11_LOG("(hSession=0x%lx, hObject=0x%lx)", hSession, hObject);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    uint16_t slot = PKCS11_HANDLE_GET_SLOT(hObject);
    lt_ret_t ret;

    /* Handle R-MEM data objects */
    if (PKCS11_IS_VALID_RMEM_HANDLE(hObject)) {

        LT_PKCS11_LOG("Erasing slot: %u", slot);
        ret = lt_r_mem_data_erase(&pkcs11_ctx.lt_handle, slot);

        if (ret != LT_OK) {
            LT_PKCS11_LOG("lt_r_mem_data_erase failed with: %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }

        LT_PKCS11_RETURN(CKR_OK);
    }

    /* Handle ECC private or public keys */
    if (PKCS11_IS_VALID_ECC_PRIV_HANDLE(hObject) || PKCS11_IS_VALID_ECC_PUB_HANDLE(hObject)) {

        LT_PKCS11_LOG("Erasing ECC key slot:%u", slot);
        ret = lt_ecc_key_erase(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot);

        if (ret != LT_OK) {
            LT_PKCS11_LOG("lt_ecc_key_erase failed with: %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }

        LT_PKCS11_RETURN(CKR_OK);
    }

    LT_PKCS11_RETURN(CKR_OBJECT_HANDLE_INVALID);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    LT_PKCS11_LOG("(hSession=0x%lx, hObject=0x%lx, pTemplate=%p, ulCount=%lu)",
                   hSession, hObject, pTemplate, ulCount);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Validate parameters */
    if (!pTemplate || ulCount == 0) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    uint16_t handle_type = PKCS11_HANDLE_GET_TYPE(hObject);
    uint16_t slot = PKCS11_HANDLE_GET_SLOT(hObject);
    CK_RV rv = CKR_OK;

    if (PKCS11_IS_VALID_RMEM_HANDLE(hObject)) {

        uint8_t data_buf[TR01_R_MEM_DATA_SIZE_MAX];
        uint16_t data_size = 0;

        lt_ret_t ret = lt_r_mem_data_read(&pkcs11_ctx.lt_handle, slot, data_buf,
                                          sizeof(data_buf), &data_size);

        if (ret == LT_L3_R_MEM_DATA_READ_SLOT_EMPTY) {
            LT_PKCS11_LOG("lt_r_mem_data_read: Slot %d is empty", slot);
            LT_PKCS11_RETURN(CKR_OBJECT_HANDLE_INVALID);
        }

        if (ret != LT_OK) {
            LT_PKCS11_LOG("lt_r_mem_data_read failed with: %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }

        /* Fill in requested attributes for CKO_DATA */
        for (CK_ULONG i = 0; i < ulCount; i++) {
            switch (pTemplate[i].type) {

            case CKA_CLASS:
            {
                CK_OBJECT_CLASS obj_class = CKO_DATA;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
                    memcpy(pTemplate[i].pValue, &obj_class, sizeof(CK_OBJECT_CLASS));
                    pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_LABEL:
            {
                /* Generate label for this slot */
                char label[4]; // Max 512 slots
                snprintf(label, sizeof(label), "%u", slot);
                CK_ULONG label_len = strlen(label);

                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = label_len;
                } else if (pTemplate[i].ulValueLen >= label_len) {
                    memcpy(pTemplate[i].pValue, label, label_len);
                    pTemplate[i].ulValueLen = label_len;
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_APPLICATION:
            {
                const char *application = "TropicSquare";
                CK_ULONG app_len = strlen(application);

                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = app_len;
                } else if (pTemplate[i].ulValueLen >= app_len) {
                    memcpy(pTemplate[i].pValue, application, app_len);
                    pTemplate[i].ulValueLen = app_len;
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_VALUE:
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = data_size;
                } else if (pTemplate[i].ulValueLen >= data_size) {
                    memcpy(pTemplate[i].pValue, data_buf, data_size);
                    pTemplate[i].ulValueLen = data_size;
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;

            case CKA_TOKEN:
            {
                CK_BBOOL on_token = CK_TRUE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &on_token, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            default:
                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
            }
        }
    } else if (PKCS11_IS_VALID_ECC_PRIV_HANDLE(hObject) ||
               PKCS11_IS_VALID_ECC_PUB_HANDLE(hObject)) {

        uint8_t pubkey_buf[TR01_CURVE_P256_PUBKEY_LEN];
        lt_ecc_curve_type_t curve;
        lt_ecc_key_origin_t origin;

        lt_ret_t ret = lt_ecc_key_read(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot,
                                       pubkey_buf, sizeof(pubkey_buf), &curve, &origin);
        if (ret == LT_L3_ECC_INVALID_KEY) {
            LT_PKCS11_LOG("lt_ecc_key_read failed with: Slot %u is empty", slot);
            LT_PKCS11_RETURN(CKR_OBJECT_HANDLE_INVALID);
        }
        if (ret != LT_OK) {
            LT_PKCS11_LOG("lt_ecc_key_read failed with: %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }

        CK_BBOOL is_private = (handle_type == PKCS11_HANDLE_TYPE_ECC_PRIVKEY);
        uint16_t pubkey_len = (curve == TR01_CURVE_P256) ? TR01_CURVE_P256_PUBKEY_LEN :
                                                           TR01_CURVE_ED25519_PUBKEY_LEN;


        /* Fill in requested attributes for ECC key */
        for (CK_ULONG i = 0; i < ulCount; i++) {
            switch (pTemplate[i].type) {

            case CKA_CLASS:
            {
                LT_PKCS11_LOG("CKA_CLASS");

                CK_OBJECT_CLASS obj_class = is_private ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
                    memcpy(pTemplate[i].pValue, &obj_class, sizeof(CK_OBJECT_CLASS));
                    pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_ID:
                LT_PKCS11_LOG("CKA_ID");

                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = 1;
                } else if (pTemplate[i].ulValueLen >= 1) {
                    *((uint8_t*)pTemplate[i].pValue) = slot;
                    pTemplate[i].ulValueLen = 1;
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;

            case CKA_KEY_TYPE:
            {
                LT_PKCS11_LOG("CKA_KEY_TYPE");

                CK_KEY_TYPE key_type = (curve == TR01_CURVE_P256) ? CKK_EC : CKK_EC_EDWARDS;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                    memcpy(pTemplate[i].pValue, &key_type, sizeof(CK_KEY_TYPE));
                    pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_VALUE:
                LT_PKCS11_LOG("CKA_VALUE");

                /* For public keys, return the public key value */
                /* For private keys, this is sensitive - return CKR_ATTRIBUTE_SENSITIVE per PKCS#11 spec */
                if (is_private) {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_SENSITIVE;  /* Private key value cannot be extracted */
                } else {
                    if (pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = pubkey_len;
                    } else if (pTemplate[i].ulValueLen >= pubkey_len) {
                        memcpy(pTemplate[i].pValue, pubkey_buf, pubkey_len);
                        pTemplate[i].ulValueLen = pubkey_len;
                    } else {
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                break;

            case CKA_EC_POINT: {
                LT_PKCS11_LOG("CKA_EC_POINT");

                /* Return DER-encoded OCTET STRING containing uncompressed EC point */
                /* Format: 04 <len> 04 <X> <Y> */
                /* For P-256: 04 41 04 <32 bytes X> <32 bytes Y> = 67 bytes total */
                /* For Ed25519: 04 21 04 <32 bytes> = 35 bytes total */
                if (is_private) {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                } else {
                    /* Build DER OCTET STRING: 04 <len> <uncompressed_point> */
                    /* Uncompressed point is: 04 <X> <Y> for P-256 (65 bytes) */
                    /*                    or: <Y> for Ed25519 (32 bytes, no prefix) */
                    uint8_t ec_point[68];  /* Max size: 04 41 04 + 64 bytes */
                    CK_ULONG ec_point_len;

                    if (curve == TR01_CURVE_P256) {
                        /* P-256: OCTET STRING { 04 || X || Y } */
                        ec_point[0] = 0x04;  /* OCTET STRING tag */
                        ec_point[1] = 65;    /* Length: 1 + 64 */
                        ec_point[2] = 0x04;  /* Uncompressed point marker */
                        memcpy(&ec_point[3], pubkey_buf, 64);
                        ec_point_len = 67;
                    } else {
                        /* Ed25519: OCTET STRING { Y } */
                        ec_point[0] = 0x04;  /* OCTET STRING tag */
                        ec_point[1] = 32;    /* Length */
                        memcpy(&ec_point[2], pubkey_buf, 32);
                        ec_point_len = 34;
                    }

                    if (pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = ec_point_len;
                    } else if (pTemplate[i].ulValueLen >= ec_point_len) {
                        memcpy(pTemplate[i].pValue, ec_point, ec_point_len);
                        pTemplate[i].ulValueLen = ec_point_len;
                    } else {
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                break;
            }

            case CKA_SIGN:
            {
                LT_PKCS11_LOG("CKA_SIGN");

                /* Private keys can sign */
                CK_BBOOL can_sign = is_private ? CK_TRUE : CK_FALSE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &can_sign, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_VERIFY:
            {
                LT_PKCS11_LOG("CKA_VERIFY");

                /* Public keys can verify */
                CK_BBOOL can_verify = is_private ? CK_FALSE : CK_TRUE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &can_verify, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            /* Attributes that are always FALSE for our keys */
            case CKA_DECRYPT:
            case CKA_ENCRYPT:
            case CKA_WRAP:
            case CKA_UNWRAP:
            case CKA_DERIVE:
            case CKA_SIGN_RECOVER:
            case CKA_VERIFY_RECOVER:
            {
                CK_BBOOL attr_false = CK_FALSE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &attr_false, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            /* Private key specific attributes */
            case CKA_SENSITIVE:
            case CKA_ALWAYS_SENSITIVE:
            case CKA_NEVER_EXTRACTABLE:
            {
                /* Private keys are always sensitive and never extractable */
                CK_BBOOL attr_val = is_private ? CK_TRUE : CK_FALSE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &attr_val, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_EXTRACTABLE:
            {
                LT_PKCS11_LOG("CKA_EXTRACTABLE");

                /* Private keys are NEVER extractable from TROPIC01 */
                CK_BBOOL extractable = CK_FALSE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &extractable, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_LOCAL:
            {
                LT_PKCS11_LOG("CKA_LOCAL");

                /* Keys generated on chip are local */
                CK_BBOOL is_local = (origin == TR01_CURVE_GENERATED) ? CK_TRUE : CK_FALSE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &is_local, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_ALWAYS_AUTHENTICATE:
            {
                LT_PKCS11_LOG("CKA_ALWAYS_AUTHENTICATE");

                /* We don't require per-operation authentication */
                CK_BBOOL always_auth = CK_FALSE;
                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                    memcpy(pTemplate[i].pValue, &always_auth, sizeof(CK_BBOOL));
                    pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_EC_PARAMS:
            {
                LT_PKCS11_LOG("CKA_EC_PARAMS");

                /* Return DER-encoded curve OID */
                const CK_BYTE *ec_params;
                CK_ULONG ec_params_len;

                if (curve == TR01_CURVE_P256) {
                    /* secp256r1 OID: 1.2.840.10045.3.1.7 */
                    static const CK_BYTE p256_oid[] = {
                        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
                    };
                    ec_params = p256_oid;
                    ec_params_len = sizeof(p256_oid);
                } else {
                    /* Ed25519 OID: 1.3.101.112 */
                    static const CK_BYTE ed25519_oid[] = {
                        0x06, 0x03, 0x2B, 0x65, 0x70
                    };
                    ec_params = ed25519_oid;
                    ec_params_len = sizeof(ed25519_oid);
                }

                if (pTemplate[i].pValue == NULL) {
                    pTemplate[i].ulValueLen = ec_params_len;
                } else if (pTemplate[i].ulValueLen >= ec_params_len) {
                    memcpy(pTemplate[i].pValue, ec_params, ec_params_len);
                    pTemplate[i].ulValueLen = ec_params_len;
                } else {
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
                break;
            }

            case CKA_LABEL:
                // Pass dummy label with zero length.
                pTemplate[i].ulValueLen = 0;
                break;

            default:
                pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
            }
        }
    }
    else {
        LT_PKCS11_RETURN(CKR_OBJECT_HANDLE_INVALID);
    }

    LT_PKCS11_LOG("0x%lx", rv);
    return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pTemplate=%p, ulCount=%lu)",
                   hSession, pTemplate, ulCount);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Check if find operation already active */
    if (pkcs11_ctx.find_active) {
        LT_PKCS11_RETURN(CKR_OPERATION_ACTIVE);
    }

    /* Parse template to find object class and label filter */
    pkcs11_ctx.find_active = CK_TRUE;
    pkcs11_ctx.find_rmem_index = 0;
    pkcs11_ctx.find_ecc_index = 0;
    pkcs11_ctx.find_ecc_done = CK_FALSE;

    pkcs11_ctx.find_slot = 0;
    pkcs11_ctx.find_slot_set = CK_FALSE;
    pkcs11_ctx.find_class = 0;
    pkcs11_ctx.find_class_set = CK_FALSE;

    for (CK_ULONG i = 0; i < ulCount; i++) {

        if (pTemplate[i].type == CKA_CLASS &&
            pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {

            pkcs11_ctx.find_class = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
            pkcs11_ctx.find_class_set = CK_TRUE;
            LT_PKCS11_LOG("  Filter CKA_CLASS = 0x%lx", pkcs11_ctx.find_class);

        } else if (pTemplate[i].type == CKA_LABEL &&
                   pTemplate[i].pValue &&
                   pTemplate[i].ulValueLen > 0) {

            /* Parse CKA_LABEL as slot number for R-Memory slots */
            char temp[16] = {0};
            CK_ULONG copy_len = TRIM_LENGTH(pTemplate[i].ulValueLen, 15);
            memcpy(temp, pTemplate[i].pValue, copy_len);
            pkcs11_ctx.find_slot = (CK_ULONG)atoi(temp);
            pkcs11_ctx.find_slot_set = CK_TRUE;

            LT_PKCS11_LOG("  Filter CKA_LABEL = '%s' (slot %lu)", temp, pkcs11_ctx.find_slot);

        } else if (pTemplate[i].type == CKA_ID &&
                   pTemplate[i].pValue &&
                   pTemplate[i].ulValueLen > 0 &&
                   !pkcs11_ctx.find_slot_set) {

            /* Parse CKA_ID as slot number for ECC key slots */
            pkcs11_ctx.find_slot = *((uint8_t*)pTemplate[i].pValue);
            pkcs11_ctx.find_slot_set = CK_TRUE;

            LT_PKCS11_LOG("  Filter CKA_ID = %02lu", pkcs11_ctx.find_slot);
        }
    }

    LT_PKCS11_LOG("(class=0x%lx, class_set=%d slot=%lu slot_set=%d)",
                    pkcs11_ctx.find_class, pkcs11_ctx.find_class_set,
                    pkcs11_ctx.find_slot, pkcs11_ctx.find_slot_set);

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    LT_PKCS11_LOG("(hSession=0x%lx, phObject=%p, ulMaxObjectCount=%lu, pulObjectCount=%p)",
                  hSession, phObject, ulMaxObjectCount, pulObjectCount);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Check if find operation is active */
    if (!pkcs11_ctx.find_active) {
        LT_PKCS11_RETURN(CKR_OPERATION_NOT_INITIALIZED);
    }

    /* Validate parameters */
    if (!phObject || !pulObjectCount) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    *pulObjectCount = 0;

    CK_BBOOL search_rmem = CK_FALSE;
    CK_BBOOL search_ecc = CK_FALSE;

    if (pkcs11_ctx.find_class_set == CK_TRUE) {
        if (pkcs11_ctx.find_class == CKO_PRIVATE_KEY ||
            pkcs11_ctx.find_class == CKO_PUBLIC_KEY) {
            search_ecc = CK_TRUE;
        } else if (pkcs11_ctx.find_class == CKO_DATA) {
            search_rmem = CK_TRUE;
        }
    } else {
        search_ecc = CK_TRUE;
        search_rmem = CK_TRUE;
    }

    LT_PKCS11_LOG("search_ecc:  %d", search_ecc);
    LT_PKCS11_LOG("search_rmem: %d", search_rmem);

    if (search_rmem) {
        uint8_t temp_buf[TR01_R_MEM_DATA_SIZE_MAX];
        uint16_t read_size;

        while (pkcs11_ctx.find_rmem_index <= TR01_R_MEM_DATA_SLOT_MAX &&
               *pulObjectCount < ulMaxObjectCount) {

            uint16_t slot = pkcs11_ctx.find_rmem_index++;

            /* If filtering by slot, skip slots that don't match */
            if (pkcs11_ctx.find_slot_set && slot != (uint16_t)pkcs11_ctx.find_slot) {
                continue;
            }

            lt_ret_t ret = lt_r_mem_data_read(&pkcs11_ctx.lt_handle, slot, temp_buf,
                                              sizeof(temp_buf), &read_size);

            /* Skip empty slots (LT_L3_R_MEM_DATA_READ_SLOT_EMPTY) */
            if (ret != LT_OK) {
                continue;
            }

            phObject[*pulObjectCount] = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_RMEM_DATA, slot);
            (*pulObjectCount)++;

            printf("Found USER-DATA in R-Memory slot: %u\n", slot);
        }
    }

    if (search_ecc && !pkcs11_ctx.find_ecc_done) {

        uint8_t pubkey_buf[TR01_CURVE_P256_PUBKEY_LEN];

        lt_ecc_curve_type_t curve;
        lt_ecc_key_origin_t origin;

        while (pkcs11_ctx.find_ecc_index <= TR01_ECC_SLOT_31 &&
               *pulObjectCount < ulMaxObjectCount) {
            uint8_t slot = pkcs11_ctx.find_ecc_index++;

            /* If filtering by ID, skip slots that don't match */
            if (pkcs11_ctx.find_slot_set && slot != (uint8_t)pkcs11_ctx.find_slot) {
                continue;
            }

            lt_ret_t ret = lt_ecc_key_read(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot,
                                           pubkey_buf, sizeof(pubkey_buf), &curve, &origin);

            /* Skip empty slots */
            if (ret != LT_OK) {
                continue;
            }

            if (*pulObjectCount >= ulMaxObjectCount) {
                break;
            }

            /* Found a valid key - add private key handle (if searching for privkey or all) */
            if (!pkcs11_ctx.find_class_set || pkcs11_ctx.find_class == CKO_PRIVATE_KEY) {
                phObject[*pulObjectCount] = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PRIVKEY, slot);
                (*pulObjectCount)++;
                printf("Found PRIVATE KEY in ECC slot %u (handle=0x%lx, curve=%d)\n",
                        slot, phObject[*pulObjectCount - 1], curve);
            }

            if (*pulObjectCount >= ulMaxObjectCount) {
                break;
            }

            /* Add public key handle (if searching for pubkey or all) */
            if (!pkcs11_ctx.find_class_set || pkcs11_ctx.find_class == CKO_PUBLIC_KEY) {
                phObject[*pulObjectCount] = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PUBKEY, slot);
                (*pulObjectCount)++;
                printf("Found PUBLIC KEY in ECC slot %u (handle=0x%lx, curve=%d)\n",
                    slot, phObject[*pulObjectCount - 1], curve);
            }
        }

        if (pkcs11_ctx.find_ecc_index > TR01_ECC_SLOT_31) {
            pkcs11_ctx.find_ecc_done = CK_TRUE;
        }
    }

    LT_PKCS11_LOG("C_FindObjects OK (found %lu objects)", *pulObjectCount);
    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    LT_PKCS11_LOG("(hSession=0x%lx)", hSession);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Check if find operation is active */
    if (!pkcs11_ctx.find_active) {
        LT_PKCS11_RETURN(CKR_OPERATION_NOT_INITIALIZED);
    }

    /* Clear find state */
    pkcs11_ctx.find_active = CK_FALSE;
    pkcs11_ctx.find_rmem_index = 0;
    pkcs11_ctx.find_ecc_index = 0;
    pkcs11_ctx.find_ecc_done = CK_FALSE;

    pkcs11_ctx.find_class = 0;
    pkcs11_ctx.find_class_set = CK_FALSE;
    pkcs11_ctx.find_slot = 0;
    pkcs11_ctx.find_slot_set = CK_FALSE;

    LT_PKCS11_RETURN(CKR_OK);
}


CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pRandomData=%p, ulRandomLen=%lu)",
                  hSession, pRandomData, ulRandomLen);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open (secure session established) */
    if (!pkcs11_ctx.session_open) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Verify session handle */
    if (hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Per PKCS#11 spec: requesting 0 bytes is valid and should just succeed */
    if (ulRandomLen == 0) {
        LT_PKCS11_RETURN(CKR_OK);
    }

    /* Validate output buffer */
    if (!pRandomData) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

   /* -----------------------------------------------------------------------
    *  GET RANDOM BYTES FROM HARDWARE RNG
    * -----------------------------------------------------------------------
    *
    * TROPIC01 can return maximum 255 bytes per request (TR01_RANDOM_VALUE_GET_LEN_MAX).
    * For larger requests, we need to make multiple calls and accumulate the data.
    *
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
            LT_PKCS11_LOG("lt_random_value_get failed with: %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }

        /* Move pointer forward and decrease remaining count */
        ptr += chunk_size;
        remaining -= chunk_size;
    }

    LT_PKCS11_LOG("Random bytes (%lu bytes):", ulRandomLen);
    for (CK_ULONG i = 0; i < ulRandomLen; i++) {
        LT_PKCS11_LOG("0x%02X", pRandomData[i]);
    }

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pSeed=%p, ulSeedLen=%lu)", hSession, pSeed, ulSeedLen);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Validate parameters */
    if (!pSeed) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    // TROPIC01 has a Hardware TRNG that does not support seeding
    LT_PKCS11_RETURN(CKR_RANDOM_SEED_NOT_SUPPORTED);
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pMechanism=%p, hKey=0x%lx)", hSession, pMechanism, hKey);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Validate mechanism */
    if (!pMechanism) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    /* Check if sign operation already active */
    if (pkcs11_ctx.sign_active) {
        LT_PKCS11_RETURN(CKR_OPERATION_ACTIVE);
    }

    /* Validate key handle - must be ECC private key */
    if (!PKCS11_IS_VALID_ECC_PRIV_HANDLE(hKey)) {
        LT_PKCS11_RETURN(CKR_KEY_HANDLE_INVALID);
    }

    uint8_t slot = PKCS11_HANDLE_GET_SLOT(hKey);

    /* Read key to verify it exists and get curve type */
    uint8_t pubkey_buf[TR01_CURVE_P256_PUBKEY_LEN];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;

    lt_ret_t ret = lt_ecc_key_read(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot,
                                   pubkey_buf, sizeof(pubkey_buf), &curve, &origin);
    if (ret == LT_L3_ECC_INVALID_KEY) {
        LT_PKCS11_LOG("lt_ecc_key_read ECC slot %u is empty", slot);
        LT_PKCS11_RETURN(CKR_KEY_HANDLE_INVALID);
    }
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_ecc_key_read failed with: %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    /* Validate mechanism matches key type */
    if (pMechanism->mechanism == CKM_ECDSA) {
        if (curve != TR01_CURVE_P256) {
            LT_PKCS11_RETURN(CKR_KEY_TYPE_INCONSISTENT);
        }
    } else if (pMechanism->mechanism == CKM_EDDSA) {
        if (curve != TR01_CURVE_ED25519) {
            LT_PKCS11_RETURN(CKR_KEY_TYPE_INCONSISTENT);
        }
    } else {
        LT_PKCS11_RETURN(CKR_MECHANISM_INVALID);
    }

    /* Initialize sign state */
    pkcs11_ctx.sign_active = CK_TRUE;
    pkcs11_ctx.sign_mechanism = pMechanism->mechanism;
    pkcs11_ctx.sign_key_slot = slot;
    pkcs11_ctx.sign_key_curve = curve;

    LT_PKCS11_LOG("slot=%u, mechanism=0x%lx, curve=%d)", slot, pMechanism->mechanism, curve);
    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pData=%p, ulDataLen=%lu, pSignature=%p, pulSignatureLen=%p)",
                  hSession, pData, ulDataLen, pSignature, pulSignatureLen);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Check if sign operation is active */
    if (!pkcs11_ctx.sign_active) {
        LT_PKCS11_RETURN(CKR_OPERATION_NOT_INITIALIZED);
    }

    /* Validate parameters */
    if (!pData || ulDataLen == 0 || !pulSignatureLen) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    // TODO: Check EDDSA max message size !

    /* Signature is always 64 bytes (R + S) */
    if (pSignature == NULL) {
        // TODO: Check this
        /* Query mode - return required signature length */
        *pulSignatureLen = TR01_ECDSA_EDDSA_SIGNATURE_LENGTH;
        LT_PKCS11_LOG("Query mode: signature length = %lu", *pulSignatureLen);
        LT_PKCS11_RETURN(CKR_OK);
    }

    /* Check output buffer size */
    if (*pulSignatureLen < TR01_ECDSA_EDDSA_SIGNATURE_LENGTH) {
        *pulSignatureLen = TR01_ECDSA_EDDSA_SIGNATURE_LENGTH;
        LT_PKCS11_RETURN(CKR_BUFFER_TOO_SMALL);
    }

    /* Perform signing based on mechanism */
    if (pkcs11_ctx.sign_mechanism == CKM_ECDSA) {
        LT_PKCS11_LOG("Signing with ECDSA on slot %u", pkcs11_ctx.sign_key_slot);
        lt_ret_t ret = lt_ecc_ecdsa_sign(&pkcs11_ctx.lt_handle,
                                         (lt_ecc_slot_t)pkcs11_ctx.sign_key_slot,
                                         pData, ulDataLen, pSignature);

        if (ret != LT_OK) {
            LT_PKCS11_LOG("lt_ecc_ecdsa_sign failed with %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }

    } else {
        LT_PKCS11_LOG("Signing with EDDSA on slot %u", pkcs11_ctx.sign_key_slot);
        lt_ret_t ret = lt_ecc_eddsa_sign(&pkcs11_ctx.lt_handle,
                                         (lt_ecc_slot_t)pkcs11_ctx.sign_key_slot,
                                         pData, (uint16_t)ulDataLen, pSignature);

        if (ret != LT_OK) {
            LT_PKCS11_LOG("lt_ecc_eddsa_sign failed with %s", lt_ret_verbose(ret));
            LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
        }
    }

    /* Clear sign state (operation is complete) */
    pkcs11_ctx.sign_active = CK_FALSE;
    pkcs11_ctx.sign_mechanism = 0;
    pkcs11_ctx.sign_key_slot = 0;
    pkcs11_ctx.sign_key_curve = 0;

    *pulSignatureLen = TR01_ECDSA_EDDSA_SIGNATURE_LENGTH;

    LT_PKCS11_RETURN(CKR_OK);
}

/* Supported mechanisms */
static const CK_MECHANISM_TYPE supported_mechanisms[] = {
    CKM_EC_KEY_PAIR_GEN,  /* ECC key generation */
    CKM_ECDSA,            /* ECDSA signing */
    CKM_EDDSA             /* EdDSA signing */
};
#define NUM_MECHANISMS (sizeof(supported_mechanisms) / sizeof(supported_mechanisms[0]))

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
    LT_PKCS11_LOG("(slotID=%lu, pMechanismList=%p, pulCount=%p)",
                  slotID, pMechanismList, pulCount);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (slotID != 0) {
        LT_PKCS11_RETURN(CKR_SLOT_ID_INVALID);
    }

    if (!pulCount) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    if (pMechanismList == NULL) {
        *pulCount = NUM_MECHANISMS;
        LT_PKCS11_RETURN(CKR_OK);
    }

    if (*pulCount < NUM_MECHANISMS) {
        *pulCount = NUM_MECHANISMS;
        LT_PKCS11_RETURN(CKR_BUFFER_TOO_SMALL);
    }

    for (CK_ULONG i = 0; i < NUM_MECHANISMS; i++) {
        pMechanismList[i] = supported_mechanisms[i];
    }
    *pulCount = NUM_MECHANISMS;

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("(slotID=%lu, type=0x%lx, pInfo=%p)",
                  slotID, type, pInfo);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (slotID != 0) {
        LT_PKCS11_RETURN(CKR_SLOT_ID_INVALID);
    }

    if (!pInfo) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));

    switch (type) {
    case CKM_EC_KEY_PAIR_GEN:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_EC_F_P;
        break;
    case CKM_ECDSA:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_SIGN | CKF_EC_F_P;
        break;
    case CKM_EDDSA:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_SIGN;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pInfo=%p)", hSession, pInfo);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    if (!pInfo) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    pInfo->slotID = 0;
    pInfo->state = CKS_RW_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    pInfo->ulDeviceError = 0;

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    LT_PKCS11_LOG("(hSession=0x%lx, userType=%lu, pPin=%p, ulPinLen=%lu)",
                  hSession, userType, pPin, ulPinLen);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Validate user type per PKCS#11 spec */
    if (userType != CKU_USER && userType != CKU_SO && userType != CKU_CONTEXT_SPECIFIC) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    /* Per PKCS#11 spec: if ulPinLen > 0, pPin must not be NULL */
    if (ulPinLen > 0 && pPin == NULL) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    /*
     * TROPIC01 authentication is handled at session start via pairing keys.
     * We don't use PIN-based login - the secure session establishment already
     * authenticated the host. Accept the login as a no-op.
     */

    LT_PKCS11_RETURN(CKR_OK);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    LT_PKCS11_LOG("(hSession=0x%lx)", hSession);

    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* No-op - real session management via pairing keys */

    LT_PKCS11_RETURN(CKR_OK);
}


/* DER-encoded OID for secp256r1 (P-256): 1.2.840.10045.3.1.7 */
static const CK_BYTE OID_SECP256R1[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* DER-encoded OID for Ed25519: 1.3.101.112 */
static const CK_BYTE OID_ED25519[] = {
    0x06, 0x03, 0x2B, 0x65, 0x70
};

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    LT_PKCS11_LOG("(hSession=0x%lx, pMechanism=%p, pPublicKeyTemplate=%p, \
                   ulPublicKeyAttributeCount=%lu, pPrivateKeyTemplate=%p, \
                   ulPrivateKeyAttributeCount=%lu, phPublicKey=%p, \
                   phPrivateKey=%p)", hSession, pMechanism, pPublicKeyTemplate,
                   ulPublicKeyAttributeCount, pPrivateKeyTemplate,
                   ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);

    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_RETURN(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_RETURN(CKR_SESSION_HANDLE_INVALID);
    }

    /* Validate parameters */
    if (!pMechanism || !phPublicKey || !phPrivateKey) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    /* Check mechanism - we support EC key generation */
    if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) {
        LT_PKCS11_RETURN(CKR_MECHANISM_INVALID);
    }

    /* Parse templates to find curve (EC_PARAMS) and slot (LABEL) */
    lt_ecc_curve_type_t curve = TR01_CURVE_P256;  /* Default to P-256 */
    CK_ULONG slot_id = CK_UNAVAILABLE_INFORMATION;

    /* Check public key template for EC_PARAMS (curve) and LABEL (slot) */
    for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
        if (pPublicKeyTemplate[i].type == CKA_EC_PARAMS && pPublicKeyTemplate[i].pValue) {

            /* Check if it's secp256r1 or Ed25519 */
            if (pPublicKeyTemplate[i].ulValueLen == sizeof(OID_SECP256R1) &&
                memcmp(pPublicKeyTemplate[i].pValue, OID_SECP256R1, sizeof(OID_SECP256R1)) == 0) {
                curve = TR01_CURVE_P256;
                LT_PKCS11_LOG("  Curve: P-256 (secp256r1)");

            } else if (pPublicKeyTemplate[i].ulValueLen == sizeof(OID_ED25519) &&
                       memcmp(pPublicKeyTemplate[i].pValue, OID_ED25519, sizeof(OID_ED25519)) == 0) {
                curve = TR01_CURVE_ED25519;
                LT_PKCS11_LOG("  Curve: Ed25519");

            } else {
                LT_PKCS11_RETURN(CKR_ATTRIBUTE_VALUE_INVALID);
            }

        } else if (pPublicKeyTemplate[i].type == CKA_ID && pPublicKeyTemplate[i].pValue) {
            /* Parse ID as slot number */
            if (pPublicKeyTemplate[i].ulValueLen > 0) {
                slot_id = *((uint8_t*)pPublicKeyTemplate[i].pValue);
                LT_PKCS11_LOG("  Slot from public template: %lu", slot_id);
            }
        }
    }

    /* Also check private key template for ID */
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
            if (pPrivateKeyTemplate[i].type == CKA_ID && pPrivateKeyTemplate[i].pValue) {
                if (pPrivateKeyTemplate[i].ulValueLen > 0) {
                    slot_id = *((uint8_t*)pPublicKeyTemplate[i].pValue);
                    LT_PKCS11_LOG("  Slot from private template: %lu", slot_id);
                }
            }
        }
    }

    /* Slot must be specified explicitly via --label */
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        LT_PKCS11_RETURN(CKR_TEMPLATE_INCOMPLETE);
    }

    /* Validate slot range */
    if (slot_id > TR01_ECC_SLOT_31) {
        LT_PKCS11_RETURN(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    LT_PKCS11_LOG("Generating %s key in ECC slot %lu...",
                  (curve == TR01_CURVE_P256) ? "P-256" : "Ed25519", slot_id);

    lt_ret_t ret = lt_ecc_key_generate(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot_id, curve);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_ecc_key_generate failed with %s", lt_ret_verbose(ret));
        LT_PKCS11_RETURN(CKR_DEVICE_ERROR);
    }

    *phPrivateKey = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PRIVKEY, slot_id);
    *phPublicKey = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PUBKEY, slot_id);

    LT_PKCS11_RETURN(CKR_OK);
}

/**************************************************************************************************
* FUNCTION LIST
*
* This structure contains pointers to ALL PKCS#11 functions.
*
* Fields set to NULL indicate unimplemented functions.
* When called, the application receives CKR_FUNCTION_NOT_SUPPORTED.
***************************************************************************************************/
static const CK_FUNCTION_LIST pkcs11_fnc_list = {

    /* Cryptoki version this library implements */
    .version = {2, 40},

    /* GENERAL PURPOSE FUNCTIONS */
    .C_Initialize = C_Initialize,               /* Initialize library */
    .C_Finalize = C_Finalize,                   /* Shut down library */
    .C_GetInfo = C_GetInfo,                     /* Get library info */
    .C_GetFunctionList = C_GetFunctionList,     /* Get this function list */

    /* SLOT AND TOKEN MANAGEMENT */
    .C_GetSlotList = C_GetSlotList,             /* List available slots */
    .C_GetSlotInfo = C_GetSlotInfo,             /* Get info about a slot */
    .C_GetTokenInfo = C_GetTokenInfo,           /* Get info about token in slot */
    .C_GetMechanismList = C_GetMechanismList,   /* List supported mechanisms */
    .C_GetMechanismInfo = C_GetMechanismInfo,   /* Get mechanism info */
    .C_InitToken = NULL,                        /* Initialize a token (not implemented) */
    .C_InitPIN = NULL,                          /* Initialize user PIN (not implemented) */
    .C_SetPIN = NULL,                           /* Change user PIN (not implemented) */

    /* SESSION MANAGEMENT */
    .C_OpenSession = C_OpenSession,             /* Open a session */
    .C_CloseSession = C_CloseSession,           /* Close a session */
    .C_CloseAllSessions = NULL,                 /* Close all sessions (not implemented) */
    .C_GetSessionInfo = C_GetSessionInfo,       /* Get session info */
    .C_GetOperationState = NULL,                /* Get crypto operation state (not implemented) */
    .C_SetOperationState = NULL,                /* Set crypto operation state (not implemented) */
    .C_Login = C_Login,                         /* No-op login (auth via pairing keys) */
    .C_Logout = C_Logout,                       /* No-op logout */

    /* OBJECT MANAGEMENT */
    .C_CreateObject = C_CreateObject,           /* Create data object in R-MEM */
    .C_CopyObject = NULL,                       /* Copy an object (not implemented) */
    .C_DestroyObject = C_DestroyObject,         /* Erase data from R-MEM */
    .C_GetObjectSize = NULL,                    /* Get object size (not implemented) */
    .C_GetAttributeValue = C_GetAttributeValue, /* Read data from R-MEM */
    .C_SetAttributeValue = NULL,                /* Set object attributes (not implemented) */
    .C_FindObjectsInit = C_FindObjectsInit,     /* Start R-MEM enumeration */
    .C_FindObjects = C_FindObjects,             /* Find non-empty R-MEM slots */
    .C_FindObjectsFinal = C_FindObjectsFinal,   /* End R-MEM enumeration */

    /* ENCRYPTION FUNCTIONS */
    .C_EncryptInit = NULL,                      /* Initialize encryption (not implemented) */
    .C_Encrypt = NULL,                          /* Encrypt data (not implemented) */
    .C_EncryptUpdate = NULL,                    /* Continue multi-part encryption (not implemented) */
    .C_EncryptFinal = NULL,                     /* Finish multi-part encryption (not implemented) */

    /* DECRYPTION FUNCTIONS */
    .C_DecryptInit = NULL,                      /* Initialize decryption (not implemented) */
    .C_Decrypt = NULL,                          /* Decrypt data (not implemented) */
    .C_DecryptUpdate = NULL,                    /* Continue multi-part decryption (not implemented) */
    .C_DecryptFinal = NULL,                     /* Finish multi-part decryption (not implemented) */

    /* MESSAGE DIGESTING (HASHING) FUNCTIONS */
    .C_DigestInit = NULL,                       /* Initialize digest (not implemented) */
    .C_Digest = NULL,                           /* Compute digest (not implemented) */
    .C_DigestUpdate = NULL,                     /* Continue multi-part digest (not implemented) */
    .C_DigestKey = NULL,                        /* Include key in digest (not implemented) */
    .C_DigestFinal = NULL,                      /* Finish multi-part digest (not implemented) */

    /* SIGNING AND MACING FUNCTIONS */
    .C_SignInit = C_SignInit,                   /* Initialize ECDSA/EdDSA signing */
    .C_Sign = C_Sign,                           /* Perform signature on TROPIC01 */
    .C_SignUpdate = NULL,                       /* Continue multi-part signing (not implemented) */
    .C_SignFinal = NULL,                        /* Finish multi-part signing (not implemented) */
    .C_SignRecoverInit = NULL,                  /* Init signing with data recovery (not implemented) */
    .C_SignRecover = NULL,                      /* Sign with data recovery (not implemented) */

    /* SIGNATURE VERIFICATION FUNCTIONS */
    .C_VerifyInit = NULL,                       /* Initialize verification (not implemented) */
    .C_Verify = NULL,                           /* Verify signature (not implemented) */
    .C_VerifyUpdate = NULL,                     /* Continue multi-part verification (not implemented) */
    .C_VerifyFinal = NULL,                      /* Finish multi-part verification (not implemented) */
    .C_VerifyRecoverInit = NULL,                /* Init verify with data recovery (not implemented) */
    .C_VerifyRecover = NULL,                    /* Verify with data recovery (not implemented) */

    /* DUAL-FUNCTION CRYPTOGRAPHIC OPERATIONS */
    .C_DigestEncryptUpdate = NULL,              /* Digest + encrypt combined (not implemented) */
    .C_DecryptDigestUpdate = NULL,              /* Decrypt + digest combined (not implemented) */
    .C_SignEncryptUpdate = NULL,                /* Sign + encrypt combined (not implemented) */
    .C_DecryptVerifyUpdate = NULL,              /* Decrypt + verify combined (not implemented) */

    /* KEY MANAGEMENT FUNCTIONS */
    .C_GenerateKey = NULL,                      /* Generate symmetric key (not implemented) */
    .C_GenerateKeyPair = C_GenerateKeyPair,     /* Generate ECC key pair (P-256 or Ed25519) */
    .C_WrapKey = NULL,                          /* Wrap (encrypt) a key (not implemented) */
    .C_UnwrapKey = NULL,                        /* Unwrap (decrypt) a key (not implemented) */
    .C_DeriveKey = NULL,                        /* Derive a key from another (not implemented) */

    /* RANDOM NUMBER GENERATION - OUR MAIN FEATURE! */
    .C_SeedRandom = C_SeedRandom,               /* Returns CKR_RANDOM_SEED_NOT_SUPPORTED (HWRNG) */
    .C_GenerateRandom = C_GenerateRandom,       /* *** GENERATE RANDOM BYTES FROM TROPIC01 *** */

    /* PARALLEL FUNCTION MANAGEMENT (DEPRECATED) */
    .C_GetFunctionStatus = NULL,                /* Get parallel operation status (deprecated) */
    .C_CancelFunction = NULL,                   /* Cancel parallel operation (deprecated) */
    .C_WaitForSlotEvent = NULL,                 /* Wait for slot events (not implemented) */
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    LT_PKCS11_LOG("(ppFunctionList=0x%p)", ppFunctionList);

    /* Validate parameter */
    if (!ppFunctionList) {
        LT_PKCS11_RETURN(CKR_ARGUMENTS_BAD);
    }

    *ppFunctionList = (CK_FUNCTION_LIST_PTR)(&pkcs11_fnc_list);

    LT_PKCS11_RETURN(CKR_OK);
}

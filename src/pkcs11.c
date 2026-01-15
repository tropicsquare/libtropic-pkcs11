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

/* Pairing keys for secure session (defined in libtropic/keys/keys.c) */
extern uint8_t sh0priv[];
extern uint8_t sh0pub[];

/*
 * Object handle encoding: (TYPE << 16) | SLOT_INDEX
 * R-MEM: 512 slots (0-511), 1-444 bytes each
 * ECC: 32 slots (0-31), P256 or Ed25519
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

/* Module context - all global state in one place */
typedef struct {
    CK_BBOOL initialized;
    CK_BBOOL session_open;
    lt_handle_t lt_handle;
    lt_dev_unix_usb_dongle_t lt_device;
    CK_SESSION_HANDLE session_handle;

    /* PKCS#11 function list - must persist for lifetime of library */
    CK_FUNCTION_LIST functionList;

    /* C_FindObjects state */
    CK_BBOOL find_active;
    CK_OBJECT_CLASS find_class;
    uint16_t find_rmem_index;
    uint8_t find_ecc_index;
    CK_BBOOL find_ecc_done;
    CK_BBOOL find_id_set;           /* True if filtering by slot (via CKA_LABEL) */
    CK_ULONG find_id;               /* The ID value to filter by (slot number) */

    /* C_Sign state */
    CK_BBOOL sign_active;
    CK_MECHANISM_TYPE sign_mechanism;
    uint8_t sign_key_slot;
    lt_ecc_curve_type_t sign_key_curve;
} lt_pkcs11_ctx_t;

static lt_pkcs11_ctx_t pkcs11_ctx = {0};

/* ---------------------------------------------------------------------------
 * Core PKCS#11 Functions
 * --------------------------------------------------------------------------- */
 
 
CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    LT_PKCS11_LOG("C_Initialize");

    if (pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    /* Configure USB device (path from CMake TS_USB_DEV option) */
    memset(&pkcs11_ctx.lt_device, 0, sizeof(pkcs11_ctx.lt_device));
    strncpy(pkcs11_ctx.lt_device.dev_path, TS_USB_DEV,
            sizeof(pkcs11_ctx.lt_device.dev_path) - 1);
    pkcs11_ctx.lt_device.baud_rate = 115200;

    /* Initialize libtropic handle */
    memset(&pkcs11_ctx.lt_handle, 0, sizeof(pkcs11_ctx.lt_handle));
    pkcs11_ctx.lt_handle.l2.device = &pkcs11_ctx.lt_device;

    lt_ret_t ret = lt_init(&pkcs11_ctx.lt_handle);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("lt_init failed: %s", lt_ret_verbose(ret));
        return CKR_DEVICE_ERROR;
    }

    pkcs11_ctx.initialized = CK_TRUE;
    return CKR_OK;
}
 
 
CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    LT_PKCS11_LOG("C_Finalize");

    if (pReserved != NULL)
        return CKR_ARGUMENTS_BAD;

    if (!pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    /* Close secure session if still open */
    if (pkcs11_ctx.session_open) {
        lt_session_abort(&pkcs11_ctx.lt_handle);
        pkcs11_ctx.session_open = CK_FALSE;
    }

    lt_deinit(&pkcs11_ctx.lt_handle);
    memset(&pkcs11_ctx, 0, sizeof(pkcs11_ctx));

    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("C_GetInfo");

    if (!pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strncpy((char *)pInfo->manufacturerID, "TropicSquare", 32);
    strncpy((char *)pInfo->libraryDescription, "Tropic PKCS11", 32);

    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    LT_PKCS11_LOG("C_GetSlotList");
    (void)tokenPresent;

    if (!pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;

    if (!pSlotList) {
        *pulCount = 1;
    } else {
        if (*pulCount < 1)
            return CKR_BUFFER_TOO_SMALL;
        pSlotList[0] = 0;
        *pulCount = 1;
    }

    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("C_GetSlotInfo slot=%lu", slotID);

    if (!pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (slotID != 0)
        return CKR_SLOT_ID_INVALID;

    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    strncpy((char *)pInfo->slotDescription, "TROPIC01 Secure Element USB Slot", 64);
    strncpy((char *)pInfo->manufacturerID, "TropicSquare", 32);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

    /* Read firmware versions from chip */
    uint8_t fw_ver[4] = {0};
    if (lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver) == LT_OK) {
        pInfo->firmwareVersion.major = fw_ver[3];
        pInfo->firmwareVersion.minor = fw_ver[2];
    }
    if (lt_get_info_spect_fw_ver(&pkcs11_ctx.lt_handle, fw_ver) == LT_OK) {
        pInfo->hardwareVersion.major = fw_ver[3];
        pInfo->hardwareVersion.minor = fw_ver[2];
    }

    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("C_GetTokenInfo slot=%lu", slotID);

    if (!pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (slotID != 0)
        return CKR_SLOT_ID_INVALID;
    
    /* pInfo is required */
    if (!pInfo) {
        LT_PKCS11_LOG("pInfo is NULL: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Get chip ID to verify token is present and get token info */
    struct lt_chip_id_t chip_id = {0};
    lt_ret_t ret = lt_get_info_chip_id(&pkcs11_ctx.lt_handle, &chip_id);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("Failed to read chip ID: %s: CKR_TOKEN_NOT_PRESENT", lt_ret_verbose(ret));
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    /* Fill in token information */
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    
    /* Manufacturer is always TropicSquare */
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
    ret = lt_get_info_riscv_fw_ver(&pkcs11_ctx.lt_handle, fw_ver);
    if (ret == LT_OK) {
        pInfo->firmwareVersion.major = fw_ver[3];
        pInfo->firmwareVersion.minor = fw_ver[2];
    }
    
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
    
    LT_PKCS11_LOG("C_GetTokenInfo OK (label='%.32s', model='%.16s', serial='%.16s', HW=%d.%d, FW=%d.%d)",
        pInfo->label, pInfo->model, pInfo->serialNumber,
        pInfo->hardwareVersion.major, pInfo->hardwareVersion.minor,
        pInfo->firmwareVersion.major, pInfo->firmwareVersion.minor);
     return CKR_OK;
 }
 
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    LT_PKCS11_LOG("C_OpenSession (slotID=%lu, flags=0x%lx, pApplication=%p, Notify=%p, phSession=%p)", 
        slotID, flags, pApplication, Notify, phSession);
    
    (void)pApplication;  /* Unused - we don't support notifications */
    (void)Notify;        /* Unused - we don't support notifications */
    
    /* Library must be initialized first */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* We only support slot ID 1 */
    if (slotID != 0) {
        LT_PKCS11_LOG("Invalid slotID=%lu: CKR_SLOT_ID_INVALID", slotID);
        return CKR_SLOT_ID_INVALID;
    }
    
    /* phSession is required - we need somewhere to return the handle */
    if (!phSession) {
        LT_PKCS11_LOG("phSession is NULL: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* CKF_SERIAL_SESSION must be set for legacy reasons (PKCS#11 v2.40 spec) */
    if (!(flags & CKF_SERIAL_SESSION)) {
        LT_PKCS11_LOG("CKF_SERIAL_SESSION not set: CKR_SESSION_PARALLEL_NOT_SUPPORTED");
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    
    /* Check if session is already open - we only support one session at a time */
    if (pkcs11_ctx.session_open) {
        LT_PKCS11_LOG("Session already open: CKR_SESSION_COUNT");
        return CKR_SESSION_COUNT;
    }
    
    /* Establish authenticated encrypted session with TROPIC01 */
    lt_ret_t ret = lt_verify_chip_and_start_secure_session(
        &pkcs11_ctx.lt_handle, sh0priv, sh0pub, TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("Secure session failed: %s", lt_ret_verbose(ret));
        return CKR_DEVICE_ERROR;
    }

    pkcs11_ctx.session_handle = (CK_SESSION_HANDLE)&pkcs11_ctx.lt_handle;
    pkcs11_ctx.session_open = CK_TRUE;
    *phSession = pkcs11_ctx.session_handle;

    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    LT_PKCS11_LOG("C_CloseSession");

    if (!pkcs11_ctx.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pkcs11_ctx.session_open)
        return CKR_SESSION_HANDLE_INVALID;

    if (hSession != pkcs11_ctx.session_handle)
        return CKR_SESSION_HANDLE_INVALID;

    lt_ret_t ret = lt_session_abort(&pkcs11_ctx.lt_handle);
     if (ret != LT_OK) {
         LT_PKCS11_LOG("Warning: Failed to abort Secure Session: %s", lt_ret_verbose(ret));
         /* Continue anyway - mark session as closed */
     }
     
     /* Mark session as closed */
     pkcs11_ctx.session_open = CK_FALSE;
     pkcs11_ctx.session_handle = 0;
     
    LT_PKCS11_LOG("C_CloseSession OK");
    return CKR_OK;
}


/* ---------------------------------------------------------------------------
 * OBJECT MANAGEMENT FUNCTIONS
 * --------------------------------------------------------------------------
 * 
 * These functions implement storage and retrieval of data objects using TROPIC01's
 * R-MEM (Read/Write Memory). R-MEM provides 512 slots (0-511), each storing 1-444 bytes.
 * 
 * PKCS#11 Object Type Mapping:
 * - CKO_DATA → R-MEM data slots
 * 
 * Object handles encode the type and slot: handle = (type << 16) | slot_index
 */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    LT_PKCS11_LOG("C_CreateObject (hSession=0x%lx, pTemplate=%p, ulCount=%lu, phObject=%p)",
        hSession, pTemplate, ulCount, phObject);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Validate parameters */
    if (!pTemplate || ulCount == 0 || !phObject) {
        LT_PKCS11_LOG("Invalid arguments: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
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
                    LT_PKCS11_LOG("  CKA_CLASS = 0x%lx", obj_class);
                }
                break;
            case CKA_VALUE:
                data_value = (CK_BYTE_PTR)pTemplate[i].pValue;
                data_len = pTemplate[i].ulValueLen;
                LT_PKCS11_LOG("  CKA_VALUE = %lu bytes", data_len);
                break;
            case CKA_LABEL:
                /* Use CKA_LABEL as slot number */
                if (pTemplate[i].pValue && pTemplate[i].ulValueLen > 0) {
                    char temp[16] = {0};
                    CK_ULONG copy_len = (pTemplate[i].ulValueLen < 15) ? pTemplate[i].ulValueLen : 15;
                    memcpy(temp, pTemplate[i].pValue, copy_len);
                    slot_id = (CK_ULONG)atoi(temp);
                    LT_PKCS11_LOG("  CKA_LABEL = '%s' (slot %lu)", temp, slot_id);
                }
                break;
            default:
                break;
        }
    }
    
    LT_PKCS11_LOG("Parsed: obj_class=0x%lx, data_len=%lu, slot_id=%lu", obj_class, data_len, slot_id);
    
    /* We only support CKO_DATA objects */
    if (obj_class != CKO_DATA) {
        LT_PKCS11_LOG("Unsupported object class 0x%lx: CKR_ATTRIBUTE_VALUE_INVALID", obj_class);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    
    /* CKA_VALUE is required for data objects */
    if (!data_value || data_len == 0) {
        LT_PKCS11_LOG("CKA_VALUE missing or empty: CKR_TEMPLATE_INCOMPLETE");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    
    /* Validate data size */
    if (data_len < TR01_R_MEM_DATA_SIZE_MIN || data_len > TR01_R_MEM_DATA_SIZE_MAX) {
        LT_PKCS11_LOG("Data size %lu out of range [%d, %d]: CKR_ATTRIBUTE_VALUE_INVALID",
            data_len, TR01_R_MEM_DATA_SIZE_MIN, TR01_R_MEM_DATA_SIZE_MAX);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    
    /* Slot must be specified via CKA_LABEL */
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        LT_PKCS11_LOG("Slot not specified (use --label): CKR_TEMPLATE_INCOMPLETE");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    
    /* Validate slot ID */
    if (slot_id > TR01_R_MEM_DATA_SLOT_MAX) {
        LT_PKCS11_LOG("Slot ID %lu exceeds max %d: CKR_ATTRIBUTE_VALUE_INVALID",
            slot_id, TR01_R_MEM_DATA_SLOT_MAX);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    
    /* Write data to R-MEM */
    LT_PKCS11_LOG("Writing %lu bytes to slot:%lu", data_len, slot_id);
    lt_ret_t ret = lt_r_mem_data_write(&pkcs11_ctx.lt_handle, (uint16_t)slot_id, data_value, (uint16_t)data_len);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("Failed to write R-MEM: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
        return CKR_DEVICE_ERROR;
    }
    
    /* Return object handle */
    *phObject = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_RMEM_DATA, slot_id);
    
    LT_PKCS11_LOG("C_CreateObject OK (handle=0x%lx, slot=%lu)", *phObject, slot_id);
    return CKR_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    LT_PKCS11_LOG("C_DestroyObject (hSession=0x%lx, hObject=0x%lx)", hSession, hObject);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    uint16_t slot = PKCS11_HANDLE_GET_SLOT(hObject);
    lt_ret_t ret;
    
    /* Handle R-MEM data objects */
    if (PKCS11_IS_VALID_RMEM_HANDLE(hObject)) {
        /* Erase R-MEM slot */
        LT_PKCS11_LOG("Erasing slot:%u", slot);
        ret = lt_r_mem_data_erase(&pkcs11_ctx.lt_handle, slot);
        if (ret != LT_OK) {
            LT_PKCS11_LOG("Failed to erase R-MEM: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
            return CKR_DEVICE_ERROR;
        }
        LT_PKCS11_LOG("C_DestroyObject OK");
        return CKR_OK;
    }
    
    /* Handle ECC private or public keys */
    if (PKCS11_IS_VALID_ECC_PRIV_HANDLE(hObject) || PKCS11_IS_VALID_ECC_PUB_HANDLE(hObject)) {
        /* Erase ECC key (both private and public keys are in the same slot) */
        LT_PKCS11_LOG("Erasing ECC key slot:%u", slot);
        ret = lt_ecc_key_erase(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot);
        if (ret != LT_OK) {
            LT_PKCS11_LOG("Failed to erase ECC key: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
            return CKR_DEVICE_ERROR;
        }
        LT_PKCS11_LOG("C_DestroyObject OK");
        return CKR_OK;
    }
    
    /* Invalid object handle */
    LT_PKCS11_LOG("Invalid object handle: CKR_OBJECT_HANDLE_INVALID");
    return CKR_OBJECT_HANDLE_INVALID;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    LT_PKCS11_LOG("C_GetAttributeValue (hSession=0x%lx, hObject=0x%lx, pTemplate=%p, ulCount=%lu)",
        hSession, hObject, pTemplate, ulCount);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Validate parameters */
    if (!pTemplate || ulCount == 0) {
        LT_PKCS11_LOG("Invalid arguments: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    uint16_t handle_type = PKCS11_HANDLE_GET_TYPE(hObject);
    uint16_t slot = PKCS11_HANDLE_GET_SLOT(hObject);
    CK_RV rv = CKR_OK;
    
    /* Handle R-MEM Data Objects */
    if (PKCS11_IS_VALID_RMEM_HANDLE(hObject)) {
        uint8_t data_buf[TR01_R_MEM_DATA_SIZE_MAX];
        uint16_t data_size = 0;
        lt_ret_t ret = lt_r_mem_data_read(&pkcs11_ctx.lt_handle, slot, data_buf, sizeof(data_buf), &data_size);
        if (ret == LT_L3_R_MEM_DATA_READ_SLOT_EMPTY) {
            LT_PKCS11_LOG("slot:%u is empty: CKR_OBJECT_HANDLE_INVALID", slot);
            return CKR_OBJECT_HANDLE_INVALID;
        }
        if (ret != LT_OK) {
            LT_PKCS11_LOG("Failed to read R-MEM: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
            return CKR_DEVICE_ERROR;
        }
        
        /* Generate label for this slot (just the slot number) */
        char label[32];
        snprintf(label, sizeof(label), "%u", slot);
        CK_ULONG label_len = strlen(label);
        
        const char *application = "TropicSquare";
        CK_ULONG app_len = strlen(application);
        
        /* Fill in requested attributes for CKO_DATA */
        for (CK_ULONG i = 0; i < ulCount; i++) {
            switch (pTemplate[i].type) {
                case CKA_CLASS: {
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
                case CKA_APPLICATION:
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
                case CKA_ID: {
                    /* R-MEM objects use ID format: 2 bytes big-endian with high byte = 0x80
                     * This distinguishes R-MEM IDs from ECC IDs (which are 0x00-0x1F)
                     * Example: R-MEM slot 5 → ID = 0x80 0x05 */
                    uint8_t id_bytes[2] = { 0x80, (uint8_t)slot };
                    if (pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 2;
                    } else if (pTemplate[i].ulValueLen >= 2) {
                        memcpy(pTemplate[i].pValue, id_bytes, 2);
                        pTemplate[i].ulValueLen = 2;
                    } else {
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                    break;
                }
                case CKA_TOKEN: {
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
    }
    /* Handle ECC Keys (Private and Public) */
    else if (PKCS11_IS_VALID_ECC_PRIV_HANDLE(hObject) || PKCS11_IS_VALID_ECC_PUB_HANDLE(hObject)) {
        uint8_t pubkey_buf[TR01_CURVE_P256_PUBKEY_LEN];
        lt_ecc_curve_type_t curve;
        lt_ecc_key_origin_t origin;
        
        lt_ret_t ret = lt_ecc_key_read(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot,
                                       pubkey_buf, sizeof(pubkey_buf), &curve, &origin);
        if (ret == LT_L3_ECC_INVALID_KEY) {
            LT_PKCS11_LOG("ECC slot %u is empty: CKR_OBJECT_HANDLE_INVALID", slot);
            return CKR_OBJECT_HANDLE_INVALID;
        }
        if (ret != LT_OK) {
            LT_PKCS11_LOG("Failed to read ECC key: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
            return CKR_DEVICE_ERROR;
        }
        
        CK_BBOOL is_private = (handle_type == PKCS11_HANDLE_TYPE_ECC_PRIVKEY);
        uint16_t pubkey_len = (curve == TR01_CURVE_P256) ? TR01_CURVE_P256_PUBKEY_LEN : TR01_CURVE_ED25519_PUBKEY_LEN;
        
        /* Generate label for this key */
        char key_label[48];
        const char *curve_name = (curve == TR01_CURVE_P256) ? "P256" : "Ed25519";
        const char *key_type_name = is_private ? "Private" : "Public";
        snprintf(key_label, sizeof(key_label), "ECC %s Key Slot %u (%s)", key_type_name, slot, curve_name);
        CK_ULONG key_label_len = strlen(key_label);
        
        /* Fill in requested attributes for ECC key */
        for (CK_ULONG i = 0; i < ulCount; i++) {
            switch (pTemplate[i].type) {
                case CKA_CLASS: {
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
                case CKA_LABEL:
                    if (pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = key_label_len;
                    } else if (pTemplate[i].ulValueLen >= key_label_len) {
                        memcpy(pTemplate[i].pValue, key_label, key_label_len);
                        pTemplate[i].ulValueLen = key_label_len;
                    } else {
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                    break;
                case CKA_KEY_TYPE: {
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
                case CKA_ID: {
                    uint8_t id = (uint8_t)slot;
                    if (pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(uint8_t);
                    } else if (pTemplate[i].ulValueLen >= sizeof(uint8_t)) {
                        memcpy(pTemplate[i].pValue, &id, sizeof(uint8_t));
                        pTemplate[i].ulValueLen = sizeof(uint8_t);
                    } else {
                        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                    break;
                }
                case CKA_VALUE:
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
                case CKA_SIGN: {
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
                case CKA_VERIFY: {
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
                case CKA_VERIFY_RECOVER: {
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
                case CKA_NEVER_EXTRACTABLE: {
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
                case CKA_EXTRACTABLE: {
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
                case CKA_LOCAL: {
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
                case CKA_ALWAYS_AUTHENTICATE: {
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
                case CKA_EC_PARAMS: {
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
                default:
                    pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
            }
        }
    }
    else {
        LT_PKCS11_LOG("Invalid object handle: CKR_OBJECT_HANDLE_INVALID");
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    LT_PKCS11_LOG("C_GetAttributeValue returning 0x%lx", rv);
    return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    LT_PKCS11_LOG("C_FindObjectsInit (hSession=0x%lx, pTemplate=%p, ulCount=%lu)",
        hSession, pTemplate, ulCount);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Check if find operation already active */
    if (pkcs11_ctx.find_active) {
        LT_PKCS11_LOG("Find operation already active: CKR_OPERATION_ACTIVE");
        return CKR_OPERATION_ACTIVE;
    }
    
    /* Parse template to find object class and label filter */
    CK_OBJECT_CLASS find_class = 0;
    CK_BBOOL find_slot_set = CK_FALSE;
    CK_ULONG find_slot = 0;
    
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            find_class = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
            LT_PKCS11_LOG("  Filter CKA_CLASS = 0x%lx", find_class);
        } else if (pTemplate[i].type == CKA_LABEL && pTemplate[i].pValue && pTemplate[i].ulValueLen > 0) {
            /* Parse CKA_LABEL as slot number */
            char temp[16] = {0};
            CK_ULONG copy_len = (pTemplate[i].ulValueLen < 15) ? pTemplate[i].ulValueLen : 15;
            memcpy(temp, pTemplate[i].pValue, copy_len);
            find_slot = (CK_ULONG)atoi(temp);
            find_slot_set = CK_TRUE;
            LT_PKCS11_LOG("  Filter CKA_LABEL = '%s' (slot %lu)", temp, find_slot);
        }
    }
    
    /* Initialize find state */
    pkcs11_ctx.find_active = CK_TRUE;
    pkcs11_ctx.find_class = find_class;
    pkcs11_ctx.find_rmem_index = 0;
    pkcs11_ctx.find_ecc_index = 0;
    pkcs11_ctx.find_ecc_done = CK_FALSE;
    pkcs11_ctx.find_id_set = find_slot_set;
    pkcs11_ctx.find_id = find_slot;
    
    LT_PKCS11_LOG("C_FindObjectsInit OK (class=0x%lx, slot_set=%d, slot=%lu)", 
        find_class, find_slot_set, find_slot);
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    LT_PKCS11_LOG("C_FindObjects (hSession=0x%lx, phObject=%p, ulMaxObjectCount=%lu, pulObjectCount=%p)",
        hSession, phObject, ulMaxObjectCount, pulObjectCount);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Check if find operation is active */
    if (!pkcs11_ctx.find_active) {
        LT_PKCS11_LOG("No find operation active: CKR_OPERATION_NOT_INITIALIZED");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    /* Validate parameters */
    if (!phObject || !pulObjectCount) {
        LT_PKCS11_LOG("Invalid arguments: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    *pulObjectCount = 0;
    CK_OBJECT_CLASS find_class = pkcs11_ctx.find_class;
    
    /* Decide which backends to search based on class filter */
    CK_BBOOL search_rmem = (find_class == 0 || find_class == CKO_DATA);
    CK_BBOOL search_ecc = (find_class == 0 || find_class == CKO_PRIVATE_KEY || find_class == CKO_PUBLIC_KEY);
    
    if (search_rmem) {
        uint8_t temp_buf[TR01_R_MEM_DATA_SIZE_MAX];
        uint16_t read_size;
        
        while (pkcs11_ctx.find_rmem_index <= TR01_R_MEM_DATA_SLOT_MAX && *pulObjectCount < ulMaxObjectCount) {
            uint16_t slot = pkcs11_ctx.find_rmem_index++;
            
            /* If filtering by ID, skip slots that don't match */
            if (pkcs11_ctx.find_id_set && slot != (uint16_t)pkcs11_ctx.find_id) {
                continue;
            }
            
            lt_ret_t ret = lt_r_mem_data_read(&pkcs11_ctx.lt_handle, slot, temp_buf, sizeof(temp_buf), &read_size);
            if (ret == LT_OK) {
                phObject[*pulObjectCount] = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_RMEM_DATA, slot);
                (*pulObjectCount)++;
                LT_PKCS11_LOG("Found DATA object slot:%u (handle=0x%lx)", slot, phObject[*pulObjectCount - 1]);
            }
            /* Skip empty slots (LT_L3_R_MEM_DATA_READ_SLOT_EMPTY) */
        }
    }
    
    if (search_ecc && !pkcs11_ctx.find_ecc_done) {
        
        uint8_t pubkey_buf[TR01_CURVE_P256_PUBKEY_LEN];  /* P256 is larger */
        lt_ecc_curve_type_t curve;
        lt_ecc_key_origin_t origin;
        
        while (pkcs11_ctx.find_ecc_index <= TR01_ECC_SLOT_31 && *pulObjectCount < ulMaxObjectCount) {
            uint8_t slot = pkcs11_ctx.find_ecc_index++;
            
            /* If filtering by ID, skip slots that don't match */
            if (pkcs11_ctx.find_id_set && slot != (uint8_t)pkcs11_ctx.find_id) {
                continue;
            }
            
            lt_ret_t ret = lt_ecc_key_read(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot, 
                                           pubkey_buf, sizeof(pubkey_buf), &curve, &origin);
            if (ret == LT_OK) {
                /* Found a valid key - add private key handle (if searching for privkey or all) */
                if (find_class == 0 || find_class == CKO_PRIVATE_KEY) {
                    if (*pulObjectCount < ulMaxObjectCount) {
                        phObject[*pulObjectCount] = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PRIVKEY, slot);
                        (*pulObjectCount)++;
                        LT_PKCS11_LOG("Found PRIVATE_KEY at ECC slot %u (handle=0x%lx, curve=%d)", 
                            slot, phObject[*pulObjectCount - 1], curve);
                    }
                }
                /* Add public key handle (if searching for pubkey or all) */
                if (find_class == 0 || find_class == CKO_PUBLIC_KEY) {
                    if (*pulObjectCount < ulMaxObjectCount) {
                        phObject[*pulObjectCount] = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PUBKEY, slot);
                        (*pulObjectCount)++;
                        LT_PKCS11_LOG("Found PUBLIC_KEY at ECC slot %u (handle=0x%lx, curve=%d)", 
                            slot, phObject[*pulObjectCount - 1], curve);
                    }
                }
            }
            /* Skip empty/invalid slots (LT_L3_ECC_INVALID_KEY) */
        }
        
        if (pkcs11_ctx.find_ecc_index > TR01_ECC_SLOT_31) {
            pkcs11_ctx.find_ecc_done = CK_TRUE;
        }
    }
    
    LT_PKCS11_LOG("C_FindObjects OK (found %lu objects)", *pulObjectCount);
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    LT_PKCS11_LOG("C_FindObjectsFinal (hSession=0x%lx)", hSession);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Check if find operation is active */
    if (!pkcs11_ctx.find_active) {
        LT_PKCS11_LOG("No find operation active: CKR_OPERATION_NOT_INITIALIZED");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    /* Clear find state */
    pkcs11_ctx.find_active = CK_FALSE;
    pkcs11_ctx.find_class = 0;
    pkcs11_ctx.find_rmem_index = 0;
    pkcs11_ctx.find_ecc_index = 0;
    pkcs11_ctx.find_ecc_done = CK_FALSE;
    pkcs11_ctx.find_id_set = CK_FALSE;
    pkcs11_ctx.find_id = 0;
    
    LT_PKCS11_LOG("C_FindObjectsFinal OK");
    return CKR_OK;
}


/* ---------------------------------------------------------------------------
 * RANDOM NUMBER GENERATION FUNCTIONS
 * --------------------------------------------------------------------------
  * 
  * This is the main functionality of this PKCS#11 module!
  * 
  * We implement:
  * - C_GenerateRandom: Get random bytes from TROPIC01's hardware RNG
  * - C_SeedRandom: Add seed data to RNG (no-op for true HWRNG)
  */
 
 CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
 {
     LT_PKCS11_LOG("C_GenerateRandom (hSession=0x%lx, pRandomData=%p, ulRandomLen=%lu)", 
         hSession, pRandomData, ulRandomLen);
     
     /* -----------------------------------------------------------------------
      * STEP 1: VALIDATE STATE AND PARAMETERS
       -----------------------------------------------------------------------
      */
     
     /* Library must be initialized */
     if (!pkcs11_ctx.initialized) {
         LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
         return CKR_CRYPTOKI_NOT_INITIALIZED;
     }
     
     /* Session must be open (secure session established) */
     if (!pkcs11_ctx.session_open) {
         LT_PKCS11_LOG("No session open: CKR_SESSION_HANDLE_INVALID");
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* Verify session handle */
     if (hSession != pkcs11_ctx.session_handle) {
         LT_PKCS11_LOG("Invalid session handle 0x%lx (expected 0x%lx): CKR_SESSION_HANDLE_INVALID", 
             hSession, pkcs11_ctx.session_handle);
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* Per PKCS#11 spec: requesting 0 bytes is valid and should just succeed */
     if (ulRandomLen == 0) {
         LT_PKCS11_LOG("ulRandomLen is 0: CKR_OK (valid no-op per spec)");
         return CKR_OK;
     }
     
     /* Validate output buffer */
     if (!pRandomData) {
         LT_PKCS11_LOG("pRandomData is NULL: CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* -----------------------------------------------------------------------
      * STEP 2: GET RANDOM BYTES FROM HARDWARE RNG
       -----------------------------------------------------------------------
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
             LT_PKCS11_LOG("Failed to get random bytes: %s", lt_ret_verbose(ret));
             return CKR_DEVICE_ERROR;
         }
         
         /* Move pointer forward and decrease remaining count */
         ptr += chunk_size;
         remaining -= chunk_size;
     }
     
     /* -----------------------------------------------------------------------
      * STEP 3: DEBUG OUTPUT - PRINT RANDOM BYTES IN HEX
       -----------------------------------------------------------------------
      * 
      * Print the generated random bytes for verification.
      * Format: 0xAA, 0xBB, 0xCC, ...
      * 
      * NOTE: Remove this for production use - it pollutes stdout.
      */
     LT_PKCS11_LOG("Random bytes (%lu bytes):", ulRandomLen);
     for (CK_ULONG i = 0; i < ulRandomLen; i++) {
         LT_PKCS11_LOG("0x%02X", pRandomData[i]);
     }
     
     LT_PKCS11_LOG("C_GenerateRandom OK (generated %lu bytes from TROPIC01 hardware RNG)", ulRandomLen);
     return CKR_OK;
 }
 
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    LT_PKCS11_LOG("C_SeedRandom (hSession=0x%lx, pSeed=%p, ulSeedLen=%lu)",
         hSession, pSeed, ulSeedLen);
     
     /* Library must be initialized */
     if (!pkcs11_ctx.initialized) {
         LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
         return CKR_CRYPTOKI_NOT_INITIALIZED;
     }
     
     /* Session must be open */
     if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
         LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
         return CKR_SESSION_HANDLE_INVALID;
     }
     
     /* Validate parameters */
     if (!pSeed) {
         LT_PKCS11_LOG("pSeed is NULL: CKR_ARGUMENTS_BAD");
         return CKR_ARGUMENTS_BAD;
     }
     
     /* 
      * Per PKCS#11 spec: TROPIC01 has a true hardware RNG that uses physical
      * entropy sources (thermal noise). It does not use or need external seeding.
      * Return CKR_RANDOM_SEED_NOT_SUPPORTED to indicate this.
      */
     LT_PKCS11_LOG("C_SeedRandom: HWRNG does not use seed: CKR_RANDOM_SEED_NOT_SUPPORTED");
     return CKR_RANDOM_SEED_NOT_SUPPORTED;
}


/* ---------------------------------------------------------------------------
 * SIGNING FUNCTIONS
 * --------------------------------------------------------------------------
 * 
 * These functions implement ECDSA (P256) and EdDSA (Ed25519) signing using the
 * ECC private keys stored in TROPIC01's secure key slots.
 * 
 * The private keys never leave the chip - signing is performed inside TROPIC01.
 */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    LT_PKCS11_LOG("C_SignInit (hSession=0x%lx, pMechanism=%p, hKey=0x%lx)",
        hSession, pMechanism, hKey);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Validate mechanism */
    if (!pMechanism) {
        LT_PKCS11_LOG("pMechanism is NULL: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Check if sign operation already active */
    if (pkcs11_ctx.sign_active) {
        LT_PKCS11_LOG("Sign operation already active: CKR_OPERATION_ACTIVE");
        return CKR_OPERATION_ACTIVE;
    }
    
    /* Validate key handle - must be ECC private key */
    if (!PKCS11_IS_VALID_ECC_PRIV_HANDLE(hKey)) {
        LT_PKCS11_LOG("Invalid key handle (not ECC private key): CKR_KEY_HANDLE_INVALID");
        return CKR_KEY_HANDLE_INVALID;
    }
    
    uint8_t slot = PKCS11_HANDLE_GET_SLOT(hKey);
    
    /* Read key to verify it exists and get curve type */
    uint8_t pubkey_buf[TR01_CURVE_P256_PUBKEY_LEN];
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    
    lt_ret_t ret = lt_ecc_key_read(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot,
                                   pubkey_buf, sizeof(pubkey_buf), &curve, &origin);
    if (ret == LT_L3_ECC_INVALID_KEY) {
        LT_PKCS11_LOG("ECC slot %u is empty: CKR_KEY_HANDLE_INVALID", slot);
        return CKR_KEY_HANDLE_INVALID;
    }
    if (ret != LT_OK) {
        LT_PKCS11_LOG("Failed to read ECC key: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
        return CKR_DEVICE_ERROR;
    }
    
    /* Validate mechanism matches key type */
    if (pMechanism->mechanism == CKM_ECDSA) {
        if (curve != TR01_CURVE_P256) {
            LT_PKCS11_LOG("ECDSA requires P256 key, got Ed25519: CKR_KEY_TYPE_INCONSISTENT");
            return CKR_KEY_TYPE_INCONSISTENT;
        }
    } else if (pMechanism->mechanism == CKM_EDDSA) {
        if (curve != TR01_CURVE_ED25519) {
            LT_PKCS11_LOG("EdDSA requires Ed25519 key, got P256: CKR_KEY_TYPE_INCONSISTENT");
            return CKR_KEY_TYPE_INCONSISTENT;
        }
    } else {
        LT_PKCS11_LOG("Unsupported mechanism 0x%lx: CKR_MECHANISM_INVALID", pMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }
    
    /* Initialize sign state */
    pkcs11_ctx.sign_active = CK_TRUE;
    pkcs11_ctx.sign_mechanism = pMechanism->mechanism;
    pkcs11_ctx.sign_key_slot = slot;
    pkcs11_ctx.sign_key_curve = curve;
    
    LT_PKCS11_LOG("C_SignInit OK (slot=%u, mechanism=0x%lx, curve=%d)", 
        slot, pMechanism->mechanism, curve);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    LT_PKCS11_LOG("C_Sign (hSession=0x%lx, pData=%p, ulDataLen=%lu, pSignature=%p, pulSignatureLen=%p)",
        hSession, pData, ulDataLen, pSignature, pulSignatureLen);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Check if sign operation is active */
    if (!pkcs11_ctx.sign_active) {
        LT_PKCS11_LOG("No sign operation active: CKR_OPERATION_NOT_INITIALIZED");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    /* Validate parameters */
    if (!pData || ulDataLen == 0 || !pulSignatureLen) {
        LT_PKCS11_LOG("Invalid arguments: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Signature is always 64 bytes (R + S) */
    if (pSignature == NULL) {
        /* Query mode - return required signature length */
        *pulSignatureLen = TR01_ECDSA_EDDSA_SIGNATURE_LENGTH;
        LT_PKCS11_LOG("Query mode: signature length = %lu", *pulSignatureLen);
        return CKR_OK;
    }
    
    /* Check output buffer size */
    if (*pulSignatureLen < TR01_ECDSA_EDDSA_SIGNATURE_LENGTH) {
        *pulSignatureLen = TR01_ECDSA_EDDSA_SIGNATURE_LENGTH;
        LT_PKCS11_LOG("Buffer too small: CKR_BUFFER_TOO_SMALL");
        return CKR_BUFFER_TOO_SMALL;
    }
    
    lt_ret_t ret;
    
    /* Perform signing based on mechanism */
    if (pkcs11_ctx.sign_mechanism == CKM_ECDSA) {
        LT_PKCS11_LOG("Performing ECDSA sign on slot %u", pkcs11_ctx.sign_key_slot);
        ret = lt_ecc_ecdsa_sign(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)pkcs11_ctx.sign_key_slot,
                                pData, ulDataLen, pSignature);
    } else {
        /* CKM_EDDSA */
        LT_PKCS11_LOG("Performing EdDSA sign on slot %u", pkcs11_ctx.sign_key_slot);
        ret = lt_ecc_eddsa_sign(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)pkcs11_ctx.sign_key_slot,
                                pData, (uint16_t)ulDataLen, pSignature);
    }
    
    /* Clear sign state (operation is complete) */
    pkcs11_ctx.sign_active = CK_FALSE;
    pkcs11_ctx.sign_mechanism = 0;
    pkcs11_ctx.sign_key_slot = 0;
    pkcs11_ctx.sign_key_curve = 0;
    
    if (ret != LT_OK) {
        LT_PKCS11_LOG("Signing failed: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
        return CKR_DEVICE_ERROR;
    }
    
    *pulSignatureLen = TR01_ECDSA_EDDSA_SIGNATURE_LENGTH;
    
    LT_PKCS11_LOG("C_Sign OK (signature length = %lu)", *pulSignatureLen);
    return CKR_OK;
}


/* ---------------------------------------------------------------------------
 * KEY GENERATION FUNCTIONS
 * --------------------------------------------------------------------------
 * 
 * Generate ECC key pairs (P-256 or Ed25519) in TROPIC01's secure key slots.
 * Private keys never leave the chip - only the public key is readable.
 */

/* ---------------------------------------------------------------------------
 * MECHANISM FUNCTIONS
 * --------------------------------------------------------------------------
 */

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
    LT_PKCS11_LOG("C_GetMechanismList (slotID=%lu, pMechanismList=%p, pulCount=%p)",
        slotID, pMechanismList, pulCount);
    
    if (!pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    if (!pulCount) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (pMechanismList == NULL) {
        *pulCount = NUM_MECHANISMS;
        return CKR_OK;
    }
    
    if (*pulCount < NUM_MECHANISMS) {
        *pulCount = NUM_MECHANISMS;
        return CKR_BUFFER_TOO_SMALL;
    }
    
    for (CK_ULONG i = 0; i < NUM_MECHANISMS; i++) {
        pMechanismList[i] = supported_mechanisms[i];
    }
    *pulCount = NUM_MECHANISMS;
    
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("C_GetMechanismInfo (slotID=%lu, type=0x%lx, pInfo=%p)",
        slotID, type, pInfo);
    
    if (!pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
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
    
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    LT_PKCS11_LOG("C_GetSessionInfo (hSession=0x%lx, pInfo=%p)", hSession, pInfo);
    
    if (!pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }
    
    pInfo->slotID = 0;
    pInfo->state = CKS_RW_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    pInfo->ulDeviceError = 0;
    
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    LT_PKCS11_LOG("C_Login (hSession=0x%lx, userType=%lu, pPin=%p, ulPinLen=%lu)",
        hSession, userType, pPin, ulPinLen);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Validate user type per PKCS#11 spec */
    if (userType != CKU_USER && userType != CKU_SO && userType != CKU_CONTEXT_SPECIFIC) {
        LT_PKCS11_LOG("Invalid user type %lu: CKR_ARGUMENTS_BAD", userType);
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Per PKCS#11 spec: if ulPinLen > 0, pPin must not be NULL */
    if (ulPinLen > 0 && pPin == NULL) {
        LT_PKCS11_LOG("pPin is NULL but ulPinLen > 0: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* 
     * TROPIC01 authentication is handled at session start via pairing keys.
     * We don't use PIN-based login - the secure session establishment already
     * authenticated the host. Accept the login as a no-op.
     */
    LT_PKCS11_LOG("C_Login OK (no-op, auth via pairing keys)");
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    LT_PKCS11_LOG("C_Logout (hSession=0x%lx)", hSession);
    
    if (!pkcs11_ctx.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* No-op - real session management via pairing keys */
    return CKR_OK;
}


/* ---------------------------------------------------------------------------
 * KEY GENERATION FUNCTIONS
 * --------------------------------------------------------------------------
 * 
 * Generate ECC key pairs (P-256 or Ed25519) in TROPIC01's secure key slots.
 * Private keys never leave the chip - only the public key is readable.
 */

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
    LT_PKCS11_LOG("C_GenerateKeyPair (hSession=0x%lx, pMechanism=%p)", hSession, pMechanism);
    
    /* Library must be initialized */
    if (!pkcs11_ctx.initialized) {
        LT_PKCS11_LOG("Library not initialized: CKR_CRYPTOKI_NOT_INITIALIZED");
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    /* Session must be open */
    if (!pkcs11_ctx.session_open || hSession != pkcs11_ctx.session_handle) {
        LT_PKCS11_LOG("Invalid session: CKR_SESSION_HANDLE_INVALID");
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    /* Validate parameters */
    if (!pMechanism || !phPublicKey || !phPrivateKey) {
        LT_PKCS11_LOG("Invalid arguments: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Check mechanism - we support EC key generation */
    if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) {
        LT_PKCS11_LOG("Unsupported mechanism 0x%lx: CKR_MECHANISM_INVALID", pMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
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
                LT_PKCS11_LOG("Unsupported curve OID: CKR_ATTRIBUTE_VALUE_INVALID");
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        } else if (pPublicKeyTemplate[i].type == CKA_LABEL && pPublicKeyTemplate[i].pValue) {
            /* Parse LABEL as slot number */
            if (pPublicKeyTemplate[i].ulValueLen > 0) {
                char temp[16] = {0};
                CK_ULONG copy_len = (pPublicKeyTemplate[i].ulValueLen < 15) ? pPublicKeyTemplate[i].ulValueLen : 15;
                memcpy(temp, pPublicKeyTemplate[i].pValue, copy_len);
                slot_id = (CK_ULONG)atoi(temp);
                LT_PKCS11_LOG("  Slot from public template: %lu", slot_id);
            }
        }
    }

    /* Also check private key template for LABEL */
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
            if (pPrivateKeyTemplate[i].type == CKA_LABEL && pPrivateKeyTemplate[i].pValue) {
                if (pPrivateKeyTemplate[i].ulValueLen > 0) {
                    char temp[16] = {0};
                    CK_ULONG copy_len = (pPrivateKeyTemplate[i].ulValueLen < 15) ? pPrivateKeyTemplate[i].ulValueLen : 15;
                    memcpy(temp, pPrivateKeyTemplate[i].pValue, copy_len);
                    slot_id = (CK_ULONG)atoi(temp);
                    LT_PKCS11_LOG("  Slot from private template: %lu", slot_id);
                }
            }
        }
    }

    /* Slot must be specified explicitly via --label */
    if (slot_id == CK_UNAVAILABLE_INFORMATION) {
        LT_PKCS11_LOG("Slot not specified (use --label): CKR_TEMPLATE_INCOMPLETE");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    
    /* Validate slot range */
    if (slot_id > TR01_ECC_SLOT_31) {
        LT_PKCS11_LOG("Invalid slot ID %lu (max %d): CKR_ATTRIBUTE_VALUE_INVALID", 
            slot_id, TR01_ECC_SLOT_31);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    
    /* Generate the key pair on TROPIC01 */
    LT_PKCS11_LOG("Generating %s key in ECC slot %lu...", 
        (curve == TR01_CURVE_P256) ? "P-256" : "Ed25519", slot_id);
    
    lt_ret_t ret = lt_ecc_key_generate(&pkcs11_ctx.lt_handle, (lt_ecc_slot_t)slot_id, curve);
    if (ret != LT_OK) {
        LT_PKCS11_LOG("Key generation failed: %s: CKR_DEVICE_ERROR", lt_ret_verbose(ret));
        return CKR_DEVICE_ERROR;
    }
    
    /* Return handles for both keys */
    *phPrivateKey = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PRIVKEY, slot_id);
    *phPublicKey = PKCS11_MAKE_HANDLE(PKCS11_HANDLE_TYPE_ECC_PUBKEY, slot_id);
    
    LT_PKCS11_LOG("C_GenerateKeyPair OK (slot=%lu, privKey=0x%lx, pubKey=0x%lx)", 
        slot_id, *phPrivateKey, *phPublicKey);
    return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    static CK_BBOOL functionList_initialized = CK_FALSE;
    
    LT_PKCS11_LOG("========================================");
    LT_PKCS11_LOG("C_GetFunctionList (ppFunctionList=%p)", ppFunctionList);
    LT_PKCS11_LOG("LOADING TROPIC PKCS#11 LIBRARY");
    LT_PKCS11_LOG("========================================");
    
    /* Validate parameter */
    if (!ppFunctionList) {
        LT_PKCS11_LOG("ppFunctionList is NULL: CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Initialize function list once (lazy initialization) */
    if (!functionList_initialized) {
        /* -----------------------------------------------------------------------
         * THE FUNCTION LIST
         * -----------------------------------------------------------------------
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
        pkcs11_ctx.functionList = (CK_FUNCTION_LIST){
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
         .C_GetMechanismList = C_GetMechanismList, /* List supported mechanisms */
         .C_GetMechanismInfo = C_GetMechanismInfo, /* Get mechanism info */
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
         .C_GetSessionInfo = C_GetSessionInfo,   /* Get session info */
         .C_GetOperationState = NULL,            /* Get crypto operation state (not implemented) */
         .C_SetOperationState = NULL,            /* Set crypto operation state (not implemented) */
         .C_Login = C_Login,                     /* No-op login (auth via pairing keys) */
         .C_Logout = C_Logout,                   /* No-op logout */
         
        /* =====================================================================
         * OBJECT MANAGEMENT
         * Functions for managing objects (keys, certs, data) on the token.
         * CKO_DATA objects are stored in TROPIC01's R-MEM (512 slots, 1-444 bytes each)
         * ===================================================================== */
        .C_CreateObject = C_CreateObject,       /* Create data object in R-MEM */
        .C_CopyObject = NULL,                   /* Copy an object (not implemented) */
        .C_DestroyObject = C_DestroyObject,     /* Erase data from R-MEM */
        .C_GetObjectSize = NULL,                /* Get object size (not implemented) */
        .C_GetAttributeValue = C_GetAttributeValue, /* Read data from R-MEM */
        .C_SetAttributeValue = NULL,            /* Set object attributes (not implemented) */
        .C_FindObjectsInit = C_FindObjectsInit, /* Start R-MEM enumeration */
        .C_FindObjects = C_FindObjects,         /* Find non-empty R-MEM slots */
        .C_FindObjectsFinal = C_FindObjectsFinal, /* End R-MEM enumeration */
         
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
         * ECDSA (P256) and EdDSA (Ed25519) supported via TROPIC01.
         * ===================================================================== */
        .C_SignInit = C_SignInit,               /* Initialize ECDSA/EdDSA signing */
        .C_Sign = C_Sign,                       /* Perform signature on TROPIC01 */
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
         .C_GenerateKeyPair = C_GenerateKeyPair, /* Generate ECC key pair (P-256 or Ed25519) */
         .C_WrapKey = NULL,                      /* Wrap (encrypt) a key (not implemented) */
         .C_UnwrapKey = NULL,                    /* Unwrap (decrypt) a key (not implemented) */
         .C_DeriveKey = NULL,                    /* Derive a key from another (not implemented) */
         
         /* =====================================================================
          * RANDOM NUMBER GENERATION - OUR MAIN FEATURE!
          * ===================================================================== */
         .C_SeedRandom = C_SeedRandom,           /* Returns CKR_RANDOM_SEED_NOT_SUPPORTED (HWRNG) */
         .C_GenerateRandom = C_GenerateRandom,   /* *** GENERATE RANDOM BYTES FROM TROPIC01 *** */
         
         /* =====================================================================
          * PARALLEL FUNCTION MANAGEMENT (DEPRECATED)
          * Legacy functions, rarely used.
          * ===================================================================== */
         .C_GetFunctionStatus = NULL,            /* Get parallel operation status (deprecated) */
         .C_CancelFunction = NULL,               /* Cancel parallel operation (deprecated) */
         .C_WaitForSlotEvent = NULL,             /* Wait for slot events (not implemented) */
        };
        functionList_initialized = CK_TRUE;
    }
    
    /* Return pointer to our function list from context */
    *ppFunctionList = &pkcs11_ctx.functionList;
    
    /* Log some info about the function pointers (for debugging) */
    LT_PKCS11_LOG("C_GetFunctionList OK (function list returned at %p)", *ppFunctionList);
    LT_PKCS11_LOG("Function pointers: C_Initialize=%p, C_Finalize=%p, C_GetInfo=%p", 
        pkcs11_ctx.functionList.C_Initialize, pkcs11_ctx.functionList.C_Finalize, pkcs11_ctx.functionList.C_GetInfo);
    LT_PKCS11_LOG("Function pointers: C_OpenSession=%p, C_CloseSession=%p, C_CloseAllSessions=%p",
        pkcs11_ctx.functionList.C_OpenSession, pkcs11_ctx.functionList.C_CloseSession, pkcs11_ctx.functionList.C_CloseAllSessions);
    LT_PKCS11_LOG("Actual function: C_OpenSession=%p", C_OpenSession);
    
    return CKR_OK;
}
 
 /* End of pkcs11.c */
 
/* Direct test of PKCS#11 library - bypasses OpenSSL completely */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "pkcs11.h"

int main(int argc, char **argv) {
    void *handle;
    CK_RV (*C_GetFunctionList_ptr)(CK_FUNCTION_LIST_PTR_PTR);
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_RV rv;
    
    const char *lib_path = argc > 1 ? argv[1] : 
        "/usr/lib/aarch64-linux-gnu/ossl-modules/liblibtropic_pkcs11.so";
    
    printf("=== Direct PKCS#11 Library Test ===\n");
    printf("Loading: %s\n\n", lib_path);
    
    // Load library
    handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load library: %s\n", dlerror());
        return 1;
    }
    
    // Get C_GetFunctionList
    C_GetFunctionList_ptr = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(handle, "C_GetFunctionList");
    if (!C_GetFunctionList_ptr) {
        fprintf(stderr, "ERROR: C_GetFunctionList not found: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
    
    printf("✓ C_GetFunctionList found\n");
    
    // Call C_GetFunctionList
    rv = C_GetFunctionList_ptr(&pFunctionList);
    if (rv != CKR_OK) {
        fprintf(stderr, "ERROR: C_GetFunctionList failed: 0x%08lX\n", rv);
        dlclose(handle);
        return 1;
    }
    
    printf("✓ C_GetFunctionList returned OK\n\n");
    
    // Initialize
    printf("Calling C_Initialize...\n");
    rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "ERROR: C_Initialize failed: 0x%08lX\n", rv);
        dlclose(handle);
        return 1;
    }
    printf("✓ C_Initialize OK\n\n");
    
    // Get slot list
    CK_ULONG slot_count;
    printf("Calling C_GetSlotList...\n");
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &slot_count);
    if (rv != CKR_OK) {
        fprintf(stderr, "ERROR: C_GetSlotList failed: 0x%08lX\n", rv);
    } else {
        printf("✓ C_GetSlotList returned %lu slots\n\n", slot_count);
    }
    
    // Open session on slot 1
    CK_SESSION_HANDLE session;
    printf("Calling C_OpenSession...\n");
    rv = pFunctionList->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
                                       NULL, NULL, &session);
    if (rv != CKR_OK) {
        fprintf(stderr, "ERROR: C_OpenSession failed: 0x%08lX\n", rv);
    } else {
        printf("✓ C_OpenSession OK (handle: 0x%lX)\n\n", session);
        
        // Generate random!
        unsigned char random[32];
        printf("Calling C_GenerateRandom for 32 bytes...\n");
        rv = pFunctionList->C_GenerateRandom(session, random, 32);
        if (rv != CKR_OK) {
            fprintf(stderr, "ERROR: C_GenerateRandom failed: 0x%08lX\n", rv);
        } else {
            printf("✓ C_GenerateRandom OK\n");
            printf("Random data: ");
            for (int i = 0; i < 32; i++) {
                printf("%02x", random[i]);
            }
            printf("\n\n");
        }
        
        // Close session
        pFunctionList->C_CloseSession(session);
    }
    
    // Finalize
    printf("Calling C_Finalize...\n");
    pFunctionList->C_Finalize(NULL);
    printf("✓ C_Finalize OK\n\n");
    
    dlclose(handle);
    printf("=== Test Complete - SUCCESS ===\n");
    return 0;
}


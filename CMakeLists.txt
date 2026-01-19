cmake_minimum_required(VERSION 3.21.0)

project(libtropic_pkcs11 VERSION 0.1)

###############################################################################
# User configuration
###############################################################################
option(LT_PKCS11_LOG_EN "Enable PKCS11 logging" OFF)
set(TS_USB_DEV "/dev/ttyACM0" CACHE STRING "Device path for TROPIC01 USB dongle")


###############################################################################
# Build settings
###############################################################################

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(PATH_LIBTROPIC ${CMAKE_CURRENT_SOURCE_DIR}/libtropic/)
set(LT_CRYPTO "trezor_crypto")  
set(LT_BUILD_EXAMPLES ON CACHE BOOL "Build libtropic examples" FORCE)


###############################################################################
# Print info
###############################################################################
message("libtropic PKCS11 build configuration:")
message("   Version:        ${CMAKE_PROJECT_VERSION}")
message("   Logging:        ${LT_PKCS11_LOG_EN}")
message("   USB device:     ${TS_USB_DEV}")
message("   Libtropic:      ${PATH_LIBTROPIC}")
message("   Libtropic CAL:  ${LT_CRYPTO}")
message("")

###############################################################################
# Library definition
###############################################################################

add_library(tropic_pkcs11 SHARED
            src/pkcs11.h
            src/pkcs11.c
            ${PATH_LIBTROPIC}/hal/port/unix/libtropic_port_unix_usb_dongle.c
    	    )

# Add path to the libtropic's repository root folder.
message("Libtropic initialization:")
add_subdirectory(${PATH_LIBTROPIC} "libtropic")

# Add include path for Unix HAL port headers
target_include_directories(tropic_pkcs11 PRIVATE 
    ${PATH_LIBTROPIC}/hal/port/unix
)

# Link libtropic with your binary.
target_link_libraries(tropic_pkcs11 PRIVATE tropic)

# Convert CMake boolean (ON/OFF) to C preprocessor integer (1/0)
if(LT_PKCS11_LOG_EN)
    target_compile_definitions(tropic_pkcs11 PRIVATE LT_PKCS11_LOG_EN=1)
else()
    target_compile_definitions(tropic_pkcs11 PRIVATE LT_PKCS11_LOG_EN=0)
endif()

# Pass device path as a compile definition (with quotes for string literal)
target_compile_definitions(tropic_pkcs11 PRIVATE TS_USB_DEV="${TS_USB_DEV}")

cmake_minimum_required(VERSION 3.21.0)
include (FetchContent)

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
# Set up dependencies
###############################################################################

# ------------------------------------------------------------------------
# Libtropic 
# ------------------------------------------------------------------------
# Add path to Libtropic source
add_subdirectory(${PATH_LIBTROPIC} "libtropic")

# Customize libtropic's compilation
target_compile_options(tropic PRIVATE -ffunction-sections -fdata-sections)

# ------------------------------------------------------------------------
# External dependencies
# ------------------------------------------------------------------------

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(tropic PUBLIC OpenSSL::Crypto)

###############################################################################
# Library definition
###############################################################################

# Add OpenSSL CAL for Libtropic
add_subdirectory("${PATH_LIBTROPIC}/cal/openssl" "openssl_cal")
target_sources(tropic PRIVATE ${LT_CAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_CAL_INC_DIRS})

# Add USB DevKit POSIX HAL for Libtropic
add_subdirectory("${PATH_LIBTROPIC}hal/posix/usb_dongle" "posix_usb_dongle")
target_sources(tropic PRIVATE ${LT_HAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_HAL_INC_DIRS})

add_library(tropic_pkcs11 SHARED
            src/pkcs11.h
            src/pkcs11.c
    	    )

# TODO: Add -Wpedantic and clean-up
target_compile_options(tropic_pkcs11 PUBLIC -Wall -Wextra)

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

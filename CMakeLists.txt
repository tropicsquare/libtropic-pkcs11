cmake_minimum_required(VERSION 3.31.6)
project(libtropic_pkcs11)

# Enable Position Independent Code for all targets (required for shared library)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set path to libtropic (inside libtropic-linux)
set(PATH_LIBTROPIC ${CMAKE_CURRENT_SOURCE_DIR}/libtropic-linux/libtropic/)

# It is necessary to set provider of cryptography functions.
# You can use e.g. trezor_crypto as the cryptography provider.
set(LT_CRYPTO "trezor_crypto")

add_library(libtropic_pkcs11 SHARED
            src/pkcs11.h
            src/pkcs11.c
            ${PATH_LIBTROPIC}/hal/port/unix/libtropic_port_unix_usb_dongle.c
            ${PATH_LIBTROPIC}/keys/keys.c
            )

# Add path to the libtropic's repository root folder.
add_subdirectory(${PATH_LIBTROPIC} "libtropic")

# Add include path for Unix HAL port headers
target_include_directories(libtropic_pkcs11 PRIVATE 
    ${PATH_LIBTROPIC}/hal/port/unix
)

# Link libtropic with your binary.
target_link_libraries(libtropic_pkcs11 PRIVATE tropic)

cmake_minimum_required(VERSION 3.31.6)
project(libtropic_pkcs11)
add_library(libtropic_pkcs11 SHARED
            src/pkcs11.h
            src/pkcs11.c
            )

# Set path to the libtropic submodule. For example:
set(PATH_LIBTROPIC ${CMAKE_CURRENT_SOURCE_DIR}/../libtropic/)

# It is necessary to set provider of cryptography functions.
# You can use e.g. trezor_crypto as the cryptography provider.
set(LT_CRYPTO "trezor_crypto")

# Add path to the libtropic's repository root folder.
add_subdirectory(${PATH_LIBTROPIC} "libtropic")

# Link libtropic with your binary.
target_link_libraries(libtropic_pkcs11 PRIVATE tropic)
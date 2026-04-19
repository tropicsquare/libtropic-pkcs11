cmake_minimum_required(VERSION 3.21.0)
include (FetchContent)

project(libtropic_pkcs11 VERSION 0.1)

###############################################################################
# User configuration
###############################################################################
option(LT_PKCS11_LOG_EN "Enable PKCS11 logging" OFF)
set(LT_HAL "posix_usb_dongle" CACHE STRING "Hardware Abstraction Layer used to connect to the TROPIC01")
set_property(CACHE LT_HAL PROPERTY STRINGS
    posix_usb_dongle
    linux_spi
    linux_spi_native_cs
)
set(TS_USB_DEV "/dev/ttyACM0" CACHE STRING "Device path for TROPIC01 USB dongle")
set(LT_SPI_DEV_PATH "/dev/spidev0.0" CACHE STRING "Path to the SPI device where TROPIC01 is connected")
set(LT_GPIO_DEV_PATH "/dev/gpiochip0" CACHE STRING "Path to the GPIO device that provides the TROPIC01's interrupt (GPO) and Chip Select (CS) line")
set(LT_SPI_CS_PIN 25 CACHE STRING "GPIO pin number in LT_GPIO_DEV_PATH used for SPI Chip Select (CS). Used only when LT_HAL is linux_spi.")
set(LT_INT_PIN 5 CACHE STRING "GPIO pin number in LT_GPIO_DEV_PATH used for TROPIC01 interrupt (GPO)")

# enable interrupt if LT_INT_PIN is configured
if((LT_HAL STREQUAL "linux_spi" OR LT_HAL STREQUAL "linux_spi_native_cs") AND LT_INT_PIN GREATER_EQUAL 0)
    set(LT_USE_INT_PIN ON)
else()
    set(LT_USE_INT_PIN OFF)
endif()

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
message("   HAL:            ${LT_HAL}")
if(LT_HAL STREQUAL "posix_usb_dongle")
    message("   USB device:     ${TS_USB_DEV}")
elseif(LT_HAL STREQUAL "linux_spi" OR LT_HAL STREQUAL "linux_spi_native_cs")
    message("   SPI device:     ${LT_SPI_DEV_PATH}")
    message("   GPIO device:    ${LT_GPIO_DEV_PATH}")
    if(LT_HAL STREQUAL "linux_spi")
        message("   SPI CS pin:     ${LT_SPI_CS_PIN}")
    endif()
    if(LT_USE_INT_PIN)
        message("   GPIO INT pin:   ${LT_INT_PIN}")
    endif()
endif()
message("   Libtropic:      ${PATH_LIBTROPIC}")
message("   Libtropic CAL:  OpenSSL")
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

# Add HAL for Libtropic
if(LT_HAL STREQUAL "posix_usb_dongle")
    add_subdirectory("${PATH_LIBTROPIC}hal/posix/usb_dongle" "posix_usb_dongle")
elseif(LT_HAL STREQUAL "linux_spi")
    add_subdirectory("${PATH_LIBTROPIC}hal/linux/spi" "linux_spi")
elseif(LT_HAL STREQUAL "linux_spi_native_cs")
    add_subdirectory("${PATH_LIBTROPIC}hal/linux/spi_native_cs" "linux_spi_native_cs")
else()
    message(FATAL_ERROR "Invalid LT_HAL specified: '${LT_HAL}'. Supported options are posix_usb_dongle, linux_spi, and linux_spi_native_cs.")
endif()
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
target_compile_definitions(tropic_pkcs11 PRIVATE LT_SPI_DEV_PATH="${LT_SPI_DEV_PATH}")
target_compile_definitions(tropic_pkcs11 PRIVATE LT_SPI_CS_PIN=${LT_SPI_CS_PIN})
target_compile_definitions(tropic_pkcs11 PRIVATE LT_GPIO_DEV_PATH="${LT_GPIO_DEV_PATH}")
target_compile_definitions(tropic_pkcs11 PRIVATE LT_INT_PIN=${LT_INT_PIN})
string(TOUPPER "${LT_HAL}" LT_HAL_UPPER)
target_compile_definitions(tropic_pkcs11 PRIVATE "LT_HAL_${LT_HAL_UPPER}=1")

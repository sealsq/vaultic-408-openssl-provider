#
# Copyright 2025 SEALSQ
# SPDX-License-Identifier: Apache-2.0
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

PROJECT(sealsq_vic408_provider)

SET(VIC408_ELIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/libVaultIC/408)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(VAULTIC_BUILD_CRYPTO_EXT ON)
SET(VAULTIC_PRODUCT 408)   


add_subdirectory(${VIC408_ELIB_DIR}/vaultic_tls-4xx/src vaultic_tls)

FILE(
    GLOB
    SOURCES
    provider/*.c
    provider/*.h
)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SOURCES})

target_link_libraries(${PROJECT_NAME} vaultic_tls_${VAULTIC_PRODUCT} vaultic_tls_crypto)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/provider)


ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ../bin
    COMMENT "Copy dll to bin"
)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_LIBDIR})
#
# Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

cmake_minimum_required(VERSION 3.5)

project(KonaCrypto C)

include_directories("include")

set(SOURCES kona_common.c kona_sm2.c kona_sm3.c kona_sm4.c)
set(LIB_DIR "${CMAKE_SOURCE_DIR}/../resources")

add_library(KonaCrypto SHARED ${SOURCES})

if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        target_link_libraries(KonaCrypto ${LIB_DIR}/libOpenSSLCrypto-macos-aarch64.dylib)
        set_target_properties(KonaCrypto PROPERTIES SUFFIX "-macos-aarch64.dylib")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        target_link_libraries(KonaCrypto ${LIB_DIR}/libOpenSSLCrypto-macos-x86_64.dylib)
        set_target_properties(KonaCrypto PROPERTIES SUFFIX "-macos-x86_64.dylib")
    endif()
elseif(UNIX)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        target_link_libraries(KonaCrypto ${LIB_DIR}/libOpenSSLCrypto-linux-aarch64.so)
        set_target_properties(KonaCrypto PROPERTIES SUFFIX "-linux-aarch64.so")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        target_link_libraries(KonaCrypto ${LIB_DIR}/libOpenSSLCrypto-linux-x86_64.so)
        set_target_properties(KonaCrypto PROPERTIES SUFFIX "-linux-x86_64.so")
    endif()
endif()

set_target_properties(KonaCrypto PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

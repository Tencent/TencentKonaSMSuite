#!/usr/bin/env bash

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

BUILD_DIR=build

if [ -d "${BUILD_DIR}" ]; then
    echo "Remove existing ${BUILD_DIR} directory"
    rm -rf "${BUILD_DIR}"
fi

echo "Create ${BUILD_DIR} directory"
mkdir build

echo "Go into ${BUILD_DIR} directory"
cd build

echo "Making..."
cmake -DCMAKE_BUILD_TYPE=Release ..
make

echo "Copy library file to resources directory"
cp lib/* ../../resources

echo "Clean ${BUILD_DIR} directory"
cd ..
rm -rf "${BUILD_DIR}"

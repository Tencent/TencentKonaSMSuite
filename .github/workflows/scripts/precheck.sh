#!/usr/bin/env bash

#
# Copyright (C) 2023, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

# Check trailing whitespaces
files=$(find . -type f \
    -not -path "./.git/*" \
    -not -path "*/.gradle/*" \
    -not -path "*/build/*" \
    -not -path "*/include/*" \
    -not -name "*.jar" \
    -not -name "*.so" \
    -not -name "*.dylib" \
    -exec egrep -l " +$" {} \;)

count=0
for file in $files; do
    ((count++))
    echo "$file"
done

if [ $count -ne 0 ]; then
    echo "Error: trailing whitespace(s) in the above $count file(s)"
    exit 1
fi

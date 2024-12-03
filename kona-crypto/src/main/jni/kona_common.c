/*
 * Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <string.h>

#include "kona_common.h"

const char* hex_digits = "0123456789abcdef";
void bytes_to_hex(const uint8_t* bytes, size_t offset, size_t len, uint8_t* hex) {
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_digits[bytes[i + offset] / 16];
        hex[i * 2 + 1] = hex_digits[bytes[i + offset] % 16];
    }

    hex[len * 2] = '\0';
}

void print_hex(const uint8_t* byte_array, size_t offset, size_t len) {
    uint8_t* hex = malloc(len* 2 + 1);
    bytes_to_hex(byte_array, offset, len, hex);
    KONA_print("%s", hex);
    free(hex);
}

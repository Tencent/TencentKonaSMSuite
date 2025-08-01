#!/usr/bin/env bash
#
# Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

##### AIA certificates
echo "AIA: Generate X.509 version 3 extensions for EE"
cat > ee-aia.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
authorityInfoAccess=OCSP;URI:http://127.0.0.1:9080
EOF

echo "AIA: P256 key EE, signed SHA256withECDSA <- P256 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL req -new -key ee-p256ecdsa-p256ecdsa-p256ecdsa.key -subj "/CN=ee-p256ecdsa-p256ecdsa-p256ecdsa-aia" -sha256 \
    -out ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.csr
$OPENSSL x509 -extfile ee-aia.ext -req -CAcreateserial -days 3650 -in ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.csr -sha256 \
    -CA intca-p256ecdsa-p256ecdsa.crt -CAkey intca-p256ecdsa-p256ecdsa.key -out ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.crt.tmp
$OPENSSL x509 -text -in ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.crt.tmp > ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.crt

echo "AIA: SM2 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SM3withSM2 <- SM2 key CA, signed by SM3withSM2"
$OPENSSL req -new -key ee-sm2sm2-sm2sm2-sm2sm2.key -subj "/CN=ee-sm2sm2-sm2sm2-sm2sm2-aia" -sha256 -out ee-sm2sm2-sm2sm2-sm2sm2-aia.csr
$OPENSSL x509 -extfile ee-aia.ext -req -CAcreateserial -days 3650 -in ee-sm2sm2-sm2sm2-sm2sm2-aia.csr -sm3 \
    -CA intca-sm2sm2-sm2sm2.crt -CAkey intca-sm2sm2-sm2sm2.key -out ee-sm2sm2-sm2sm2-sm2sm2-aia.crt.tmp
$OPENSSL x509 -text -in ee-sm2sm2-sm2sm2-sm2sm2-aia.crt.tmp > ee-sm2sm2-sm2sm2-sm2sm2-aia.crt

##### OCSP
cat > openssl.cnf << EOF
[crl]
database = index
EOF

cat > index << EOF
R	310909201516Z	211209111500Z,superseded	6E3E80966323524286F4AD300FFF2E11A0D84CFF	unknown	/CN=ee-p256ecdsa-p256ecdsa-p256ecdsa-aia
R	310909201516Z	211209111500Z,superseded	4FDDF00D68A3D013819B91D510F23C60955B0BC7	unknown	/CN=ee-sm2sm2-sm2sm2-sm2sm2-aia
EOF

$OPENSSL ocsp -index index -rmd sha256 -CA intca-p256ecdsa-p256ecdsa.crt \
    -rsigner intca-p256ecdsa-p256ecdsa.crt -rkey intca-p256ecdsa-p256ecdsa.key -port 9080 -text
$OPENSSL ocsp -sha256 -issuer intca-p256ecdsa-p256ecdsa.crt -cert ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.crt \
    -url http://localhost:9080 -text -reqout ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.req -respout ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.resp

$OPENSSL ocsp -index index -rmd sm3 -CA intca-sm2sm2-sm2sm2.crt \
    -rsigner intca-sm2sm2-sm2sm2.crt -rkey intca-sm2sm2-sm2sm2.key -port 9080 -text
$OPENSSL ocsp -sm3 -issuer intca-sm2sm2-sm2sm2.crt -cert ee-sm2sm2-sm2sm2-sm2sm2-aia.crt \
    -url http://localhost:9080 -text -respout ee-sm2sm2-sm2sm2-sm2sm2-aia.ocsp

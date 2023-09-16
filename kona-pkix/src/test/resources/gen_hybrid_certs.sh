#!/usr/bin/env bash
#
# Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

DIR="hybrid"
if [ ! -d ${DIR} ]; then
  echo "mkdir tlcp_certs"
  mkdir ${DIR}
fi
cd ${DIR}

echo "Generate X.509 version 3 extensions for CA"
cat > ca.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign,cRLSign
EOF

echo "Generate X.509 version 3 extensions for EE"
cat > ee.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment,keyAgreement
EOF

echo "Generate X.509 version 3 extensions for sign EE"
cat > ee-sign.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
EOF

echo "Generate X.509 version 3 extensions for enc EE"
cat > ee-enc.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyEncipherment,dataEncipherment,keyAgreement
EOF

OPENSSL=babassl

########## RSA START ##########

##### CA
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa-ca.key
$OPENSSL req -new -key rsa-ca.key -subj "/CN=rsa-ca" -sha256 -out rsa-ca.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in rsa-ca.csr -sha256 \
    -signkey rsa-ca.key -out rsa-ca.crt.tmp
$OPENSSL x509 -text -in rsa-ca.crt.tmp > rsa-ca.crt

##### Intermediate CA
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa-intca.key
$OPENSSL req -new -key rsa-intca.key -subj "/CN=rsa-intca" -sha256 -out rsa-intca.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in rsa-intca.csr -sha256 \
    -CA rsa-ca.crt -CAkey rsa-ca.key -out rsa-intca.crt.tmp
$OPENSSL x509 -text -in rsa-intca.crt.tmp > rsa-intca.crt

##### EE (Server)
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa-server.key
$OPENSSL req -new -key rsa-server.key -subj "/CN=rsa-server" -sha256 -out rsa-server.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in rsa-server.csr -sha256 \
    -CA rsa-intca.crt -CAkey rsa-intca.key -out rsa-server.crt.tmp
$OPENSSL x509 -text -in rsa-server.crt.tmp > rsa-server.crt

##### EE (Client)
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa-client.key
$OPENSSL req -new -key rsa-client.key -subj "/CN=rsa-client" -sha256 -out rsa-client.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in rsa-client.csr -sha256 \
    -CA rsa-intca.crt -CAkey rsa-intca.key -out rsa-client.crt.tmp
$OPENSSL x509 -text -in rsa-client.crt.tmp > rsa-client.crt

##### EE (localhost)
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa-ee-lo.key
$OPENSSL req -new -key rsa-ee-lo.key -subj "/CN=localhost" -sha256 -out rsa-ee-lo.csr
$OPENSSL x509 -extfile ee-sign.ext -req -CAcreateserial -days 3650 -in rsa-ee-lo.csr -sha256 \
    -CA rsa-intca.crt -CAkey rsa-intca.key -out rsa-ee-lo.crt.tmp
$OPENSSL x509 -text -in rsa-ee-lo.crt.tmp > rsa-ee-lo.crt

########## RSA END ##########

########## EC START ##########

##### CA
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ec-ca.key
$OPENSSL req -new -key ec-ca.key -subj "/CN=ec-ca" -sha256 -out ec-ca.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ec-ca.csr -sha256 \
    -signkey ec-ca.key -out ec-ca.crt.tmp
$OPENSSL x509 -text -in ec-ca.crt.tmp > ec-ca.crt

##### Intermediate CA
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ec-intca.key
$OPENSSL req -new -key ec-intca.key -subj "/CN=ec-intca" -sha256 -out ec-intca.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ec-intca.csr -sha256 \
    -CA ec-ca.crt -CAkey ec-ca.key -out ec-intca.crt.tmp
$OPENSSL x509 -text -in ec-intca.crt.tmp > ec-intca.crt

##### EE (Server)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ec-server.key
$OPENSSL req -new -key ec-server.key -subj "/CN=ec-server" -sha256 -out ec-server.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ec-server.csr -sha256 \
    -CA ec-intca.crt -CAkey ec-intca.key -out ec-server.crt.tmp
$OPENSSL x509 -text -in ec-server.crt.tmp > ec-server.crt

##### EE (Client)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ec-client.key
$OPENSSL req -new -key ec-client.key -subj "/CN=ec-client" -sha256 -out ec-client.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ec-client.csr -sha256 \
    -CA ec-intca.crt -CAkey ec-intca.key -out ec-client.crt.tmp
$OPENSSL x509 -text -in ec-client.crt.tmp > ec-client.crt

##### EE (localhost)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ec-ee-lo.key
$OPENSSL req -new -key ec-ee-lo.key -subj "/CN=localhost" -sha256 -out ec-ee-lo.csr
$OPENSSL x509 -extfile ee-sign.ext -req -CAcreateserial -days 3650 -in ec-ee-lo.csr -sha256 \
    -CA ec-intca.crt -CAkey ec-intca.key -out ec-ee-lo.crt.tmp
$OPENSSL x509 -text -in ec-ee-lo.crt.tmp > ec-ee-lo.crt

########## EC END ##########

########## SM START ##########

##### CA
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-ca.key
$OPENSSL req -new -key sm-ca.key -subj "/CN=sm-ca" -sm3 -out sm-ca.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in sm-ca.csr -sm3 \
    -signkey sm-ca.key -out sm-ca.crt.tmp
$OPENSSL x509 -text -in sm-ca.crt.tmp > sm-ca.crt

##### Intermediate CA
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-intca.key
$OPENSSL req -new -key sm-intca.key -subj "/CN=sm-intca" -sm3 -out sm-intca.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in sm-intca.csr -sm3 \
    -CA sm-ca.crt -CAkey sm-ca.key -out sm-intca.crt.tmp
$OPENSSL x509 -text -in sm-intca.crt.tmp > sm-intca.crt

##### Sign + Enc EE (Server)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-server.key
$OPENSSL req -new -key sm-server.key -subj "/CN=sm-server" -sm3 -out sm-server.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in sm-server.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-server.crt.tmp
$OPENSSL x509 -text -in sm-server.crt.tmp > sm-server.crt

##### Sign + Enc EE (Client)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-client.key
$OPENSSL req -new -key sm-client.key -subj "/CN=sm-client" -sm3 -out sm-client.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in sm-client.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-client.crt.tmp
$OPENSSL x509 -text -in sm-client.crt.tmp > sm-client.crt

##### Sign EE (Server)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-server-sign.key
$OPENSSL req -new -key sm-server-sign.key -subj "/CN=sm-server-sign" -sm3 -out sm-server-sign.csr
$OPENSSL x509 -extfile ee-sign.ext -req -CAcreateserial -days 3650 -in sm-server-sign.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-server-sign.crt.tmp
$OPENSSL x509 -text -in sm-server-sign.crt.tmp > sm-server-sign.crt

##### Sign EE (Client)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-client-sign.key
$OPENSSL req -new -key sm-client-sign.key -subj "/CN=sm-client-sign" -sm3 -out sm-client-sign.csr
$OPENSSL x509 -extfile ee-sign.ext -req -CAcreateserial -days 3650 -in sm-client-sign.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-client-sign.crt.tmp
$OPENSSL x509 -text -in sm-client-sign.crt.tmp > sm-client-sign.crt

##### Sign EE (localhost)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-sign-ee-lo.key
$OPENSSL req -new -key sm-sign-ee-lo.key -subj "/CN=localhost" -sm3 -out sm-sign-ee-lo.csr
$OPENSSL x509 -extfile ee-sign.ext -req -CAcreateserial -days 3650 -in sm-sign-ee-lo.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-sign-ee-lo.crt.tmp
$OPENSSL x509 -text -in sm-sign-ee-lo.crt.tmp > sm-sign-ee-lo.crt

##### Enc EE (Server)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-server-enc.key
$OPENSSL req -new -key sm-server-enc.key -subj "/CN=sm-server-enc" -sm3 -out sm-server-enc.csr
$OPENSSL x509 -extfile ee-enc.ext -req -CAcreateserial -days 3650 -in sm-server-enc.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-server-enc.crt.tmp
$OPENSSL x509 -text -in sm-server-enc.crt.tmp > sm-server-enc.crt

##### Enc EE (Client)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-client-enc.key
$OPENSSL req -new -key sm-client-enc.key -subj "/CN=sm-client-enc" -sm3 -out sm-client-enc.csr
$OPENSSL x509 -extfile ee-enc.ext -req -CAcreateserial -days 3650 -in sm-client-enc.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-client-enc.crt.tmp
$OPENSSL x509 -text -in sm-client-enc.crt.tmp > sm-client-enc.crt

##### Enc EE (localhost)
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out sm-enc-ee-lo.key
$OPENSSL req -new -key sm-enc-ee-lo.key -subj "/CN=localhost" -sm3 -out sm-enc-ee-lo.csr
$OPENSSL x509 -extfile ee-enc.ext -req -CAcreateserial -days 3650 -in sm-enc-ee-lo.csr -sm3 \
    -CA sm-intca.crt -CAkey sm-intca.key -out sm-enc-ee-lo.crt.tmp
$OPENSSL x509 -text -in sm-enc-ee-lo.crt.tmp > sm-enc-ee-lo.crt

########## SM END ##########

rm *.tmp *.srl *.csr

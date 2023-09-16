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

# Generate X.509 version 3 extensions for CA
cat > ca.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
extendedKeyUsage=critical,OCSPSigning
EOF

tsmssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ca-demo.key
tsmssl req -new -key ca-demo.key -subj "/CN=ca-demo" -sha256 -out ca-demo.csr
tsmssl x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-demo.csr -sm3 -signkey ca-demo.key -out ca-demo.crt

# Generate X.509 version 3 extensions for EE
cat > ee.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
crlDistributionPoints=URI:file:src/test/resources/demo/ee-demo.crl
EOF

tsmssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ee-demo.key
tsmssl req -new -key ee-demo.key -subj "/CN=ee-demo" -sm3 -out ee-demo.csr
tsmssl x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-demo.csr -sm3 -CA ca-demo.crt -CAkey ca-demo.key -out ee-demo.crt

# Create CRL database
touch index
cat > cnf << EOF
[crl]
database = index
EOF

# Revoke ee-demo certificate
tsmssl ca -config cnf -name crl -cert ca-demo.crt -keyfile ca-demo.key -revoke ee-demo.crt -crl_reason superseded -md sm3

# Generate CRL and contain the ee-demo
tsmssl ca -config cnf -name crl -gencrl -cert ca-demo.crt -keyfile ca-demo.key -md sm3 -crldays 3650 -out ee-demo.crl

rm *.ext cnf *.srl *.csr index*

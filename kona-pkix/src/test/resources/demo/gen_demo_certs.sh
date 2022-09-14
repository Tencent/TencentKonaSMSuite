#!/usr/bin/env bash

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

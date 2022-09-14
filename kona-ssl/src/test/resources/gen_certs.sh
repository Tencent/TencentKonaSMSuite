#!/usr/bin/env bash

if [ ! -d "certs" ]; then
  echo "mkdir certs"
  mkdir certs
fi
cd certs

echo "Generate X.509 version 3 extensions for CA"
cat > ca.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
extendedKeyUsage=critical,OCSPSigning
EOF

echo "Generate X.509 version 3 extensions for EE"
cat > ee.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

echo password > password

OPENSSL=babassl

##### CAs
echo "RSA key CA, signed by SHA256withRSA"
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out ca-rsarsa.key
$OPENSSL req -new -key ca-rsarsa.key -subj "/CN=ca-rsarsa" -sha256 -out ca-rsarsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-rsarsa.csr -sha256 \
    -signkey ca-rsarsa.key -out ca-rsarsa.crt.tmp
$OPENSSL x509 -text -in ca-rsarsa.crt.tmp > ca-rsarsa.crt

echo "P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ca-p256ecdsa.key
$OPENSSL req -new -key ca-p256ecdsa.key -subj "/CN=ca-p256ecdsa" -sha256 -out ca-p256ecdsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-p256ecdsa.csr -sha256 -signkey ca-p256ecdsa.key -out ca-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in ca-p256ecdsa.crt.tmp > ca-p256ecdsa.crt

echo "SM2 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ca-sm2ecdsa.key
$OPENSSL req -new -key ca-sm2ecdsa.key -subj "/CN=ca-sm2ecdsa" -sha256 -out ca-sm2ecdsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-sm2ecdsa.csr -sha256 -signkey ca-sm2ecdsa.key -out ca-sm2ecdsa.crt.tmp
$OPENSSL x509 -text -in ca-sm2ecdsa.crt.tmp > ca-sm2ecdsa.crt

echo "P256 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ca-p256sm2.key
$OPENSSL req -new -key ca-p256sm2.key -subj "/CN=ca-p256sm2" -sha256 -out ca-p256sm2.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-p256sm2.csr -sm3 -signkey ca-p256sm2.key -out ca-p256sm2.crt.tmp
$OPENSSL x509 -text -in ca-p256sm2.crt.tmp > ca-p256sm2.crt

echo "SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ca-sm2sm2.key
$OPENSSL req -new -key ca-sm2sm2.key -subj "/CN=ca-sm2sm2" -sha256 -out ca-sm2sm2.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-sm2sm2.csr -sm3 -signkey ca-sm2sm2.key -out ca-sm2sm2.crt.tmp
$OPENSSL x509 -text -in ca-sm2sm2.crt.tmp > ca-sm2sm2.crt

echo "FOO: SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ca-sm2sm2-foo.key
$OPENSSL req -new -key ca-sm2sm2-foo.key -subj "/CN=ca-sm2sm2-foo" -sha256 -out ca-sm2sm2-foo.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-sm2sm2-foo.csr -sm3 -signkey ca-sm2sm2-foo.key -out ca-sm2sm2-foo.crt.tmp
$OPENSSL x509 -text -in ca-sm2sm2-foo.crt.tmp > ca-sm2sm2-foo.crt

echo "BAR: SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ca-sm2sm2-bar.key
$OPENSSL req -new -key ca-sm2sm2-bar.key -subj "/CN=ca-sm2sm2-bar" -sha256 -out ca-sm2sm2-bar.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-sm2sm2-bar.csr -sm3 -signkey ca-sm2sm2-bar.key -out ca-sm2sm2-bar.crt.tmp
$OPENSSL x509 -text -in ca-sm2sm2-bar.crt.tmp > ca-sm2sm2-bar.crt

echo "ID: SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ca-sm2sm2-id.key
$OPENSSL req -new -key ca-sm2sm2-id.key -subj "/CN=ca-sm2sm2-id" -sha256 -out ca-sm2sm2-id.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in ca-sm2sm2-id.csr -sm3 -signkey ca-sm2sm2-id.key -out ca-sm2sm2-id.crt.tmp
$OPENSSL x509 -text -in ca-sm2sm2-id.crt.tmp > ca-sm2sm2-id.crt

# Encrypted CA keys with passphrase "password"
echo "RSA key CA, signed by SHA256withRSA (encrypted key)"
$OPENSSL rsa -aes-128-cbc -in ca-rsarsa.key -out ca-rsarsa.key.enc
$OPENSSL pkcs8 -topk8 -in ca-rsarsa.key.enc -out ca-rsarsa_enc.key

echo "P256 key CA, signed by SHA256withECDSA (encrypted key)"
$OPENSSL ec -aes-128-cbc -in ca-p256ecdsa.key -out ca-p256ecdsa.key.enc
$OPENSSL pkcs8 -topk8 -in ca-p256ecdsa.key.enc -out ca-p256ecdsa_enc.key

echo "P256 key CA, signed by SM3withSM2 (encrypted key)"
$OPENSSL ec -aes-128-cbc -in ca-p256sm2.key -out ca-p256sm2.key.enc
$OPENSSL pkcs8 -topk8 -in ca-p256sm2.key.enc -out ca-p256sm2_enc.key

echo "SM2 key CA, signed by SHA256withECDSA (encrypted key)"
$OPENSSL ec -aes-128-cbc -in ca-sm2ecdsa.key -out ca-sm2ecdsa.key.enc
$OPENSSL pkcs8 -topk8 -in ca-sm2ecdsa.key.enc -out ca-sm2ecdsa_enc.key

echo "SM2 key CA, signed by SM3withSM2 (encrypted key)"
$OPENSSL ec -aes-128-cbc -in ca-sm2sm2.key -out ca-sm2sm2.key.enc
$OPENSSL pkcs8 -topk8 -in ca-sm2sm2.key.enc -out ca-sm2sm2_enc.key

##### Intermediate CAs
echo "RSA key intermediate CA, signed by SHA256withRSA <- RSA key CA, signed by SHA256withRSA"
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out intca-rsarsa-rsarsa.key
$OPENSSL req -new -key intca-rsarsa-rsarsa.key -subj "/CN=intca-rsarsa-rsarsa" -sha256 -out intca-rsarsa-rsarsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in intca-rsarsa-rsarsa.csr -sha256 \
    -CA ca-rsarsa.crt -CAkey ca-rsarsa.key -out intca-rsarsa-rsarsa.crt.tmp
$OPENSSL x509 -text -in intca-rsarsa-rsarsa.crt.tmp > intca-rsarsa-rsarsa.crt

echo "P256 key intermediate CA, signed by SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out intca-p256ecdsa-p256ecdsa.key
$OPENSSL req -new -key intca-p256ecdsa-p256ecdsa.key -subj "/CN=intca-p256ecdsa-p256ecdsa" -sha256 -out intca-p256ecdsa-p256ecdsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in intca-p256ecdsa-p256ecdsa.csr -sha256 \
    -CA ca-p256ecdsa.crt -CAkey ca-p256ecdsa.key -out intca-p256ecdsa-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in intca-p256ecdsa-p256ecdsa.crt.tmp > intca-p256ecdsa-p256ecdsa.crt

echo "SM2 key intermediate CA, signed by SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out intca-sm2ecdsa-p256ecdsa.key
$OPENSSL req -new -key intca-sm2ecdsa-p256ecdsa.key -subj "/CN=intca-sm2ecdsa-p256ecdsa" -sha256 -out intca-sm2ecdsa-p256ecdsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in intca-sm2ecdsa-p256ecdsa.csr -sha256 \
    -CA ca-p256ecdsa.crt -CAkey ca-p256ecdsa.key -out intca-sm2ecdsa-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in intca-sm2ecdsa-p256ecdsa.crt.tmp > intca-sm2ecdsa-p256ecdsa.crt

echo "P256 key intermediate CA, signed by SM3withSM2 <- SM2 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out intca-p256sm2-sm2ecdsa.key
$OPENSSL req -new -key intca-p256sm2-sm2ecdsa.key -subj "/CN=intca-p256sm2-sm2ecdsa" -sha256 -out intca-p256sm2-sm2ecdsa.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in intca-p256sm2-sm2ecdsa.csr -sm3 \
    -CA ca-sm2ecdsa.crt -CAkey ca-sm2ecdsa.key -out intca-p256sm2-sm2ecdsa.crt.tmp
$OPENSSL x509 -text -in intca-p256sm2-sm2ecdsa.crt.tmp > intca-p256sm2-sm2ecdsa.crt

echo "P256 key intermediate CA, signed by SHA256withECDSA <- P256 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out intca-p256ecdsa-p256sm2.key
$OPENSSL req -new -key intca-p256ecdsa-p256sm2.key -subj "/CN=intca-p256ecdsa-p256sm2" -sha256 -out intca-p256ecdsa-p256sm2.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in intca-p256ecdsa-p256sm2.csr -sha256 \
    -CA ca-p256sm2.crt -CAkey ca-p256sm2.key -out intca-p256ecdsa-p256sm2.crt.tmp
$OPENSSL x509 -text -in intca-p256ecdsa-p256sm2.crt.tmp > intca-p256ecdsa-p256sm2.crt

echo "SM2 key intermediate CA, signed by SM3withSM2 <- SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out intca-sm2sm2-sm2sm2.key
$OPENSSL req -new -key intca-sm2sm2-sm2sm2.key -subj "/CN=intca-sm2sm2-sm2sm2" -sha256 -out intca-sm2sm2-sm2sm2.csr
$OPENSSL x509 -extfile ca.ext -req -CAcreateserial -days 3650 -in intca-sm2sm2-sm2sm2.csr -sm3 \
    -CA ca-sm2sm2.crt -CAkey ca-sm2sm2.key -out intca-sm2sm2-sm2sm2.crt.tmp
$OPENSSL x509 -text -in intca-sm2sm2-sm2sm2.crt.tmp > intca-sm2sm2-sm2sm2.crt

##### EEs
echo "RSA key EE, signed SHA256withRSA <- RSA key intermediate CA, signed SHA256withRSA <- RSA key CA, signed SHA256withRSA"
$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out ee-rsarsa-rsarsa-rsarsa.key
$OPENSSL req -new -key ee-rsarsa-rsarsa-rsarsa.key -subj "/CN=ee-rsarsa-rsarsa-rsarsa" -sha256 -out ee-rsarsa-rsarsa-rsarsa.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-rsarsa-rsarsa-rsarsa.csr -sha256 \
    -CA intca-rsarsa-rsarsa.crt -CAkey intca-rsarsa-rsarsa.key -out ee-rsarsa-rsarsa-rsarsa.crt.tmp
$OPENSSL x509 -text -in ee-rsarsa-rsarsa-rsarsa.crt.tmp > ee-rsarsa-rsarsa-rsarsa.crt

echo "P256 key EE, signed SHA256withECDSA <- P256 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ee-p256ecdsa-p256ecdsa-p256ecdsa.key
$OPENSSL req -new -key ee-p256ecdsa-p256ecdsa-p256ecdsa.key -subj "/CN=ee-p256ecdsa-p256ecdsa-p256ecdsa" -sha256 -out ee-p256ecdsa-p256ecdsa-p256ecdsa.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-p256ecdsa-p256ecdsa-p256ecdsa.csr -sha256 \
    -CA intca-p256ecdsa-p256ecdsa.crt -CAkey intca-p256ecdsa-p256ecdsa.key -out ee-p256ecdsa-p256ecdsa-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in ee-p256ecdsa-p256ecdsa-p256ecdsa.crt.tmp > ee-p256ecdsa-p256ecdsa-p256ecdsa.crt

echo "SM2 key EE, signed SHA256withECDSA <- P256 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ee-sm2ecdsa-p256ecdsa-p256ecdsa.key
$OPENSSL req -new -key ee-sm2ecdsa-p256ecdsa-p256ecdsa.key -subj "/CN=ee-sm2ecdsa-p256ecdsa-p256ecdsa" -sha256 -out ee-sm2ecdsa-p256ecdsa-p256ecdsa.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-sm2ecdsa-p256ecdsa-p256ecdsa.csr -sha256 \
    -CA intca-p256ecdsa-p256ecdsa.crt -CAkey intca-p256ecdsa-p256ecdsa.key -out ee-sm2ecdsa-p256ecdsa-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in ee-sm2ecdsa-p256ecdsa-p256ecdsa.crt.tmp > ee-sm2ecdsa-p256ecdsa-p256ecdsa.crt

echo "P256 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ee-p256sm2-sm2ecdsa-p256ecdsa.key
$OPENSSL req -new -key ee-p256sm2-sm2ecdsa-p256ecdsa.key -subj "/CN=ee-p256sm2-sm2ecdsa-p256ecdsa" -sha256 -out ee-p256sm2-sm2ecdsa-p256ecdsa.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-p256sm2-sm2ecdsa-p256ecdsa.csr -sm3 \
    -CA intca-sm2ecdsa-p256ecdsa.crt -CAkey intca-sm2ecdsa-p256ecdsa.key -out ee-p256sm2-sm2ecdsa-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in ee-p256sm2-sm2ecdsa-p256ecdsa.crt.tmp > ee-p256sm2-sm2ecdsa-p256ecdsa.crt

echo "SM2 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ee-sm2sm2-sm2ecdsa-p256ecdsa.key
$OPENSSL req -new -key ee-sm2sm2-sm2ecdsa-p256ecdsa.key -subj "/CN=ee-sm2sm2-sm2ecdsa-p256ecdsa" -sha256 -out ee-sm2sm2-sm2ecdsa-p256ecdsa.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-sm2sm2-sm2ecdsa-p256ecdsa.csr -sm3 \
    -CA intca-sm2ecdsa-p256ecdsa.crt -CAkey intca-sm2ecdsa-p256ecdsa.key -out ee-sm2sm2-sm2ecdsa-p256ecdsa.crt.tmp
$OPENSSL x509 -text -in ee-sm2sm2-sm2ecdsa-p256ecdsa.crt.tmp > ee-sm2sm2-sm2ecdsa-p256ecdsa.crt

echo "P256 key EE, signed SHA256withECDSA <- P256 key intermediate CA, signed SM3withSM2 <- SM2 key CA, signed by SHA256withECDSA"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ee-p256ecdsa-p256sm2-sm2ecdsa.key
$OPENSSL req -new -key ee-p256ecdsa-p256sm2-sm2ecdsa.key -subj "/CN=ee-p256ecdsa-p256sm2-sm2ecdsa" -sha256 -out ee-p256ecdsa-p256sm2-sm2ecdsa.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-p256ecdsa-p256sm2-sm2ecdsa.csr -sha256 \
    -CA intca-p256sm2-sm2ecdsa.crt -CAkey intca-p256sm2-sm2ecdsa.key -out ee-p256ecdsa-p256sm2-sm2ecdsa.crt.tmp
$OPENSSL x509 -text -in ee-p256ecdsa-p256sm2-sm2ecdsa.crt.tmp > ee-p256ecdsa-p256sm2-sm2ecdsa.crt

echo "P256 key EE, signed SHA256withECDSA <- P256 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ee-p256ecdsa-p256ecdsa-p256sm2.key
$OPENSSL req -new -key ee-p256ecdsa-p256ecdsa-p256sm2.key -subj "/CN=ee-p256ecdsa-p256ecdsa-p256sm2" -sha256 -out ee-p256ecdsa-p256ecdsa-p256sm2.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-p256ecdsa-p256ecdsa-p256sm2.csr -sha256 \
    -CA intca-p256ecdsa-p256sm2.crt -CAkey intca-p256ecdsa-p256sm2.key -out ee-p256ecdsa-p256ecdsa-p256sm2.crt.tmp
$OPENSSL x509 -text -in ee-p256ecdsa-p256ecdsa-p256sm2.crt.tmp > ee-p256ecdsa-p256ecdsa-p256sm2.crt

echo "SM2 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SM3withSM2 <- SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ee-sm2sm2-sm2sm2-sm2sm2.key
$OPENSSL req -new -key ee-sm2sm2-sm2sm2-sm2sm2.key -subj "/CN=ee-sm2sm2-sm2sm2-sm2sm2" -sha256 -out ee-sm2sm2-sm2sm2-sm2sm2.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-sm2sm2-sm2sm2-sm2sm2.csr -sm3 \
    -CA intca-sm2sm2-sm2sm2.crt -CAkey intca-sm2sm2-sm2sm2.key -out ee-sm2sm2-sm2sm2-sm2sm2.crt.tmp
$OPENSSL x509 -text -in ee-sm2sm2-sm2sm2-sm2sm2.crt.tmp > ee-sm2sm2-sm2sm2-sm2sm2.crt

echo "localhost SM2 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SM3withSM2 <- SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ee-sm2sm2-sm2sm2-sm2sm2-lh.key
$OPENSSL req -new -key ee-sm2sm2-sm2sm2-sm2sm2-lh.key -subj "/CN=localhost" -sha256 -out ee-sm2sm2-sm2sm2-sm2sm2-lh.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-sm2sm2-sm2sm2-sm2sm2-lh.csr -sm3 \
    -CA intca-sm2sm2-sm2sm2.crt -CAkey intca-sm2sm2-sm2sm2.key -out ee-sm2sm2-sm2sm2-sm2sm2-lh.crt.tmp
$OPENSSL x509 -text -in ee-sm2sm2-sm2sm2-sm2sm2-lh.crt.tmp > ee-sm2sm2-sm2sm2-sm2sm2-lh.crt

echo "localhost with custom ID SM2 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SM3withSM2 <- SM2 key CA, signed by SM3withSM2"
$OPENSSL genpkey -algorithm ec -pkeyopt ec_paramgen_curve:SM2 -pkeyopt ec_param_enc:named_curve -out ee-sm2sm2-sm2sm2-sm2sm2-id.key
$OPENSSL req -new -key ee-sm2sm2-sm2sm2-sm2sm2-id.key -subj "/CN=localhost" -sm3 -sigopt "sm2_id:custom-id" -out ee-sm2sm2-sm2sm2-sm2sm2-id.csr
$OPENSSL x509 -extfile ee.ext -req -CAcreateserial -days 3650 -in ee-sm2sm2-sm2sm2-sm2sm2-id.csr -sm3 \
    -CA intca-sm2sm2-sm2sm2.crt -CAkey intca-sm2sm2-sm2sm2.key -sm2-id "custom-id" -sigopt "sm2_id:custom-id" \
    -out ee-sm2sm2-sm2sm2-sm2sm2-id.crt.tmp
$OPENSSL x509 -text -in ee-sm2sm2-sm2sm2-sm2sm2-id.crt.tmp > ee-sm2sm2-sm2sm2-sm2sm2-id.crt

rm -f *.csr *.tmp *.srl *.enc


##### CRL
touch index
cat > openssl.cnf << EOF
[crl]
database = index
EOF

$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert ca-p256ecdsa.crt -keyfile ca-p256ecdsa.key \
    -md sha256 -crldays 3650 -out ca-p256ecdsa-empty.crl

$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert ca-sm2sm2.crt -keyfile ca-sm2sm2.key \
    -md sm3 -crldays 3650 -out ca-sm2sm2-empty.crl

$OPENSSL ca -config openssl.cnf -name crl -cert ca-p256ecdsa.crt -keyfile ca-p256ecdsa.key \
    -revoke intca-p256ecdsa-p256ecdsa.crt -crl_reason superseded -md sha256
$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert ca-p256ecdsa.crt -keyfile ca-p256ecdsa.key \
    -md sha256 -crldays 3650 -out intca-p256ecdsa-p256ecdsa.crl

$OPENSSL ca -config openssl.cnf -name crl -cert intca-p256ecdsa-p256ecdsa.crt -keyfile intca-p256ecdsa-p256ecdsa.key \
    -revoke ee-p256ecdsa-p256ecdsa-p256ecdsa.crt -crl_reason superseded -md sha256
$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert intca-p256ecdsa-p256ecdsa.crt -keyfile intca-p256ecdsa-p256ecdsa.key \
    -md sha256 -crldays 3650 -out ee-p256ecdsa-p256ecdsa-p256ecdsa.crl

$OPENSSL ca -config openssl.cnf -name crl -cert ca-sm2sm2.crt -keyfile ca-sm2sm2.key \
    -revoke intca-sm2sm2-sm2sm2.crt -crl_reason superseded -md sm3
$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert ca-sm2sm2.crt -keyfile ca-sm2sm2.key \
    -md sm3 -crldays 3650 -out intca-sm2sm2-sm2sm2.crl

$OPENSSL ca -config openssl.cnf -name crl -cert intca-sm2sm2-sm2sm2.crt -keyfile intca-sm2sm2-sm2sm2.key \
    -revoke ee-sm2sm2-sm2sm2-sm2sm2.crt -crl_reason superseded -md sm3
$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert intca-sm2sm2-sm2sm2.crt -keyfile intca-sm2sm2-sm2sm2.key \
    -md sm3 -crldays 3650 -out ee-sm2sm2-sm2sm2-sm2sm2.crl

# CRL Distribution Points
echo "CRLDP: Generate X.509 version 3 extensions for EE"
cat > ee-crldp.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
crlDistributionPoints=URI:file:src/test/resources/certs/ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crl
EOF

echo "CRLDP: P256 key EE, signed SHA256withECDSA <- P256 key intermediate CA, signed SHA256withECDSA <- P256 key CA, signed by SHA256withECDSA"
$OPENSSL req -new -key ee-p256ecdsa-p256ecdsa-p256ecdsa.key -subj "/CN=ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp" -sha256 -out ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.csr
$OPENSSL x509 -extfile ee-crldp.ext -req -CAcreateserial -days 3650 -in ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.csr -sha256 \
    -CA intca-p256ecdsa-p256ecdsa.crt -CAkey intca-p256ecdsa-p256ecdsa.key -out ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crt.tmp
$OPENSSL x509 -text -in ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crt.tmp > ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crt

$OPENSSL ca -config openssl.cnf -name crl -cert intca-p256ecdsa-p256ecdsa.crt -keyfile intca-p256ecdsa-p256ecdsa.key \
    -revoke ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crt -crl_reason superseded -md sha256
$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert intca-p256ecdsa-p256ecdsa.crt -keyfile intca-p256ecdsa-p256ecdsa.key \
    -md sha256 -crldays 3650 -out ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crl

echo "CRLDP: Generate X.509 version 3 extensions for EE"
cat > ee-crldp.ext << EOF
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
crlDistributionPoints=URI:file:src/test/resources/certs/ee-sm2sm2-sm2sm2-sm2sm2-crldp.crl
EOF

echo "CRLDP: SM2 key EE, signed SM3withSM2 <- SM2 key intermediate CA, signed SM3withSM2 <- SM2 key CA, signed by SM3withSM2"
$OPENSSL req -new -key ee-sm2sm2-sm2sm2-sm2sm2.key -subj "/CN=ee-sm2sm2-sm2sm2-sm2sm2-crldp" -sha256 -out ee-sm2sm2-sm2sm2-sm2sm2-crldp.csr
$OPENSSL x509 -extfile ee-crldp.ext -req -CAcreateserial -days 3650 -in ee-sm2sm2-sm2sm2-sm2sm2-crldp.csr -sm3 \
    -CA intca-sm2sm2-sm2sm2.crt -CAkey intca-sm2sm2-sm2sm2.key -out ee-sm2sm2-sm2sm2-sm2sm2-crldp.crt.tmp
$OPENSSL x509 -text -in ee-sm2sm2-sm2sm2-sm2sm2-crldp.crt.tmp > ee-sm2sm2-sm2sm2-sm2sm2-crldp.crt

$OPENSSL ca -config openssl.cnf -name crl -cert intca-sm2sm2-sm2sm2.crt -keyfile intca-sm2sm2-sm2sm2.key \
    -revoke ee-sm2sm2-sm2sm2-sm2sm2-crldp.crt -crl_reason superseded -md sm3
$OPENSSL ca -config openssl.cnf -name crl -gencrl -cert intca-sm2sm2-sm2sm2.crt -keyfile intca-sm2sm2-sm2sm2.key \
    -md sm3 -crldays 3650 -out ee-sm2sm2-sm2sm2-sm2sm2-crldp.crl

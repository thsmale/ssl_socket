#!/bin/bash
#An example of generating a certificate for a user to use in an SSL connection
#Uses the openssl library 
#Only the public key associated with the certificate works with the private key assoiated with the certificate

#Reference: https://www.ibm.com/docs/en/api-connect/10.0.1.x?topic=overview-generating-self-signed-certificate-using-openssl
#Create a self signed certificate for HTTPS connections
#Generate private key and public certificate
#openssl req -newkey rsa:2048 -nodes -keyout private_key.pem -x509 -days 365 -out certificate.pem
#Combine key and certificate in PKCS#12 bundle
#openssl pkcs12 -inkey private_key.pem -in certificate.pem -export -out certificate.p12

#Reference: https://www.ibm.com/docs/en/license-metric-tool?topic=communication-step-2-signing-certificates
#Create a private key and public certificate 
openssl req -new -newkey rsa:2048 -nodes -out CA_CSR.csr -outform PEM -keyout CA_private_key.pem -sha256
#Create certificate
openssl x509 -signkey CA_private_key.pem -days 90 -req -in CA_CSR.csr -out CA_certificate.arm -sha256
#Sign the certificate
openssl x509 -req -days 90 -in CSR.csr -CA CA_certificate.arm -CAkey CA_private_key.pem -out certificate.arm -set_serial 01 -sha256

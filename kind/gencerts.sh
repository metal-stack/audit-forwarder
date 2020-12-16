#!/bin/bash

#
# Generates CA / Certificates and replace CA-Bundle in deployment
#

set -e
set -o errexit
set -o nounset
set -o pipefail

CERTDIR=certs
# MANIFESTSDIR=../deployment

# CREATE THE PRIVATE KEY FOR OUR CUSTOM CA
openssl genrsa -out $CERTDIR/ca.key 2048

# GENERATE A CA CERT WITH THE PRIVATE KEY
openssl req -new -x509 -key $CERTDIR/ca.key -out $CERTDIR/ca.crt -config $CERTDIR/ca-config.txt

# CREATE THE PRIVATE KEY FOR OUR fluentd SERVER
openssl genrsa -out $CERTDIR/fluentd-key.pem 2048

# CREATE A CSR FROM THE CONFIGURATION FILE AND OUR PRIVATE KEY
openssl req -new -key $CERTDIR/fluentd-key.pem -subj "/CN=kubernetes-audit-tailer" -out $CERTDIR/fluentd.csr -config $CERTDIR/ca-config.txt

# CREATE THE CERT SIGNING THE CSR WITH THE CA CREATED BEFORE
openssl x509 -req -in $CERTDIR/fluentd.csr -CA $CERTDIR/ca.crt -CAkey $CERTDIR/ca.key -CAcreateserial -out $CERTDIR/fluentd-crt.pem

# CREATE THE PRIVATE KEY FOR OUR forwarder
openssl genrsa -out $CERTDIR/forwarder-key.pem 2048

# CREATE A CSR FROM THE CONFIGURATION FILE AND OUR PRIVATE KEY
openssl req -new -key $CERTDIR/forwarder-key.pem -subj "/CN=kubernetes-audit-forwarder" -out $CERTDIR/forwarder.csr -config $CERTDIR/ca-config.txt

# CREATE THE CERT SIGNING THE CSR WITH THE CA CREATED BEFORE
openssl x509 -req -in $CERTDIR/forwarder.csr -CA $CERTDIR/ca.crt -CAkey $CERTDIR/ca.key -CAcreateserial -out $CERTDIR/forwarder-crt.pem

# INJECT CA IN THE WEBHOOK CONFIGURATION
export CA_BUNDLE=$(cat $CERTDIR/ca.crt | base64 | tr -d '\n')

# CABundle is not inserted in file here, instead it must be mounted - see https://kubernetes.io/docs/reference/access-authn-authz/webhook/#configuration-file-format
# cat $MANIFESTSDIR/token-webhook-config.tpl | envsubst > $MANIFESTSDIR/token-webhook-config.yaml

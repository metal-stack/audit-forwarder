#!/bin/bash

CERTDIR=certs

# INJECT CA IN THE WEBHOOK CONFIGURATION
CA_BUNDLE=$(cat $CERTDIR/ca.crt | base64 | tr -d '\n')
FLUENTD_KEY=$(cat $CERTDIR/fluentd-key.pem | base64 | tr -d '\n')
FLUENTD_CERT=$(cat $CERTDIR/fluentd-crt.pem | base64 | tr -d '\n')
FORWARDER_KEY=$(cat $CERTDIR/forwarder-key.pem | base64 | tr -d '\n')
FORWARDER_CERT=$(cat $CERTDIR/forwarder-crt.pem | base64 | tr -d '\n')

cat <<EOF >$CERTDIR/cert-secret.yaml
---
apiVersion: v1
data:
  ca.crt: $CA_BUNDLE
  fluentd.crt: $FLUENTD_CERT
  fluentd.key: $FLUENTD_KEY
  forwarder.crt: $FORWARDER_CERT
  forwarder.key: $FORWARDER_KEY
kind: Secret
metadata:
  name: cert-secret
  namespace: kube-system
type: Opaque
EOF

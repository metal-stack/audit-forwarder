#!/bin/bash

CERTDIR=certs

# INJECT CA IN THE WEBHOOK CONFIGURATION
CA_BUNDLE=$(cat $CERTDIR/ca.crt | base64 | tr -d '\n')
FLUENTD_KEY=$(cat $CERTDIR/fluentd-key.pem | base64 | tr -d '\n')
FLUENTD_CERT=$(cat $CERTDIR/fluentd-crt.pem | base64 | tr -d '\n')
FORWARDER_KEY=$(cat $CERTDIR/forwarder-key.pem | base64 | tr -d '\n')
FORWARDER_CERT=$(cat $CERTDIR/forwarder-crt.pem | base64 | tr -d '\n')

echo "ca.crt: $CA_BUNDLE"
echo "fluentd.crt: $FLUENTD_CERT"
echo "fluentd.key: $FLUENTD_KEY"
echo "forwarder.crt: $FORWARDER_CERT"
echo "forwarder.key: $FORWARDER_KEY"

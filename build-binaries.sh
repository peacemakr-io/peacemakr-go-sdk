#!/bin/sh

set -ex

# Setup credentials
$(aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr) || true

# Pull the latest
docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/peacemakr-services:testing-stable || true
docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/key-derivation-service:testing-stable || true

# Build all binaries
docker build -f Dockerfile-example-integration -t peacemakr-go-sdk-example-integration:latest .

# Build the tests
docker build -f Dockerfile-test -t peacemakr-go-sdk-test .

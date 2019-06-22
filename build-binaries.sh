#!/bin/sh

set -ex

CORE_CRYPTO_VERSION=$(cat corecrypto-version.txt)

# Setup credentials
`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

# Pull latest dependencies
docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:${CORE_CRYPTO_VERSION} || true

# Build all binaries
docker build -f Dockerfile-example-integration -t peacemakr-go-sdk-example-integration:latest .

# Build the tests
docker build -f Dockerfile-test -t peacemakr-go-sdk-test .

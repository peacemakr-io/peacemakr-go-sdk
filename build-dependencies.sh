#!/bin/sh

set -ex

CORE_CRYPTO_VERSION=$(cat corecrypto-version.txt)

# Setup credentials
`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

# Pull latest dependencies

docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:${CORE_CRYPTO_VERSION}
docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:${CORE_CRYPTO_VERSION}

docker build -f Dockerfile-dependencies -t peacemakr-go-sdk-dependencies --build-arg CORE_CRYPTO_VERSION=${CORE_CRYPTO_VERSION} .


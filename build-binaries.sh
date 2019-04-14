#!/bin/sh

set -ex

# Setup credentials
`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

# Pull latest dependencies
docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:0.0.2 || true

# Build all binaries
docker build -f Dockerfile-example-integration -t peacemakr-go-sdk-example-integration:latest .

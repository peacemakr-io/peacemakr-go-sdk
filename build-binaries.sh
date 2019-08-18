#!/bin/sh

set -ex

# Setup credentials
$(aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr) || true

# Build all binaries
docker build -f Dockerfile-example-integration -t peacemakr-go-sdk-example-integration:latest .

# Build the tests
docker build -f Dockerfile-test -t peacemakr-go-sdk-test .

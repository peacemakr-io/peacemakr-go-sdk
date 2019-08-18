#!/bin/sh

set -ex

# Setup credentials
`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

# Pull latest dependencies
docker build -f Dockerfile-dependencies -t peacemakr-go-sdk-dependencies --network=host .


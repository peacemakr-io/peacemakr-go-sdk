#!/bin/sh

set -ex

# Setup credentials
`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

# Pull latest dependencies

docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:0.0.2
docker pull 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:0.0.2

docker build -f Dockerfile-dependencies -t peacemakr-go-sdk-dependencies .


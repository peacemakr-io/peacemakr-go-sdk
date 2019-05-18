#!/bin/sh

set -ex

./swagger-go.sh validate peacemakr-services.yml

# Strip .yml off swagger file name
PROJECT_NAME="peacemakr-client"
mkdir -p generated

./swagger-go.sh generate client -f peacemakr-services.yml -A ${PROJECT_NAME} -t generated


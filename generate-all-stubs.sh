#!/bin/sh

rm -rf src/peacemakr/generated/peacemakr-client/ || true
./generate-stub-client.sh

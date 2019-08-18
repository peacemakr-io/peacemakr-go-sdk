#!/bin/sh

rm -rf pkg/generated || true
./generate-stub-client.sh

# Peacemakr
[![CircleCI](https://circleci.com/gh/notasecret/peacemakr-api/tree/master.svg?style=svg)](https://circleci.com/gh/notasecret/peacemakr-api/tree/master)

A cloud or on-prem backed service that which provides simple, backward compatible, and secure key lifecycle management.

## Getting started

How Do build this?

### (1) Get dependencies (alternatively, just build the dependecy to core-crypto locally)
 * Docker
 * AWS CLI tools
 * AWS account with read permissions to peacemakr's AWS ECR
   * 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:latest
   * 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:latest

### (2) Generate all stubs from swagger
```
./generate-all-stubs.sh
```

### (3) Build base images, containing all dependencies for peacemakr-api artifacts
```
./build-dependencies.sh
```

### (4) Build binaries for all peacmakr-api artifactors,
```
./build-binaries.sh
```

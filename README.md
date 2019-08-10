# Peacemakr Go SDK
[![CircleCI](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master.svg?style=svg)](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master)

A cloud or on-prem backed service that which provides simple, backward compatible, and secure key lifecycle management.

## Getting started

How do I build this?

### (1) Get dependencies (alternatively, just build the dependency to core-crypto locally)
 * Docker
 * AWS CLI tools
 * AWS account with read permissions to peacemakr's AWS ECR
   * 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto:latest
   * 716293438869.dkr.ecr.us-east-2.amazonaws.com/corecrypto-dependencies:latest

### (2) Generate all stubs from swagger
```
./generate-all-stubs.sh
```

### (3) Build base images, containing all dependencies for peacemakr-go-sdk artifacts
```
./build-dependencies.sh
```

### (4) Build docker images,
```
./build-binaries.sh
```

### (5) Release docker images,
```
./build-binaries.sh -release
```

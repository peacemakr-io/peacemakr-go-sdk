# Peacemakr
[![CircleCI](https://circleci.com/gh/notasecret/peacemakr-api/tree/master.svg?style=svg)](https://circleci.com/gh/notasecret/peacemakr-api/tree/master)

A cloud or on-prem backed service that which provides simple, backward compatible, and secure application layer encryption and signing.

High level design, https://docs.google.com/document/d/1VYYEsAgkDaGJzZqfLiWouOd04K53Pzx27-5BJiiMpFY/edit

## The SDKs
The SDK's perform all encryption and decryption operations. This allows for integration in both application layer client and/or server, as needed.

### Go
### Java
### iOS
### JavaScript

# Services
The SDK's are backed by a collection of cloud or on-prem services.

### Generate all stubs from swagger
```
./generate-all-stubs.sh
```

### Build base images, containing all dependencies
```
./build-dependencies.sh
```

### Build binaries,
```
./build-binaries.sh
```

### Run example integration,
```
docker run peacemakr-go-sdk-example-integration:latest
```

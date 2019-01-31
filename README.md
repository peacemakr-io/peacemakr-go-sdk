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

### Edit Swagger
```
./swagger-edit.sh peacemakr-services.yml
./swagger-edit.sh key-derivation-service.yml
```

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

### Something is exploding, how do I debug?
Run it in GDB,

(1) Get GDB inside your docker images:
# Get core dumps and gdb
RUN apk update && apk upgrade && apk add --no-cache gdb
RUN ulimit -c unlimited
ENV GOTRACEBACK=crash

Run your binary in an image with reduced security constraints:
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it key-derivation-service:latest /bin/sh

and now use GDB like a regular person.

<p align="center">
  <br>
    <img src="https://admin.peacemakr.io/p_logo.png" width="150"/>
  <br>
</p>

# Peacemakr E2E-Encryption-as-a-Service Golang SDK
[![CircleCI](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master.svg?style=svg&circle-token=a5e0dd516384638b6e97cd79c7963d8081873df2)](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master)

Peacemakr's E2E-Encryption-as-a-Service SDK simplify your data security with E2E-Encryption service and automated key lifecycle management.

You can easily encrypt your data without worrying about backward compatibility, cross platform portability, or changing security requirements.

Our Zero-Trust capability allows you to customize your security strength to meet the highest standard without having to place your trust in Peacemakr as we don’t have the capacity to get your keys and decrypt your data.

We take security and trust very seriously. If you believe you have found a security issue, please responsibly disclose by [contacting us](mailto:security@peacemakr.io).

## License

The content of this SDK is open source under [Apache License 2.0](https://github.com/peacemakr-io/peacemakr-go-sdk/blob/master/LICENSE).


## Getting Started

To install
```shell script
$ go get github.com/peacemakr-io/peacemakr-go-sdk
```

Sample go.mod
```
module my-awesome-project

go 1.12

require (
    github.com/peacemakr-io/peacemakr-go-sdk v0.0.10
)
```

## Why Peacemakr
We know what it's like to have your PM come to you late on a Friday and ask you for something
complicated. That's why we want to make it simple - to let you go home on that Friday night.
You can start encrypting messages in half an hour and get home in time for dinner.

This is all you need to get started, along with an API key. Visit [admin.peacemakr.io](https://admin.peacemakr.io) to get one of those.
```go
package my_sdk

import (
    peacemakr_tools "github.com/peacemakr-io/peacemakr-go-sdk/pkg/tools"
)

type MyMessage struct {
    Secret []byte `encrypt:"true"`
    Public []byte
}

type MySDK struct {
    Encryptor peacemakr_tools.Encryptor
}

func GetMySDK(cfg *peacemakr_tools.EncryptorConfig) (*MySDK, error) {
    // This can also be nil. If it is, peacemakr will read the values from the environment
    // that are prefixed with PEACEMAKR_ENCRYPTOR
    encryptor, err := peacemakr_tools.NewEncryptor(cfg)
    if err != nil {
        return nil, err
    }

    return &MySDK{
        Encryptor: encryptor,
    }, nil
}

func (m *MySDK) EncryptMessage(message *MyMessage) error {
    // Make sure you pass a pointer into this, it modifies the message in-place to encrypt the marked fields
    return m.Encryptor.Encrypt(message)
}

func (m *MySDK) DecryptMessage(message *MyMessage) error {
    // Make sure you pass a pointer into this, it modifies the message in-place to decrypt the marked fields
    return m.Encryptor.Decrypt(message)
}

```

## Contributing
We appreciate all contributions. Some basic guidelines are here, for more informaton
see CONTRIBUTING.md

Issues:
- Please include a minimal example that reproduces your issue
- Please use the tags to help us help you
- If you file an issue and you want to work on it, fantastic! Please assign it to yourself.

PRs:
- All PRs must be reviewed and pass CI


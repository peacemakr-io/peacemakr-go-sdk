# Peacemakr Go SDK
[![CircleCI](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master.svg?style=svg&circle-token=a5e0dd516384638b6e97cd79c7963d8081873df2)](https://circleci.com/gh/peacemakr-io/peacemakr-go-sdk/tree/master)

We take security and trust very seriously. If you believe you have found a security issue, please responsibly disclose by [contacting us](mailto:security@peacemakr.io).

### Getting Started

To install
```shell script
$ go get github.com/peacemakr-io/peacemakr-go-sdk
```

Sample go.mod
```
module my-awesome-project

go 1.12

require (
    github.com/peacemakr-io/peacemakr-go-sdk v0.0.8
)
```

### Why Peacemakr
We know what it's like to have your PM come to you late on a Friday and ask you for something
complicated. That's why we want to make it simple - to let you go home on that Friday night.
You can start encrypting messages in half an hour and get home in time for dinner.

This is all you need to get started, along with an API key. Visit [admin.peacemakr.io](https://admin.peacemakr.io) to get one of those.
```go
import (
    peacemakr "github.com/peacemakr-io/peacemakr-go-sdk/pkg"
)

type MySDK struct {
    PeacemakrSdk peacemakr.PeacemakrSDK
}

func GetPeacemakrSdk(apiKey string) (peacemakr.PeacemakrSDK, error) {
    url := "https://api.peacemakr.io"

    // Set up the SDK
    sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(
                        apiKey,       // <- This will need to be set up in advance
                        "my-project", // <- This is the name of the client that will show up in logs. Making it descriptive 
                                      //    will make it easier for us and for you!
                        &url,         // <- You'll usually ping https://api.peacemakr.io directly, but you may want to 
                                      //    redirect and you're free to do that! 
                        utils.GetDiskPersister("/tmp/"), // <- This can be substituted for utils.GetInMemPersister(). 
                                                         //    Benefits include that nothing will hit disk, but you 
                                                         //    will lose all your state and have to re-register on restart.
                                                         //    want to write a different persister? Go for it, and open a
                                                         //    PR.
                        log.New(os.Stdout, "MyProjectCrypto", log.LstdFlags) // <- This can also be nil, but this way
                                                                             //    you have a nice log prefix.
    )
    if err != nil {
        return nil, err
    }

    // Register as a client of the Peacemakr server
    if err := sdk.Register(); err != nil {
        return nil, err
    }

    return sdk, nil
}

func GetMySDK(apiKey string) (*MySDK, error) {
    peacemakrSDK, err := GetPeacemakrSdk(apiKey)
    if err != nil {
        return nil, err
    }

    return &MySDK{
        PeacemakrSdk: sdk,
    }, nil
}

func (m *MySDK) EncryptMessage(message []byte) ([]byte, error) {
    return m.PeacemakrSdk.Encrypt(message)
}

func (m *MySDK) DecryptMessage(encrypted []byte) ([]byte, error) {
    return m.PeacemakrSdk.Decrypt(encrypted)
}

```

### Contributing
We appreciate all contributions. Some basic guidelines are here, for more informaton
see CONTRIBUTING.md

Issues:
- Please include a minimal example that reproduces your issue
- Please use the tags to help us help you
- If you file an issue and you want to work on it, fantastic! Please assign it to yourself.

PRs:
- All PRs must be reviewed and pass CI


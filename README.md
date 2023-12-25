# MailHedgehog package to authenticate via file storage

All users data stored in physical file on server. Useful for simple implementation with small amount of users.

## Usage

```go
package main

import (
    "github.com/mailhedgehog/gounit"
    "testing"
)

func Test(t *testing.T) {
    config := &contracts.AuthenticationConfig{}
    config.Dashboard.ViaPasswordAuthentication.Enabled = true
    auth := CreateFileAuthentication(&StorageConfiguration{Path: filePath}, config)

    (*gounit.T)(t).AssertTrue(auth.Dashboard().ViaPasswordAuthentication().Authenticate("user1", "foobar"))
}
```

## Development

```shell
go mod tidy
go mod verify
go mod vendor
go test --cover
```

## Credits

- [![Think Studio](https://yaroslawww.github.io/images/sponsors/packages/logo-think-studio.png)](https://think.studio/)

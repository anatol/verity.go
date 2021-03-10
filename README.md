# Pure Go library for verity device management

`verity.go` is a pure-Go library that helps to open/close [verity devices](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity).

`verity.go` is essentially a wrapper that helps to read on-disk dm-verity header and then set up a device mapper for it.

Here is an example that demonstrates the API usage:
```go
import "github.com/anatol/verity.go"

func main() {
    // format a verity device e.g.
    // veritysetup format --salt 0b14956bc90cf4b1d9f6ee07e84ff8ed45fc8c30785e14976d6b876090a580f0 /dev/sdX1 /dev/sdX2
    // where /dev/sdX1 is your data device and /dev/sdX2 is the hash device
    // this command returns root digest that you going to use to open the device

    name := "test.verity"
    digest := "5476200ad7eab4ecbca42bb1ba81f6562f7b9ebf256ddf2dd1cbe7a148f46ab4"
    if err := verity.Open(name, "/dev/sdX1", "/dev/sdX2", digest); err != nil {
        // handle error
    }
    defer verity.Close(name)

    // at this point a read-only mapper device /dev/mapper/test.verity will be available
}
```

## License

See [LICENSE](LICENSE).

# MassNet Core

[![MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)](./LICENSE)

`mass-core` is a Golang implementation of MassNet full-node core modules.

## Requirements

[Go](http://golang.org) 1.13 or newer.

## Development

### Contributing Code

#### Prerequisites

- Install [Golang](http://golang.org) 1.13 or newer.
- Install the specific version or [ProtoBuf](https://developers.google.com/protocol-buffers), and related `protoc-*`:
  ```
  # libprotoc
  libprotoc 3.6.1
  
  # github.com/golang/protobuf 1.3.2
  protoc-gen-go
  
  # github.com/gogo/protobuf 1.2.1
  protoc-gen-gogo
  protoc-gen-gofast
  
  # github.com/grpc-ecosystem/grpc-gateway 1.9.6
  protoc-gen-grpc-gateway
  protoc-gen-swagger
  ```

#### Modifying Code

- New codes should be compatible with Go 1.13 or newer.
- Run `gofmt` and `goimports` to lint go files.
- Run `make test` before building executables.

#### Reporting Bugs

Contact MASS community via community@massnet.org, and we will get back to you soon.

#### Verifying Commits

The following keys maybe trusted to commit code.

| Name | Fingerprint |
|------|-------------|
| massnetorg | A8A9 5C74 1AB8 08D3 E6E6  5B6C F8A8 D5CF 14D0 C419 |

## License

`MassNet Core` is licensed under the terms of the MIT license. See LICENSE for more information or see https://opensource.org/licenses/MIT.

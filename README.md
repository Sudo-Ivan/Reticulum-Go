# Reticulum-Go

> [!WARNING]  
> This project is still work in progress. Currently not compatible with the Python version.

[![Socket Badge](https://socket.dev/api/badge/go/package/github.com/sudo-ivan/reticulum-go?version=v0.4.0)](https://socket.dev/go/package/github.com/sudo-ivan/reticulum-go)
![Go Test](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/go-test.yml/badge.svg)
![Run Gosec](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/gosec.yml/badge.svg)
[![Go Build Multi-Platform](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/build.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/build.yml)
[![Go Revive Lint](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/revive.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/revive.yml)

[Reticulum Network](https://github.com/markqvist/Reticulum) implementation in Go `1.25+`.

Aiming to be fully compatible with the Python version. 

Feel free to join our seperate [matrix](https://matrix.to/#/#reticulum-go-dev:matrix.org) channel for this implementation.

## Usage

### Building

Requires Go 1.25+

```
make install
make build
make run
```

### Experimental Green Tea GC 

New GC as of Go 1.25.

See [greenteagc github issue](https://github.com/golang/go/issues/73581) for more info.

```bash
make build-experimental
```

## Linter

[Revive](https://github.com/mgechev/revive)

```bash
revive -config revive.toml -formatter friendly ./pkg/* ./cmd/* ./internal/*
```

## Cryptographic Libraries

- `golang.org/x/crypto` `v0.42.0` - Cryptographic primitives

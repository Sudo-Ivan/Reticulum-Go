# Reticulum-Go

> [!WARNING]  
> This project is still work in progress. Currently not compatible with the Python version.

[![Socket Badge](https://socket.dev/api/badge/go/package/github.com/sudo-ivan/reticulum-go?version=v0.3.9)](https://socket.dev/go/package/github.com/sudo-ivan/reticulum-go)
![Go Test](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/go-test.yml/badge.svg)
![Run Gosec](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/gosec.yml/badge.svg)
[![Bearer](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/bearer.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/bearer.yml)
[![Go Build Multi-Platform](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/build.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/build.yml)
[![Go Revive Lint](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/revive.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/revive.yml)

[Reticulum Network](https://github.com/markqvist/Reticulum) implementation in Go `1.24+`.

Aiming to be fully compatible with the Python version. 

## Usage

Requires Go 1.24+

```
make install
make build
make run
```

## Linter

[Revive](https://github.com/mgechev/revive)

```bash
revive -config revive.toml -formatter friendly ./pkg/* ./cmd/* ./internal/*
```

## External Packages

- `golang.org/x/crypto` `v0.39.0` - Cryptographic primitives

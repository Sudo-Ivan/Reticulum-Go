# Reticulum-Go

> [!WARNING]  
> This project is still work in progress. Currently not compatible with the Python version.

[![Socket Badge](https://socket.dev/api/badge/go/package/github.com/sudo-ivan/reticulum-go?version=v0.3.9)](https://socket.dev/go/package/github.com/sudo-ivan/reticulum-go)

[Reticulum Network](https://github.com/markqvist/Reticulum) implementation in Go `1.24+`.

Aiming to be fully compatible with the Python version. 

# Testing

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

- `golang.org/x/crypto` `v0.37.0` - Cryptographic primitives

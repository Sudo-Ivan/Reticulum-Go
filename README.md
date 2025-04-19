# Reticulum-Go

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


## License

This project is licensed under the [Reticulum License](LICENSE). Adopted from [Reticulum](https://github.com/markqvist/Reticulum/blob/dba6cd8393ec0d3137412b1f3890d12243bcfe10/LICENSE).
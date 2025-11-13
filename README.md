[![Socket Badge](https://socket.dev/api/badge/go/package/github.com/sudo-ivan/reticulum-go?version=v0.4.0)](https://socket.dev/go/package/github.com/sudo-ivan/reticulum-go)
![Multi-Platform Tests](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/go-test.yml/badge.svg)
![Gosec Scan](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/gosec.yml/badge.svg)
[![Multi-Platform Build](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/build.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/build.yml)
[![Revive Linter](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/revive.yml/badge.svg)](https://github.com/Sudo-Ivan/Reticulum-Go/actions/workflows/revive.yml)

# Reticulum-Go

A Go implementation of the [Reticulum Network Protocol](https://github.com/markqvist/Reticulum).

> [!WARNING]  
> This project is currently in development and is not yet compatible with the Python reference implementation.

## Goals

- To be fully compatible with the Python reference implementation.
- Additional privacy and security features.
- Support for a broader range of platforms and architectures legacy and modern.

## Quick Start

### Prerequisites

- Go 1.24 or later

### Build

```bash
make build
```

### Run

```bash
make run
```

### Test

```bash
make test
```

## Embedded systems and WebAssembly

For building for WebAssembly and embedded systems, see the [tinygo branch](https://github.com/Sudo-Ivan/Reticulum-Go/tree/tinygo). Requires TinyGo 0.37.0+.

```bash
make tinygo-build
make tinygo-wasm
```

### Experimental Features

Build with experimental Green Tea GC (Go 1.25+):

```bash
make build-experimental
```

## Official Channels

- [Telegram](https://t.me/reticulum_go)
- [Matrix](https://matrix.to/#/#reticulum-go-dev:matrix.org)

## Donations

See [donate.md](donate.md) for more information.
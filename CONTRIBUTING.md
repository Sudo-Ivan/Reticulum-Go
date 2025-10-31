# Contributing

Be good to each other.

## Communication

Feel free to join our telegram or matrix channels for this implementation.

- [Matrix](https://matrix.to/#/#reticulum-go-dev:matrix.org)
- [Telegram](https://t.me/reticulum_go)

## Usage of LLMs and other Generative AI tools

You should not use LLMs and other generative AI tools to write critical parts of the code. They can produce lots of security issues and outdated code when used incorrectly. You are not required to report that you are using these tools. 

## Static Analysis Tools

You are welcome to use the following tools, however there are actions in place to ensure the code is linted and checked with gosec.

### Linting (optional)

[Revive](https://github.com/mgechev/revive)

```bash
revive -config revive.toml -formatter friendly ./pkg/* ./cmd/* ./internal/*
```

### Security (optional)

[Gosec](https://github.com/securego/gosec)

```bash
gosec ./...
```


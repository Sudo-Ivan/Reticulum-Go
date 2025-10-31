# Security Policy

We use [Socket](https://socket.dev/), [Deepsource](https://deepsource.com/) and [gosec](https://github.com/securego/gosec) for this project.

## Supply Chain Security

- All actions are pinned to a commit hash. 

## Cryptography Dependencies

- golang.org/x/crypto for core cryptographic primitives
  - hkdf
  - curve25519

- go/crypto
  - ed25519
  - sha256
  - rand
  - aes
  - cipher
  - hmac

## Reporting a Vulnerability

Please report any security vulnerabilities using Github reporting tool or email to [rns@quad4.io](mailto:rns@quad4.io)
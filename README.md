# Reticulum-Go

Reticulum Network Stack in Go.

## To-Do List

### Core Components (In Progress)
- [x] Basic Configuration System
  - [x] Basic config structure
  - [x] Default settings
  - [x] Config file loading/saving
  - [x] Path management

- [x] Constants Definition (Testing required)
  - [x] Packet constants
  - [x] MTU constants
  - [x] Header types
  - [x] Additional protocol constants

- [x] Identity Management (Testing required)
  - [x] Identity creation
  - [x] Key pair generation
  - [x] Identity storage/recall
  - [x] Public key handling
  - [x] Signature verification
  - [x] Hash functions

- [x] Cryptographic Primitives (Testing required)
  - [x] Ed25519
  - [x] Curve25519
  - [x] AES-GCM
  - [x] SHA-256
  - [x] HKDF
  - [x] Secure random number generation
  - [x] HMAC

- [x] Packet Handling (In Progress)
  - [x] Packet creation
  - [x] Packet validation
  - [x] Basic proof system
  - [x] Packet encryption
  - [x] Signature verification
  - [ ] Testing of packet encrypt/decrypt/sign/proof

- [x] Transport Layer (In Progress)
  - [x] Path management
  - [x] Basic packet routing
  - [x] Announce handling
  - [x] Link management
  - [x] Resource cleanup
  - [x] Network layer integration
  - [ ] Testing announce from go client to python client
  - [ ] Testing path finding and caching

### Interface Implementation (In Progress)
- [x] UDP Interface
- [x] TCP Interface
- [x] Auto Interface
- [ ] Local Interface (In Progress)
- [ ] I2P Interface
- [ ] Pipe Interface
- [ ] RNode Interface
- [ ] RNode Multiinterface
- [ ] Serial Interface
- [ ] AX25KISS Interface
- [ ] Interface Discovery
- [ ] Interface Modes
  - [ ] Full mode
  - [ ] Gateway mode
  - [ ] Access point mode
  - [ ] Roaming mode
  - [ ] Boundary mode

### Destination System (Testing required)
- [x] Destination creation
- [x] Destination types (IN/OUT)
- [x] Destination aspects
- [x] Announce implementation
- [x] Ratchet support
- [x] Request handlers

### Link System (Testing required)
- [x] Link establishment
- [x] Link teardown
- [x] Basic packet transfer
- [x] Encryption/Decryption
- [x] Identity verification
- [x] Request/Response handling
- [x] Session key management
- [x] Link state tracking

### Resource System (Testing required)
- [x] Resource creation
- [x] Resource transfer
- [x] Compression
- [x] Progress tracking
- [x] Segmentation
- [x] Cleanup routines

### Testing & Validation
- [ ] Unit tests for all components (Link, Resource, Destination, Identity, Packet, Transport, Interface)
- [ ] Integration tests
- [ ] Cross-client compatibility tests
- [ ] Performance benchmarks
- [ ] Security auditing (When Reticulum is 1.0 / stable)

### Documentation
- [ ] API documentation
- [ ] Usage examples

### Cleanup
- [ ] Seperate Cryptography from identity.go to their own files.
- [ ] Move constants to their own files.

### Other
- [ ] Rate limiting
- [ ] QoS implementation?

### Ivans Future Addon Packages
- [ ] Post-quantum cryptographic primitives (separate package)
- [ ] Hardware security module (HSM) support (separate package)
- [ ] Encrypted storage for identities (separate package)
# Reticulum-Go

> [!NOTE]  
> This is WIP and not ready as of FEB 2025, Code might be a little messy in some areas.

[Reticulum Network](https://github.com/markqvist/Reticulum) implementation in Go.

Aiming for full spec compatibility with the Python version 0.8.8+. 

`Go 1.23.4`

Packages:

- `golang.org/x/crypto`

# Testing

```
make install
make build
make run
```

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
  - [x] AES-CBC
  - [x] SHA-256
  - [x] HKDF
  - [x] Secure random number generation
  - [x] HMAC

- [x] Packet Handling (In Progress)
  - [x] Packet creation
  - [x] Packet validation
  - [x] Basic proof system
  - [x] Packet encryption/decryption
  - [x] Signature verification
  - [x] Announce packet structure
  - [ ] Testing of packet encrypt/decrypt/sign/proof
  - [ ] Cross-client packet compatibility

- [x] Transport Layer (In Progress)
  - [x] Path management
  - [x] Basic packet routing
  - [x] Announce handling
  - [x] Link management
  - [x] Resource cleanup
  - [x] Network layer integration
  - [x] Basic announce implementation
  - [ ] Testing announce from go client to python client
  - [ ] Testing path finding and caching
  - [ ] Announce propagation optimization

- [x] Channel System (Testing Required)
  - [x] Channel creation and management
  - [x] Message handling
  - [x] Channel encryption
  - [x] Channel authentication
  - [x] Channel callbacks
  - [x] Integration with Buffer system
  - [ ] Testing with real network conditions
  - [ ] Cross-client compatibility testing

- [x] Buffer System (Testing Required)
  - [x] Raw channel reader/writer
  - [x] Buffered stream implementation
  - [x] Compression support
  - [ ] Testing with Channel system
  - [ ] Cross-client compatibility testing

- [x] Resolver System (Testing Required)
  - [x] Name resolution
  - [x] Cache management
  - [x] Announce handling
  - [x] Path resolution
  - [x] Integration with Transport layer
  - [ ] Testing with live network
  - [ ] Cross-client compatibility testing

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

- [ ] Hot reloading interfaces

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

### Compatibility
- [ ] RNS Utilities.
- [ ] Reticulum config.


### Testing & Validation (Priority)
- [ ] Unit tests for all components
  - [ ] Identity tests
  - [ ] Packet tests
  - [ ] Transport tests
  - [ ] Interface tests
  - [ ] Announce tests
  - [ ] Channel tests
  - [ ] Buffer tests
  - [ ] Resolver tests
  - [ ] Link tests
  - [ ] Resource tests
- [ ] Integration tests
  - [ ] Go client to Go client
  - [ ] Go client to Python client
  - [ ] Interface compatibility
  - [ ] Path finding and resolution
  - [ ] Channel system end-to-end
  - [ ] Buffer system performance
- [ ] Cross-client compatibility tests
- [ ] Performance benchmarks
- [ ] Security auditing (When Reticulum is 1.0 / stable)

### Documentation
- [ ] API documentation
- [ ] Usage examples

### Cleanup
- [ ] Separate Cryptography from identity.go to their own files
- [ ] Move constants to their own files
- [ ] Remove default community interfaces in default config creation after testing
- [ ] Optimize announce packet creation and caching
- [ ] Improve debug logging system

### Other
- [ ] Rate limiting
- [ ] QoS implementation?

### Ivans Future Addon Packages
- [ ] Post-quantum cryptographic primitives (separate package)
- [ ] Hardware security module (HSM) support (separate package)
- [ ] Encrypted storage for identities (separate package)
- [ ] Defense against AI-guided Traffic Analysis (separate package)

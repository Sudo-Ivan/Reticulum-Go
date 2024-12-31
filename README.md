# Reticulum-Go

Reticulum Network Stack in Go. 

To-Do List

Core Components
[✓] Basic Configuration System
    [✓] Basic config structure
    [✓] Default settings
    [✓] Config file loading/saving
    [✓] Path management

[✓] Constants Definition
    [✓] Packet constants
    [✓] MTU constants
    [✓] Header types
    [✓] Additional protocol constants

[✓] Identity Management
    [✓] Identity creation
    [✓] Key pair generation
    [✓] Identity storage/recall
    [✓] Public key handling
    [✓] Signature verification
    [✓] Hash functions

[✓] Cryptographic Primitives
    [✓] Ed25519
    [✓] Curve25519
    [✓] AES-GCM
    [✓] SHA-256
    [✓] HKDF
    [✓] Secure random number generation
    [✓] HMAC

[✓] Packet Handling
    [✓] Packet creation
    [✓] Packet validation
    [✓] Basic proof system
    [✓] Packet encryption
    [✓] Signature verification
    [ ] Testing of packet encrypt/decrypt/sign/proof

[✓] Transport Layer
    [✓] Path management
    [✓] Basic packet routing
    [✓] Announce handling
    [✓] Link management
    [✓] Resource cleanup
    [✓] Network layer integration
    [ ] Testing announce from go client to python client
    [ ] Testing path finding and caching

[✓] Interface Implementation
    [✓] UDP Interface
    [✓] TCP Interface
    [✓] Auto Interface
    [ ] Local Interface (In Progress)
    [ ] I2P Interface
    [ ] Pipe Interface
    [ ] RNode Interface
    [ ] RNode Multiinterface
    [ ] Serial Interface
    [ ] AX25KISS Interface
    [ ] Interface Discovery
    [ ] Interface Modes
        - [ ] Full mode
        - [ ] Gateway mode
        - [ ] Access point mode
        - [ ] Roaming mode
        - [ ] Boundary mode

[✓] Destination System
    [✓] Destination creation
    [✓] Destination types (IN/OUT)
    [✓] Destination aspects
    [✓] Announce implementation
    [✓] Ratchet support
    [✓] Request handlers

[✓] Link System
    [✓] Link establishment
    [✓] Link teardown
    [✓] Basic packet transfer
    [✓] Encryption/Decryption
    [✓] Identity verification
    [✓] Request/Response handling
    [✓] Session key management
    [✓] Link state tracking

[✓] Resource System
    [✓] Resource creation
    [✓] Resource transfer
    [✓] Compression
    [✓] Progress tracking
    [✓] Segmentation
    [✓] Cleanup routines

[ ] Testing & Validation
    [ ] Unit tests for all components (Link, Resource, Destination, Identity, Packet, Transport, Interface)
    [ ] Integration tests
    [ ] Cross-client compatibility tests
    [ ] Performance benchmarks
    [ ] Security auditing (When Reticulum is 1.0 / stable)

[ ] Documentation
    [ ] API documentation
    [ ] Usage examples

[ ] Other
    [ ] Rate limiting
    [ ] QoS implementation?

[ ] Ivans Future Addon Packages
    [ ] Post-quantum cryptographic primitives (seperate package)
    [ ] Hardware security module (HSM) support (seperate package)
    [ ] Encrypted storage for identities (seperate package)
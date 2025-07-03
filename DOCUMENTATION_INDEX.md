# ZkSchnorr Library Documentation

Welcome to the ZkSchnorr library documentation. This pure-Rust implementation of Schnorr signatures using Ristretto provides secure, efficient signature operations with batch verification capabilities.

## Documentation Overview

### 📖 [Developer Guide](DEVELOPER_GUIDE.md)
Comprehensive guide covering:
- Library overview and features
- Installation instructions
- Quick start examples
- Complete API documentation
- Advanced usage patterns
- Security considerations
- Integration examples
- Performance optimization
- Troubleshooting guide

### 📚 [API Reference](docs/API.md)
Complete API documentation including:
- All public types and methods
- Parameter descriptions
- Return values and error types
- Usage patterns
- Performance characteristics
- Thread safety information

### 💡 [Code Examples](docs/EXAMPLES.md)
Practical examples covering:
- Basic message signing and verification
- Document authentication
- User authentication systems
- Multi-context signing with transcripts
- Batch verification for performance
- JSON API integration
- Database integration
- Performance benchmarking
- Memory-efficient processing

## Quick Reference

### Basic Usage
```rust
use zkschnorr::{VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;

// Generate keys
let private_key = Scalar::random(&mut rand::thread_rng());
let nonce = Scalar::random(&mut rand::thread_rng());
let verification_key = VerificationKey::from_secret(&private_key, &nonce);

// Sign and verify
let signature = Signature::sign_message(b"label", b"message", verification_key, private_key);
assert!(signature.verify_message(b"label", b"message", verification_key).is_ok());
```

### Batch Verification
```rust
use zkschnorr::BatchVerifier;

let mut batch = BatchVerifier::new(rand::thread_rng());
// Add signatures with verify_batched()
let result = batch.verify();
```

## Getting Started

1. **New to Schnorr signatures?** Start with the [Developer Guide](DEVELOPER_GUIDE.md)
2. **Need specific API details?** Check the [API Reference](docs/API.md)
3. **Looking for code examples?** Browse the [Examples](docs/EXAMPLES.md)
4. **Integration questions?** See the integration sections in the Developer Guide

## Key Features

- **🔒 Secure**: Built on Ristretto255 and Merlin transcripts
- **⚡ Fast**: Efficient batch verification for multiple signatures
- **🛠️ Flexible**: Both simple message API and advanced transcript API
- **📦 Pure Rust**: No external dependencies outside the Rust ecosystem
- **🧵 Thread-Safe**: Core types are Send + Sync
- **💾 Compact**: 64-byte signatures and verification keys

## Dependencies

- `curve25519-dalek`: Elliptic curve operations
- `merlin`: Transcript-based random oracles
- `rand`: Random number generation
- `serde`: Serialization support
- `thiserror`: Error handling

## License

This library is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

For bug reports, feature requests, or contributions, please refer to the project repository.

---

*This documentation was generated for zkschnorr v1.0.0*
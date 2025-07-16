# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- No pending changes.

## [v0.1.1] - 2024-07-16

### Changed
- Updated the `hex` dependency from `0.3.2` to `0.4.3` to resolve dependency duplication issues in downstream crates. This has no impact on the public API.

## [0.1.0] - 2025-07-08

### Known Issues
- **RUSTSEC-2024-0344**: Uses curve25519-dalek v3.2.1 with timing vulnerability
  - Will be resolved in v0.2.0 by upgrading to curve25519-dalek v4.1.3+
  - Maintained for ecosystem compatibility in v0.1.x series

### Security
- **⚠️ SECURITY WARNING**: This library has not been formally audited
- Known timing vulnerability in curve25519-dalek dependency (see Known Issues)

- Initial public release of the zkSchnorr multipoint signature library
- Core signature operations:
  - `Signature::sign()` - Transcript-based signing
  - `Signature::verify()` - Transcript-based verification
  - `Signature::sign_message()` - Simple message signing API
  - `Signature::verify_message()` - Simple message verification API
- Multipoint verification keys with `VerificationKey` struct
- Batch verification with `BatchVerifier` for improved performance
- Comprehensive serialization support:
  - `Signature::to_bytes()` and `Signature::from_bytes()`
  - `VerificationKey::to_bytes()` and `VerificationKey::from_bytes()`
- Optimized multiscalar multiplication algorithm for batch verification
- Merlin transcript integration for domain separation
- Support for Ristretto255 curve via `curve25519-dalek`
- Comprehensive test suite with 8+ test cases
- Documentation with examples and usage instructions
- Working examples in `examples/basic_usage.rs`

### Security
- Protection against signature malleability
- Secure random nonce generation via transcript RNG
- Batch verification with cancellation attack protection

### Performance
- Single signature verification: ~1ms per signature
- Batch verification: ~0.1ms per signature (10x improvement for large batches)

### Documentation
- Complete API documentation with examples
- Comprehensive README with usage instructions
- Specification document in `docs/spec.md`
- Working code examples demonstrating all features

---
## Legacy
### [0.0.1] - Legacy Development
#### Fixed
- Fixed critical batch verification bug causing scalar/point mismatch
- Fixed domain separator inconsistency between spec and implementation
- Fixed incorrect multiscalar multiplication in batch verifier
- Fixed empty batch verification handling

#### Changed
- Updated domain separator from "ElGamalSign v1" to "zkschnorr v1"
- Improved error handling and validation
- Enhanced documentation and examples

---

## Security Notice

**⚠️ This cryptographic library has not undergone formal security auditing.**

While the implementation follows established cryptographic practices and has been thoroughly tested, it has not been reviewed by independent security experts. Use at your own risk, especially in production environments.

For production use, we recommend:
1. Independent security review of the code
2. Formal cryptographic audit by qualified professionals


## Contributing

See the main README for contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
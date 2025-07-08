# ZkSchnorr: Multipoint Schnorr Signatures on Ristretto

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)



> **⚠️ SECURITY WARNING**
> 
> **This library has not been formally audited and is not recommended for production use.**
> 
> While this implementation follows established cryptographic practices and has been thoroughly tested, it has not been reviewed by independent security experts. Use at your own risk, especially in production environments.
> 
> For production use, we recommend:
> - Independent security review of the code
> - Formal cryptographic audit by qualified professionals
> - Extensive testing in your specific use case
> - Following standard security practices for key management

A pure-Rust implementation of a multipoint Schnorr signature protocol using [Ristretto](https://ristretto.group) and [Merlin transcripts](https://merlin.cool). This library extends the concepts from [Starsig](https://github.com/stellar/slingshot/tree/main/starsig) to support multipoint Elgamal verification keys.

## Features

* **Simple message-based API** - Sign and verify messages with minimal setup
* **Flexible transcript-based API** - Full control over signature contexts using Merlin transcripts
* **Single signature verification** - Verify individual signatures efficiently
* **Batch signature verification** - Verify multiple signatures in a single operation for better performance
* **Deterministic serialization** - Reliable encoding/decoding of signatures and keys


## Security

This implementation follows the [specification](docs/spec.md) and provides:
- Protection against signature malleability
- Secure random nonce generation
- Proper domain separation using Merlin transcripts
- Batch verification with protection against cancellation attacks

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
zkschnorr = "0.1.0"
```

## Quick Start

### Basic Usage

```rust
use zkschnorr::{Signature, VerificationKey, SigningKey};
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

// Generate keys
let signing_key = Scalar::random(&mut thread_rng());
let randomness = Scalar::random(&mut thread_rng());
let verification_key = VerificationKey::from_secret(&signing_key, &randomness);

// Sign a message
let message = b"Hello, zkSchnorr!";
let signature = Signature::sign_message(b"example", message, verification_key, signing_key);

// Verify the signature
assert!(signature.verify_message(b"example", message, verification_key).is_ok());
```

### Batch Verification

```rust
use zkschnorr::{Signature, VerificationKey, BatchVerifier};
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

let mut batch = BatchVerifier::new(thread_rng());

// Add multiple signatures to the batch
for i in 0..10 {
    let signing_key = Scalar::random(&mut thread_rng());
    let randomness = Scalar::random(&mut thread_rng());
    let verification_key = VerificationKey::from_secret(&signing_key, &randomness);
    
    let message = format!("Message {}", i);
    let signature = Signature::sign_message(b"batch", message.as_bytes(), verification_key, signing_key);
    
    signature.verify_batched(
        &mut merlin::Transcript::new(b"zkschnorr.sign_message")
            .tap(|t| t.append_message(b"batch", message.as_bytes())),
        verification_key,
        &mut batch
    );
}

// Verify all signatures in the batch
assert!(batch.verify().is_ok());
```

### Serialization

```rust
use zkschnorr::{Signature, VerificationKey};

// Serialize signature to bytes
let signature_bytes = signature.to_bytes();

// Deserialize signature from bytes
let recovered_signature = Signature::from_bytes(signature_bytes)?;

// Serialize verification key
let key_bytes = verification_key.to_bytes();

// Deserialize verification key
let recovered_key = VerificationKey::from_bytes(&key_bytes)?;
```

## Advanced Usage

### Using Transcripts Directly

For more control over the signature context, you can use Merlin transcripts directly:

```rust
use merlin::Transcript;
use zkschnorr::{Signature, TranscriptProtocol};

let mut transcript = Transcript::new(b"my-protocol");
transcript.append_message(b"context", b"important context data");
transcript.append_message(b"message", b"the message to sign");

let signature = Signature::sign(&mut transcript, verification_key, signing_key);

// For verification, recreate the same transcript
let mut verify_transcript = Transcript::new(b"my-protocol");
verify_transcript.append_message(b"context", b"important context data");
verify_transcript.append_message(b"message", b"the message to sign");

assert!(signature.verify(&mut verify_transcript, verification_key).is_ok());
```

## API Reference

### Types

- `Signature` - A Schnorr signature containing point R and scalar s
- `VerificationKey` - A multipoint verification key containing points G and H
- `SigningKey` - Type alias for `curve25519_dalek::scalar::Scalar`
- `BatchVerifier` - Batch verification context for multiple signatures

### Key Functions

- `Signature::sign_message()` - Simple message signing
- `Signature::verify_message()` - Simple message verification
- `Signature::sign()` - Transcript-based signing
- `Signature::verify()` - Transcript-based verification
- `Signature::verify_batched()` - Add signature to batch verifier
- `BatchVerifier::verify()` - Verify all signatures in batch

## Performance

Batch verification provides significant performance improvements when verifying multiple signatures:

- Single signature verification: ~1ms per signature
- Batch verification: ~0.1ms per signature (for batches of 10+ signatures)

## Security Considerations

1. **Randomness**: The library uses cryptographically secure randomness from the transcript RNG
2. **Nonce Reuse**: Each signature uses a unique nonce derived from the message and private key
3. **Domain Separation**: Proper domain separation prevents cross-protocol attacks
4. **Batch Verification**: Uses random weights to prevent signature cancellation attacks

## Testing

Run the test suite:

```bash
cargo test
```

For verbose output:

```bash
cargo test -- --nocapture
```

## Specification

See the [specification document](docs/spec.md) for detailed protocol description.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built on [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- Uses [Merlin](https://github.com/dalek-cryptography/merlin) for transcript-based proofs
- Inspired by [Starsig](https://github.com/stellar/slingshot/tree/main/starsig)
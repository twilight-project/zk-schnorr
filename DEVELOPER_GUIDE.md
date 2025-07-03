# ZkSchnorr Developer Guide

## Overview

ZkSchnorr is a pure-Rust implementation of Schnorr Protocol using Ristretto that supports multipoint Elgamal verification keys. This library provides both single signature verification and efficient batch signature verification capabilities.

## Features

- ✅ Simple message-based API for easy integration
- ✅ Flexible transcript-based API for advanced use cases
- ✅ Single signature verification
- ✅ Batch signature verification for improved performance
- ✅ Built on Ristretto255 for security and performance
- ✅ Merlin transcript support for Fiat-Shamir transforms

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
zkschnorr = "1.0.0"
```

Or if you're using this library locally:

```toml
[dependencies]
zkschnorr = { path = "path/to/zkschnorr" }
```

## Quick Start

### Basic Signing and Verification

```rust
use zkschnorr::{SigningKey, VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

// Generate a private key
let privkey = Scalar::from(42u64);
let r = Scalar::random(&mut rand::thread_rng());

// Create verification key from private key
let verification_key = VerificationKey::from_secret(&privkey, &r);

// Sign a message using transcript-based API
let mut transcript = Transcript::new(b"MyApp.sign");
transcript.append_message(b"message", b"Hello, World!");
let signature = Signature::sign(&mut transcript, verification_key, privkey);

// Verify the signature
let mut verify_transcript = Transcript::new(b"MyApp.sign");
verify_transcript.append_message(b"message", b"Hello, World!");
assert!(signature.verify(&mut verify_transcript, verification_key).is_ok());
```

### Simple Message API

For basic use cases, you can use the simplified message-based API:

```rust
use zkschnorr::{SigningKey, VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;

// Generate keys
let privkey = Scalar::from(42u64);
let r = Scalar::random(&mut rand::thread_rng());
let verification_key = VerificationKey::from_secret(&privkey, &r);

// Sign a message
let signature = Signature::sign_message(
    b"document", 
    b"This is my important document", 
    verification_key, 
    privkey
);

// Verify the signature
assert!(signature.verify_message(
    b"document", 
    b"This is my important document", 
    verification_key
).is_ok());
```

## API Reference

### Core Types

#### `SigningKey`
```rust
pub type SigningKey = Scalar;
```
The signing key (private key) is a scalar in the Ristretto255 group.

#### `VerificationKey`
```rust
pub struct VerificationKey {
    pub(crate) g: CompressedRistretto,  // G.r
    pub(crate) h: CompressedRistretto,  // (G.r).sk
}
```

**Methods:**
- `VerificationKey::from_secret(privkey: &Scalar, r: &Scalar) -> Self`
  - Creates a verification key from a private key and randomness
- `VerificationKey::new(g: CompressedRistretto, h: CompressedRistretto) -> Self`
  - Creates a verification key from two compressed points
- `to_bytes(&self) -> Vec<u8>`
  - Returns the 64-byte representation of the verification key

#### `Signature`
```rust
pub struct Signature {
    pub s: Scalar,                    // Signature scalar
    pub R: CompressedRistretto,       // Nonce commitment
}
```

**Signing Methods:**
- `Signature::sign(transcript: &mut Transcript, pubkey: VerificationKey, privkey: Scalar) -> Signature`
  - Signs using a Merlin transcript (advanced API)
- `Signature::sign_message(label: &'static [u8], message: &[u8], pubkey: VerificationKey, privkey: Scalar) -> Signature`
  - Signs a message with a label (simple API)

**Verification Methods:**
- `verify(&self, transcript: &mut Transcript, pubkey: VerificationKey) -> Result<(), ZkSchnorrError>`
  - Verifies a signature using a transcript
- `verify_message(&self, label: &'static [u8], message: &[u8], pubkey: VerificationKey) -> Result<(), ZkSchnorrError>`
  - Verifies a message signature
- `verify_batched(&self, transcript: &mut Transcript, pubkey: VerificationKey, batch: &mut impl BatchVerification)`
  - Adds signature to a batch verifier

**Serialization Methods:**
- `to_bytes(&self) -> [u8; 64]` - Encodes signature as 64 bytes
- `from_bytes(sig: impl AsRefExt) -> Result<Self, ZkSchnorrError>` - Decodes from bytes

### Batch Verification

For verifying multiple signatures efficiently:

```rust
use zkschnorr::{BatchVerifier, Signature, VerificationKey};
use merlin::Transcript;

// Create a batch verifier
let mut batch = BatchVerifier::new(rand::thread_rng());

// Add signatures to the batch
signature1.verify_batched(&mut transcript1, pubkey1, &mut batch);
signature2.verify_batched(&mut transcript2, pubkey2, &mut batch);
signature3.verify_batched(&mut transcript3, pubkey3, &mut batch);

// Verify all signatures at once
match batch.verify() {
    Ok(()) => println!("All signatures valid!"),
    Err(ZkSchnorrError::InvalidBatch) => println!("At least one signature is invalid"),
}
```

### Error Handling

```rust
use zkschnorr::ZkSchnorrError;

match signature.verify(&mut transcript, verification_key) {
    Ok(()) => println!("Signature is valid"),
    Err(ZkSchnorrError::InvalidSignature) => println!("Invalid signature"),
    Err(ZkSchnorrError::InvalidBatch) => println!("Batch verification failed"),
}
```

## Advanced Usage

### Using Transcripts for Complex Protocols

Transcripts provide a way to implement complex cryptographic protocols with proper domain separation:

```rust
use merlin::Transcript;
use zkschnorr::{Signature, VerificationKey, TranscriptProtocol};

// Create a transcript with domain separation
let mut transcript = Transcript::new(b"MyProtocol.v1");

// Add context to the transcript
transcript.append_message(b"user_id", b"alice");
transcript.append_message(b"timestamp", &timestamp_bytes);
transcript.append_message(b"action", b"transfer");

// Sign with the transcript
let signature = Signature::sign(&mut transcript, verification_key, private_key);

// Verify with the same transcript construction
let mut verify_transcript = Transcript::new(b"MyProtocol.v1");
verify_transcript.append_message(b"user_id", b"alice");
verify_transcript.append_message(b"timestamp", &timestamp_bytes);
verify_transcript.append_message(b"action", b"transfer");

assert!(signature.verify(&mut verify_transcript, verification_key).is_ok());
```

### Key Generation Best Practices

```rust
use curve25519_dalek::scalar::Scalar;
use zkschnorr::VerificationKey;
use rand::rngs::OsRng;

// Generate cryptographically secure random keys
let private_key = Scalar::random(&mut OsRng);
let nonce = Scalar::random(&mut OsRng);
let verification_key = VerificationKey::from_secret(&private_key, &nonce);

// Store private_key securely and share verification_key publicly
```

### Serialization Example

```rust
use zkschnorr::Signature;

// Sign something
let signature = Signature::sign_message(b"doc", b"content", verification_key, private_key);

// Serialize to bytes
let signature_bytes = signature.to_bytes();

// Store or transmit signature_bytes...

// Deserialize later
let recovered_signature = Signature::from_bytes(&signature_bytes)?;

// Verify recovered signature
assert!(recovered_signature.verify_message(b"doc", b"content", verification_key).is_ok());
```

## Performance Considerations

### Batch Verification Benefits

Batch verification is significantly faster when verifying multiple signatures:

```rust
use zkschnorr::BatchVerifier;
use std::time::Instant;

// For many signatures, use batch verification
let start = Instant::now();
let mut batch = BatchVerifier::with_capacity(rand::thread_rng(), signatures.len());

for (signature, transcript, pubkey) in signatures.iter().zip(transcripts.iter_mut()).zip(pubkeys.iter()) {
    signature.verify_batched(transcript, *pubkey, &mut batch);
}

let result = batch.verify();
println!("Batch verification took: {:?}", start.elapsed());
```

### Memory Management

Pre-allocate batch verifiers when you know the number of signatures:

```rust
// More efficient for known signature count
let batch = BatchVerifier::with_capacity(rand::thread_rng(), expected_signature_count);
```

## Security Considerations

1. **Key Generation**: Always use cryptographically secure randomness for private keys
2. **Nonce Reuse**: Never reuse the randomness parameter `r` across different private keys
3. **Transcript Construction**: Ensure transcripts are constructed identically during sign and verify
4. **Domain Separation**: Use unique transcript labels for different protocols/applications

## Integration Examples

### Web API Integration

```rust
use zkschnorr::{Signature, VerificationKey};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SignedRequest {
    pub message: Vec<u8>,
    pub signature: [u8; 64],
    pub public_key: Vec<u8>,
}

impl SignedRequest {
    pub fn verify(&self) -> Result<(), zkschnorr::ZkSchnorrError> {
        let signature = Signature::from_bytes(&self.signature)?;
        
        // Reconstruct verification key from stored bytes
        let verification_key = VerificationKey::from_compressed(
            CompressedRistretto::from_slice(&self.public_key[..32]).unwrap(),
            CompressedRistretto::from_slice(&self.public_key[32..]).unwrap()
        );
        
        signature.verify_message(b"api_request", &self.message, verification_key)
    }
}
```

### Database Storage

```rust
// Store signatures and keys as byte arrays
CREATE TABLE signatures (
    id SERIAL PRIMARY KEY,
    message BYTEA NOT NULL,
    signature BYTEA NOT NULL, -- 64 bytes
    public_key BYTEA NOT NULL -- 64 bytes  
);
```

## Troubleshooting

### Common Issues

1. **Invalid Signature Error**: 
   - Ensure transcripts are constructed identically for sign and verify
   - Check that the correct verification key is being used
   - Verify message content hasn't been modified

2. **Batch Verification Failure**:
   - One or more signatures in the batch is invalid
   - Use individual verification to identify which signature(s) are failing

3. **Serialization Issues**:
   - Signature bytes must be exactly 64 bytes
   - Verification key bytes must be exactly 64 bytes (32 + 32)

### Debug Tips

```rust
// Enable detailed error information
#[cfg(debug_assertions)]
{
    // Verify signatures individually before batching
    for (sig, transcript, pubkey) in signatures.iter().zip(transcripts.iter()).zip(pubkeys.iter()) {
        if let Err(e) = sig.verify(transcript, *pubkey) {
            eprintln!("Signature verification failed: {:?}", e);
        }
    }
}
```

## Dependencies

- `curve25519-dalek`: Elliptic curve operations
- `merlin`: Transcript-based random oracles
- `rand`: Random number generation
- `serde`: Serialization support
- `thiserror`: Error handling

## License

This library is licensed under the MIT License.
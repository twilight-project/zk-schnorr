# ZkSchnorr API Reference

## Overview

This document provides a complete API reference for the zkschnorr library.

## Core Types

### `SigningKey`

```rust
pub type SigningKey = Scalar;
```

A type alias for `curve25519_dalek::scalar::Scalar` representing a private key in the Ristretto255 group.

### `VerificationKey`

```rust
pub struct VerificationKey {
    pub(crate) g: CompressedRistretto,  // G.r
    pub(crate) h: CompressedRistretto,  // (G.r).sk
}
```

Represents a public verification key consisting of two Ristretto points.

#### Methods

##### `from_secret`
```rust
pub fn from_secret(privkey: &Scalar, r: &Scalar) -> Self
```
Constructs a VerificationKey from a private key and randomness.

**Parameters:**
- `privkey`: The private key scalar
- `r`: Random scalar for key generation

**Returns:** A new `VerificationKey`

##### `new`
```rust
pub fn new(g: CompressedRistretto, h: CompressedRistretto) -> Self
```
Creates a verification key from two compressed Ristretto points.

**Parameters:**
- `g`: First compressed point (G.r)
- `h`: Second compressed point ((G.r).sk)

**Returns:** A new `VerificationKey`

##### `from_compressed`
```rust
pub fn from_compressed(p: CompressedRistretto, q: CompressedRistretto) -> Self
```
Creates a verification key from compressed points (alias for `new`).

##### `into_point`
```rust
pub fn into_point(self) -> (CompressedRistretto, CompressedRistretto)
```
Converts the verification key to a tuple of compressed points.

##### `as_point`
```rust
pub fn as_point(&self) -> (&CompressedRistretto, &CompressedRistretto)
```
Returns references to the compressed points.

##### `to_bytes`
```rust
pub fn to_bytes(&self) -> Vec<u8>
```
Returns the 64-byte representation of the verification key.

### `Signature`

```rust
pub struct Signature {
    pub s: Scalar,                    // Signature scalar
    pub R: CompressedRistretto,       // Nonce commitment
}
```

Represents a Schnorr signature.

#### Signing Methods

##### `sign`
```rust
pub fn sign(
    transcript: &mut Transcript,
    pubkey: VerificationKey,
    privkey: Scalar,
) -> Signature
```
Creates a signature using a Merlin transcript.

**Parameters:**
- `transcript`: Mutable reference to a Merlin transcript
- `pubkey`: The verification key corresponding to the private key
- `privkey`: The private key used for signing

**Returns:** A new `Signature`

##### `sign_message`
```rust
pub fn sign_message(
    label: &'static [u8],
    message: &[u8],
    pubkey: VerificationKey,
    privkey: Scalar,
) -> Signature
```
Signs a message with domain separation label (simplified API).

**Parameters:**
- `label`: Static byte slice for domain separation
- `message`: The message to sign
- `pubkey`: The verification key
- `privkey`: The private key

**Returns:** A new `Signature`

#### Verification Methods

##### `verify`
```rust
pub fn verify(
    &self,
    transcript: &mut Transcript,
    pubkey: VerificationKey,
) -> Result<(), ZkSchnorrError>
```
Verifies a signature using a transcript.

**Parameters:**
- `transcript`: Mutable reference to a Merlin transcript (same state as during signing)
- `pubkey`: The verification key

**Returns:** `Ok(())` if valid, `Err(ZkSchnorrError)` if invalid

##### `verify_message`
```rust
pub fn verify_message(
    &self,
    label: &'static [u8],
    message: &[u8],
    pubkey: VerificationKey,
) -> Result<(), ZkSchnorrError>
```
Verifies a message signature (simplified API).

**Parameters:**
- `label`: Domain separation label (must match signing)
- `message`: The message that was signed
- `pubkey`: The verification key

**Returns:** `Ok(())` if valid, `Err(ZkSchnorrError)` if invalid

##### `verify_batched`
```rust
pub fn verify_batched(
    &self,
    transcript: &mut Transcript,
    pubkey: VerificationKey,
    batch: &mut impl BatchVerification,
)
```
Adds the signature to a batch verifier for efficient batch verification.

**Parameters:**
- `transcript`: Mutable reference to a Merlin transcript
- `pubkey`: The verification key
- `batch`: Mutable reference to a batch verifier

#### Serialization Methods

##### `to_bytes`
```rust
pub fn to_bytes(&self) -> [u8; 64]
```
Encodes the signature as a 64-byte array.

**Returns:** 64-byte array representation

##### `from_bytes`
```rust
pub fn from_bytes(sig: impl AsRefExt) -> Result<Self, ZkSchnorrError>
```
Decodes a signature from bytes.

**Parameters:**
- `sig`: Byte slice or array containing the signature

**Returns:** `Result<Signature, ZkSchnorrError>`

## Batch Verification

### `BatchVerification` (Trait)

```rust
pub trait BatchVerification {
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator<Item = Scalar>,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>;
}
```

Trait for batch verification of signatures.

### `BatchVerifier`

```rust
pub struct BatchVerifier<R: RngCore + CryptoRng> {
    // internal fields
}
```

Concrete implementation for batch signature verification.

#### Methods

##### `new`
```rust
pub fn new(rng: R) -> Self
```
Creates a new batch verifier.

**Parameters:**
- `rng`: Cryptographically secure random number generator

**Returns:** New `BatchVerifier`

##### `with_capacity`
```rust
pub fn with_capacity(rng: R, capacity: usize) -> Self
```
Creates a batch verifier with pre-allocated capacity.

**Parameters:**
- `rng`: Cryptographically secure random number generator
- `capacity`: Expected number of signatures

**Returns:** New `BatchVerifier` with pre-allocated capacity

##### `verify`
```rust
pub fn verify(self) -> Result<(), ZkSchnorrError>
```
Performs batch verification of all added signatures.

**Returns:** `Ok(())` if all signatures are valid, `Err(ZkSchnorrError::InvalidBatch)` if any are invalid

### `SingleVerifier`

```rust
pub struct SingleVerifier {
    // internal fields
}
```

Single signature verifier that implements the batch verification interface.

#### Methods

##### `verify`
```rust
pub fn verify<F>(closure: F) -> Result<(), ZkSchnorrError>
where
    F: FnOnce(&mut Self),
```
Verifies a single signature using the batch verification interface.

## Error Types

### `ZkSchnorrError`

```rust
pub enum ZkSchnorrError {
    InvalidSignature,
    InvalidBatch,
}
```

Error types for signature operations.

#### Variants

- **`InvalidSignature`**: Signature verification failed
- **`InvalidBatch`**: Batch signature verification failed

## Transcript Protocol

### `TranscriptProtocol` (Trait)

```rust
pub trait TranscriptProtocol {
    fn zkschnorr_domain_sep(&mut self);
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}
```

Extension trait for Merlin transcripts with Schnorr-specific operations.

#### Methods

##### `zkschnorr_domain_sep`
```rust
fn zkschnorr_domain_sep(&mut self)
```
Commits domain separator for the signing protocol.

##### `append_scalar`
```rust
fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar)
```
Commits a scalar to the transcript.

##### `append_point`
```rust
fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto)
```
Commits a point to the transcript.

##### `challenge_scalar`
```rust
fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar
```
Generates a challenge scalar from the transcript.

## Usage Patterns

### Basic Message Signing
```rust
use zkschnorr::{VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;

let private_key = Scalar::random(&mut rand::thread_rng());
let nonce = Scalar::random(&mut rand::thread_rng());
let verification_key = VerificationKey::from_secret(&private_key, &nonce);

let signature = Signature::sign_message(b"label", b"message", verification_key, private_key);
assert!(signature.verify_message(b"label", b"message", verification_key).is_ok());
```

### Batch Verification
```rust
use zkschnorr::BatchVerifier;

let mut batch = BatchVerifier::new(rand::thread_rng());
// Add signatures to batch using verify_batched()
let result = batch.verify();
```

### Transcript-based Signing
```rust
use merlin::Transcript;

let mut transcript = Transcript::new(b"MyProtocol");
transcript.append_message(b"context", b"some context");
let signature = Signature::sign(&mut transcript, verification_key, private_key);
```

## Thread Safety

- `VerificationKey`: `Send + Sync` (can be shared between threads)
- `Signature`: `Send + Sync` (can be shared between threads)  
- `BatchVerifier`: `Send` (can be moved between threads, not `Sync`)

## Memory Usage

- `VerificationKey`: 64 bytes
- `Signature`: 64 bytes
- `BatchVerifier`: Variable (depends on number of signatures added)

## Performance Notes

- Individual verification: ~100-200 μs per signature
- Batch verification: ~20-50 μs per signature (with sufficient batch size)
- Optimal batch size: 100+ signatures for maximum speedup
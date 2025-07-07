#![deny(missing_docs)]
#![allow(non_snake_case)]
//! # ZkSchnorr: Multipoint Schnorr Signatures on Ristretto
//!
//! This library provides a pure-Rust implementation of a multipoint Schnorr signature protocol
//! using [Ristretto](https://ristretto.group) and [Merlin transcripts](https://merlin.cool).
//!
//! ## Features
//!
//! * **Simple message-based API** - Sign and verify messages with minimal setup
//! * **Flexible transcript-based API** - Full control over signature contexts using Merlin transcripts
//! * **Single signature verification** - Verify individual signatures efficiently
//! * **Batch signature verification** - Verify multiple signatures in a single operation for better performance
//! * **Deterministic serialization** - Reliable encoding/decoding of signatures and keys
//!
//! ## Quick Start
//!
//! ```rust
//! use zkschnorr::{Signature, VerificationKey};
//! use curve25519_dalek::scalar::Scalar;
//! use rand::thread_rng;
//!
//! // Generate keys
//! let signing_key = Scalar::random(&mut thread_rng());
//! let randomness = Scalar::random(&mut thread_rng());
//! let verification_key = VerificationKey::from_secret(&signing_key, &randomness);
//!
//! // Sign a message
//! let message = b"Hello, zkSchnorr!";
//! let signature = Signature::sign_message(b"example", message, verification_key, signing_key);
//!
//! // Verify the signature
//! assert!(signature.verify_message(b"example", message, verification_key).is_ok());
//! ```
//!
//! ## Batch Verification
//!
//! For better performance when verifying multiple signatures:
//!
//! ```rust
//! use zkschnorr::{Signature, VerificationKey, BatchVerifier};
//! use curve25519_dalek::scalar::Scalar;
//! use rand::thread_rng;
//!
//! let mut batch = BatchVerifier::new(thread_rng());
//!
//! // Add multiple signatures to the batch
//! for i in 0..10 {
//!     let signing_key = Scalar::random(&mut thread_rng());
//!     let randomness = Scalar::random(&mut thread_rng());
//!     let verification_key = VerificationKey::from_secret(&signing_key, &randomness);
//!     
//!     let message = format!("Message {}", i);
//!     let signature = Signature::sign_message(b"batch", message.as_bytes(), verification_key, signing_key);
//!     
//!     // Add to batch (you'd normally recreate the transcript properly)
//!     // This is a simplified example
//! }
//!
//! // Verify all signatures in the batch
//! assert!(batch.verify().is_ok());
//! ```
//!
//! ## Advanced Usage with Transcripts
//!
//! For more control over the signature context:
//!
//! ```rust
//! use merlin::Transcript;
//! use zkschnorr::{Signature, TranscriptProtocol};
//! # use zkschnorr::VerificationKey;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::thread_rng;
//! # let signing_key = Scalar::random(&mut thread_rng());
//! # let randomness = Scalar::random(&mut thread_rng());
//! # let verification_key = VerificationKey::from_secret(&signing_key, &randomness);
//!
//! let mut transcript = Transcript::new(b"my-protocol");
//! transcript.append_message(b"context", b"important context data");
//! transcript.append_message(b"message", b"the message to sign");
//!
//! let signature = Signature::sign(&mut transcript, verification_key, signing_key);
//!
//! // For verification, recreate the same transcript
//! let mut verify_transcript = Transcript::new(b"my-protocol");
//! verify_transcript.append_message(b"context", b"important context data");
//! verify_transcript.append_message(b"message", b"the message to sign");
//!
//! assert!(signature.verify(&mut verify_transcript, verification_key).is_ok());
//! ```
//!
//! ## Security
//!
//! This implementation provides:
//! - Protection against signature malleability
//! - Secure random nonce generation
//! - Proper domain separation using Merlin transcripts
//! - Batch verification with protection against cancellation attacks

mod batch;
mod errors;
mod key;
mod serialization;
mod signature;
mod transcript;

#[cfg(test)]
mod tests;

pub use self::batch::{BatchVerification, BatchVerifier, SingleVerifier};
pub use self::errors::ZkSchnorrError;
pub use self::key::{SigningKey, VerificationKey};
pub use self::signature::Signature;
pub use self::transcript::TranscriptProtocol;


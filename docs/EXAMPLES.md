# ZkSchnorr Examples

This document provides practical examples for using the zkschnorr library in various scenarios.

## Table of Contents

1. [Basic Examples](#basic-examples)
2. [Advanced Usage](#advanced-usage)
3. [Integration Patterns](#integration-patterns)
4. [Performance Examples](#performance-examples)

## Basic Examples

### Example 1: Simple Message Signing

```rust
use zkschnorr::{VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;

fn simple_signing_example() -> Result<(), zkschnorr::ZkSchnorrError> {
    // Generate a private key (in practice, use secure random generation)
    let private_key = Scalar::from(12345u64);
    let nonce = Scalar::from(67890u64);
    
    // Create verification key
    let verification_key = VerificationKey::from_secret(&private_key, &nonce);
    
    // Message to sign
    let message = b"Hello, blockchain!";
    
    // Sign the message
    let signature = Signature::sign_message(
        b"greeting",  // Label for domain separation
        message,
        verification_key,
        private_key
    );
    
    // Verify the signature
    signature.verify_message(b"greeting", message, verification_key)?;
    
    println!("Message successfully signed and verified!");
    Ok(())
}
```

### Example 2: Document Authentication

```rust
use zkschnorr::{VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};

fn document_authentication() -> Result<(), zkschnorr::ZkSchnorrError> {
    // Generate keys
    let private_key = Scalar::random(&mut rand::thread_rng());
    let nonce = Scalar::random(&mut rand::thread_rng());
    let verification_key = VerificationKey::from_secret(&private_key, &nonce);
    
    // Document content
    let document = b"Important legal document content...";
    
    // Hash the document
    let mut hasher = Sha256::new();
    hasher.update(document);
    let document_hash = hasher.finalize();
    
    // Sign the hash
    let signature = Signature::sign_message(
        b"document_hash",
        &document_hash,
        verification_key,
        private_key
    );
    
    // Later: verify the document
    let mut verify_hasher = Sha256::new();
    verify_hasher.update(document);
    let verify_hash = verify_hasher.finalize();
    
    signature.verify_message(b"document_hash", &verify_hash, verification_key)?;
    
    println!("Document authenticity verified!");
    Ok(())
}
```

### Example 3: User Authentication

```rust
use zkschnorr::{VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;
use std::time::{SystemTime, UNIX_EPOCH};

struct UserAuth {
    verification_key: VerificationKey,
}

impl UserAuth {
    fn new(private_key: Scalar) -> Self {
        let nonce = Scalar::random(&mut rand::thread_rng());
        let verification_key = VerificationKey::from_secret(&private_key, &nonce);
        Self { verification_key }
    }
    
    fn create_auth_challenge(&self, user_id: &str, private_key: Scalar) -> Result<(Vec<u8>, Signature), Box<dyn std::error::Error>> {
        // Create timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        // Create challenge message
        let challenge = format!("auth:{}:{}", user_id, timestamp);
        let challenge_bytes = challenge.as_bytes();
        
        // Sign the challenge
        let signature = Signature::sign_message(
            b"user_auth",
            challenge_bytes,
            self.verification_key,
            private_key
        );
        
        Ok((challenge_bytes.to_vec(), signature))
    }
    
    fn verify_auth(&self, challenge: &[u8], signature: &Signature) -> Result<(), zkschnorr::ZkSchnorrError> {
        signature.verify_message(b"user_auth", challenge, self.verification_key)
    }
}

fn user_authentication_example() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = Scalar::random(&mut rand::thread_rng());
    let auth = UserAuth::new(private_key);
    
    // User tries to authenticate
    let (challenge, signature) = auth.create_auth_challenge("alice", private_key)?;
    
    // Server verifies authentication
    auth.verify_auth(&challenge, &signature)?;
    
    println!("User authentication successful!");
    Ok(())
}
```

## Advanced Usage

### Example 4: Multi-Context Signing with Transcripts

```rust
use zkschnorr::{VerificationKey, Signature, TranscriptProtocol};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

fn multi_context_signing() -> Result<(), zkschnorr::ZkSchnorrError> {
    let private_key = Scalar::random(&mut rand::thread_rng());
    let nonce = Scalar::random(&mut rand::thread_rng());
    let verification_key = VerificationKey::from_secret(&private_key, &nonce);
    
    // Create a complex context
    let mut signing_transcript = Transcript::new(b"MultiTransfer.v1");
    signing_transcript.append_message(b"sender", b"alice");
    signing_transcript.append_message(b"recipient", b"bob");
    signing_transcript.append_message(b"amount", &1000u64.to_le_bytes());
    signing_transcript.append_message(b"currency", b"USD");
    signing_transcript.append_message(b"memo", b"Payment for services");
    
    // Sign with the transcript
    let signature = Signature::sign(&mut signing_transcript, verification_key, private_key);
    
    // Verify with matching transcript
    let mut verify_transcript = Transcript::new(b"MultiTransfer.v1");
    verify_transcript.append_message(b"sender", b"alice");
    verify_transcript.append_message(b"recipient", b"bob");
    verify_transcript.append_message(b"amount", &1000u64.to_le_bytes());
    verify_transcript.append_message(b"currency", b"USD");
    verify_transcript.append_message(b"memo", b"Payment for services");
    
    signature.verify(&mut verify_transcript, verification_key)?;
    
    println!("Multi-context signature verified!");
    Ok(())
}
```

### Example 5: Batch Verification for Performance

```rust
use zkschnorr::{VerificationKey, Signature, BatchVerifier};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::time::Instant;

fn batch_verification_example() -> Result<(), zkschnorr::ZkSchnorrError> {
    const NUM_SIGNATURES: usize = 100;
    
    // Generate multiple signatures
    let mut signatures = Vec::new();
    let mut verification_keys = Vec::new();
    let mut transcripts = Vec::new();
    
    for i in 0..NUM_SIGNATURES {
        let private_key = Scalar::random(&mut rand::thread_rng());
        let nonce = Scalar::random(&mut rand::thread_rng());
        let verification_key = VerificationKey::from_secret(&private_key, &nonce);
        
        let message = format!("Message {}", i);
        let signature = Signature::sign_message(
            b"batch_test",
            message.as_bytes(),
            verification_key,
            private_key
        );
        
        signatures.push(signature);
        verification_keys.push(verification_key);
                 let mut transcript = Transcript::new(b"Elgamal.sign_message");
         transcript.append_message(b"batch_test", message.as_bytes());
         transcripts.push(transcript);
    }
    
    // Individual verification timing
    let start = Instant::now();
    for (sig, transcript, vk) in signatures.iter().zip(transcripts.iter_mut()).zip(verification_keys.iter()) {
        sig.verify(transcript, *vk)?;
    }
    let individual_time = start.elapsed();
    
    // Batch verification timing
    let start = Instant::now();
    let mut batch = BatchVerifier::with_capacity(rand::thread_rng(), NUM_SIGNATURES);
    
    for (sig, transcript, vk) in signatures.iter().zip(transcripts.iter_mut()).zip(verification_keys.iter()) {
        sig.verify_batched(transcript, *vk, &mut batch);
    }
    
    batch.verify()?;
    let batch_time = start.elapsed();
    
    println!("Individual verification: {:?}", individual_time);
    println!("Batch verification: {:?}", batch_time);
    println!("Speedup: {:.2}x", individual_time.as_secs_f64() / batch_time.as_secs_f64());
    
    Ok(())
}
```

## Integration Patterns

### Example 6: JSON API Integration

```rust
use zkschnorr::{VerificationKey, Signature, ZkSchnorrError};
use curve25519_dalek::{scalar::Scalar, ristretto::CompressedRistretto};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    pub content: String,
    pub signature: String,  // hex-encoded
    pub public_key: String, // hex-encoded
}

impl SignedMessage {
    pub fn new(content: String, private_key: Scalar, verification_key: VerificationKey) -> Self {
        let signature = Signature::sign_message(
            b"api_message",
            content.as_bytes(),
            verification_key,
            private_key
        );
        
        Self {
            content,
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(verification_key.to_bytes()),
        }
    }
    
    pub fn verify(&self) -> Result<(), ZkSchnorrError> {
        // Decode signature
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| ZkSchnorrError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes)?;
        
        // Decode public key
        let pubkey_bytes = hex::decode(&self.public_key)
            .map_err(|_| ZkSchnorrError::InvalidSignature)?;
        
        if pubkey_bytes.len() != 64 {
            return Err(ZkSchnorrError::InvalidSignature);
        }
        
        let g = CompressedRistretto::from_slice(&pubkey_bytes[..32])
            .map_err(|_| ZkSchnorrError::InvalidSignature)?;
        let h = CompressedRistretto::from_slice(&pubkey_bytes[32..])
            .map_err(|_| ZkSchnorrError::InvalidSignature)?;
        
        let verification_key = VerificationKey::new(g, h);
        
        // Verify signature
        signature.verify_message(b"api_message", self.content.as_bytes(), verification_key)
    }
}

fn api_integration_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create signed message
    let private_key = Scalar::random(&mut rand::thread_rng());
    let nonce = Scalar::random(&mut rand::thread_rng());
    let verification_key = VerificationKey::from_secret(&private_key, &nonce);
    
    let signed_msg = SignedMessage::new(
        "Hello from the API!".to_string(),
        private_key,
        verification_key
    );
    
    // Serialize to JSON
    let json = serde_json::to_string(&signed_msg)?;
    println!("Signed message JSON: {}", json);
    
    // Deserialize and verify
    let deserialized: SignedMessage = serde_json::from_str(&json)?;
    deserialized.verify()?;
    
    println!("API message verified successfully!");
    Ok(())
}
```

### Example 7: Database Integration

```rust
use zkschnorr::{VerificationKey, Signature};
use curve25519_dalek::scalar::Scalar;

// Simulate database record
#[derive(Debug)]
struct SignedRecord {
    id: u32,
    content: Vec<u8>,
    signature: [u8; 64],
    public_key: [u8; 64],
}

impl SignedRecord {
    fn new(id: u32, content: Vec<u8>, private_key: Scalar) -> Self {
        let nonce = Scalar::random(&mut rand::thread_rng());
        let verification_key = VerificationKey::from_secret(&private_key, &nonce);
        
        let signature = Signature::sign_message(
            b"db_record",
            &content,
            verification_key,
            private_key
        );
        
        Self {
            id,
            content,
            signature: signature.to_bytes(),
            public_key: verification_key.to_bytes().try_into().unwrap(),
        }
    }
    
    fn verify(&self) -> Result<(), zkschnorr::ZkSchnorrError> {
        let signature = Signature::from_bytes(&self.signature)?;
        
        let g = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&self.public_key[..32])
            .map_err(|_| zkschnorr::ZkSchnorrError::InvalidSignature)?;
        let h = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&self.public_key[32..])
            .map_err(|_| zkschnorr::ZkSchnorrError::InvalidSignature)?;
        
        let verification_key = VerificationKey::new(g, h);
        
        signature.verify_message(b"db_record", &self.content, verification_key)
    }
}

fn database_integration_example() -> Result<(), zkschnorr::ZkSchnorrError> {
    let private_key = Scalar::random(&mut rand::thread_rng());
    
    // Create signed record
    let record = SignedRecord::new(
        1,
        b"Important database record".to_vec(),
        private_key
    );
    
    // Simulate storing to database...
    println!("Stored record: {:?}", record.id);
    
    // Simulate loading from database and verifying...
    record.verify()?;
    
    println!("Database record verified!");
    Ok(())
}
```

## Performance Examples

### Example 8: Benchmark Different Verification Methods

```rust
use zkschnorr::{VerificationKey, Signature, BatchVerifier};
use curve25519_dalek::scalar::Scalar;
use std::time::Instant;

fn benchmark_verification_methods() -> Result<(), zkschnorr::ZkSchnorrError> {
    const SIGNATURE_COUNTS: &[usize] = &[10, 50, 100, 500, 1000];
    
    for &count in SIGNATURE_COUNTS {
        println!("\nBenchmarking {} signatures:", count);
        
        // Generate test data
        let mut test_data = Vec::new();
        for i in 0..count {
            let private_key = Scalar::random(&mut rand::thread_rng());
            let nonce = Scalar::random(&mut rand::thread_rng());
            let verification_key = VerificationKey::from_secret(&private_key, &nonce);
            
            let message = format!("Test message {}", i);
            let signature = Signature::sign_message(
                b"benchmark",
                message.as_bytes(),
                verification_key,
                private_key
            );
            
            test_data.push((signature, message, verification_key));
        }
        
        // Individual verification
        let start = Instant::now();
        for (signature, message, verification_key) in &test_data {
            signature.verify_message(b"benchmark", message.as_bytes(), *verification_key)?;
        }
        let individual_time = start.elapsed();
        
        // Batch verification
        let start = Instant::now();
        let mut batch = BatchVerifier::with_capacity(rand::thread_rng(), count);
        
        for (signature, message, verification_key) in &test_data {
                         let mut transcript = Transcript::new(b"Elgamal.sign_message");
             transcript.append_message(b"benchmark", message.as_bytes());
            signature.verify_batched(&mut transcript, *verification_key, &mut batch);
        }
        
        batch.verify()?;
        let batch_time = start.elapsed();
        
        println!("  Individual: {:?} ({:.2} μs/sig)", 
                individual_time, 
                individual_time.as_micros() as f64 / count as f64);
        println!("  Batch: {:?} ({:.2} μs/sig)", 
                batch_time, 
                batch_time.as_micros() as f64 / count as f64);
        println!("  Speedup: {:.2}x", 
                individual_time.as_secs_f64() / batch_time.as_secs_f64());
    }
    
    Ok(())
}
```

### Example 9: Memory-Efficient Batch Processing

```rust
use zkschnorr::{VerificationKey, Signature, BatchVerifier};
use curve25519_dalek::scalar::Scalar;

fn memory_efficient_batch_processing() -> Result<(), zkschnorr::ZkSchnorrError> {
    const TOTAL_SIGNATURES: usize = 10000;
    const BATCH_SIZE: usize = 100;
    
    println!("Processing {} signatures in batches of {}", TOTAL_SIGNATURES, BATCH_SIZE);
    
    // Simulate processing large numbers of signatures in batches
    for batch_num in 0..(TOTAL_SIGNATURES / BATCH_SIZE) {
        let mut batch = BatchVerifier::with_capacity(rand::thread_rng(), BATCH_SIZE);
        
        // Process one batch
        for i in 0..BATCH_SIZE {
            let signature_id = batch_num * BATCH_SIZE + i;
            
            // Generate test signature (in practice, load from storage)
            let private_key = Scalar::from((signature_id as u64 + 1) * 12345);
            let nonce = Scalar::from((signature_id as u64 + 1) * 67890);
            let verification_key = VerificationKey::from_secret(&private_key, &nonce);
            
            let message = format!("Signature {}", signature_id);
            let signature = Signature::sign_message(
                b"batch_processing",
                message.as_bytes(),
                verification_key,
                private_key
            );
            
            // Add to batch
                         let mut transcript = Transcript::new(b"Elgamal.sign_message");
             transcript.append_message(b"batch_processing", message.as_bytes());
            signature.verify_batched(&mut transcript, verification_key, &mut batch);
        }
        
        // Verify the batch
        batch.verify()?;
        
        if batch_num % 10 == 0 {
            println!("Processed batch {} ({} signatures so far)", 
                    batch_num, 
                    (batch_num + 1) * BATCH_SIZE);
        }
    }
    
    println!("All {} signatures verified successfully!", TOTAL_SIGNATURES);
    Ok(())
}
```

## Running the Examples

To run these examples, create a new Rust project and add the examples to your `main.rs`:

```rust
// Add all the example functions above, then:

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic Examples ===");
    simple_signing_example()?;
    document_authentication()?;
    user_authentication_example()?;
    
    println!("\n=== Advanced Examples ===");
    multi_context_signing()?;
    batch_verification_example()?;
    
    println!("\n=== Integration Examples ===");
    api_integration_example()?;
    database_integration_example()?;
    
    println!("\n=== Performance Examples ===");
    benchmark_verification_methods()?;
    memory_efficient_batch_processing()?;
    
    Ok(())
}
```

Make sure your `Cargo.toml` includes all necessary dependencies:

```toml
[dependencies]
zkschnorr = { path = "path/to/zkschnorr" }
curve25519-dalek = "3"
merlin = "2"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"
sha2 = "0.10"
```
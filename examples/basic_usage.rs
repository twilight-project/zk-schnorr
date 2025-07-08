//! Basic usage example for zkSchnorr
//!
//! This example demonstrates how to use the zkSchnorr library for:
//! - Key generation
//! - Message signing and verification
//! - Batch verification
//! - Serialization and deserialization

use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use zkschnorr::{BatchVerifier, Signature, VerificationKey, ZkSchnorrError};

fn main() -> Result<(), ZkSchnorrError> {
    println!("ZkSchnorr Example: Basic Usage");
    println!("==============================");

    // 1. Key Generation
    println!("\n1. Generating keys...");
    let signing_key = Scalar::random(&mut thread_rng());
    let randomness = Scalar::random(&mut thread_rng());
    let verification_key = VerificationKey::from_secret(&signing_key, &randomness);
    println!("✓ Keys generated successfully");

    // 2. Simple message signing
    println!("\n2. Signing a message...");
    let message = b"Hello, zkSchnorr! This is a test message.";
    let signature = Signature::sign_message(b"example", message, verification_key, signing_key);
    println!("✓ Message signed successfully");

    // 3. Signature verification
    println!("\n3. Verifying signature...");
    match signature.verify_message(b"example", message, verification_key) {
        Ok(()) => println!("✓ Signature verification successful"),
        Err(e) => {
            println!("✗ Signature verification failed: {e:?}");
            return Err(e);
        }
    }

    // 4. Serialization round-trip
    println!("\n4. Testing serialization...");
    let sig_bytes = signature.to_bytes();
    let key_bytes = verification_key.to_bytes();

    let recovered_sig = Signature::from_bytes(sig_bytes)?;
    let recovered_key = VerificationKey::from_bytes(&key_bytes)?;

    // Verify the recovered signature
    match recovered_sig.verify_message(b"example", message, recovered_key) {
        Ok(()) => println!("✓ Serialization round-trip successful"),
        Err(e) => {
            println!("✗ Serialization round-trip failed: {e:?}");
            return Err(e);
        }
    }

    // 5. Batch verification
    println!("\n5. Testing batch verification...");
    let mut batch = BatchVerifier::new(thread_rng());
    let batch_size = 5;

    println!("   Creating {batch_size} signatures for batch verification...");
    let mut signatures = Vec::new();
    let mut keys = Vec::new();
    let mut messages = Vec::new();

    for i in 0..batch_size {
        let sk = Scalar::random(&mut thread_rng());
        let r = Scalar::random(&mut thread_rng());
        let vk = VerificationKey::from_secret(&sk, &r);

        let msg = format!("Batch message {i}");
        let sig = Signature::sign_message(b"batch", msg.as_bytes(), vk, sk);

        signatures.push(sig);
        keys.push(vk);
        messages.push(msg);
    }

    // Add all signatures to the batch
    for (i, ((sig, key), msg)) in signatures
        .iter()
        .zip(keys.iter())
        .zip(messages.iter())
        .enumerate()
    {
        let mut transcript = merlin::Transcript::new(b"zkschnorr.sign_message");
        transcript.append_message(b"batch", msg.as_bytes());

        sig.verify_batched(&mut transcript, *key, &mut batch);
        println!("   Added signature {} to batch", i + 1);
    }

    // Verify the entire batch
    match batch.verify() {
        Ok(()) => println!("✓ Batch verification successful"),
        Err(e) => {
            println!("✗ Batch verification failed: {e:?}");
            return Err(e);
        }
    }

    // 6. Performance comparison
    println!("\n6. Performance comparison...");
    let start = std::time::Instant::now();

    // Individual verification
    for ((sig, key), msg) in signatures.iter().zip(keys.iter()).zip(messages.iter()) {
        sig.verify_message(b"batch", msg.as_bytes(), *key)?;
    }
    let individual_time = start.elapsed();

    // Batch verification
    let start = std::time::Instant::now();
    let mut batch = BatchVerifier::new(thread_rng());
    for ((sig, key), msg) in signatures.iter().zip(keys.iter()).zip(messages.iter()) {
        let mut transcript = merlin::Transcript::new(b"zkschnorr.sign_message");
        transcript.append_message(b"batch", msg.as_bytes());
        sig.verify_batched(&mut transcript, *key, &mut batch);
    }
    batch.verify()?;
    let batch_time = start.elapsed();

    println!("   Individual verification: {individual_time:?}");
    println!("   Batch verification:      {batch_time:?}");
    println!(
        "   Speedup: {:.2}x",
        individual_time.as_secs_f64() / batch_time.as_secs_f64()
    );

    println!("\n All tests passed! The zkSchnorr library is working correctly.");
    Ok(())
}

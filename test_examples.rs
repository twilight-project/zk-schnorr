use zkschnorr::{VerificationKey, Signature, BatchVerifier, ZkSchnorrError};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use sha2::{Sha256, Digest};

fn test_simple_signing_example() -> Result<(), ZkSchnorrError> {
    println!("Testing simple signing example...");
    
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
    
    println!("✓ Simple signing example works!");
    Ok(())
}

fn test_document_authentication() -> Result<(), ZkSchnorrError> {
    println!("Testing document authentication...");
    
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
    
    println!("✓ Document authentication example works!");
    Ok(())
}

fn test_multi_context_signing() -> Result<(), ZkSchnorrError> {
    println!("Testing multi-context signing...");
    
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
    
    println!("✓ Multi-context signing example works!");
    Ok(())
}

fn test_batch_verification_simple() -> Result<(), ZkSchnorrError> {
    println!("Testing simple batch verification...");
    
    const NUM_SIGNATURES: usize = 5;
    
    // Generate multiple signatures
    let mut signatures = Vec::new();
    let mut verification_keys = Vec::new();
    let mut messages = Vec::new();
    
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
        messages.push(message);
    }
    
    // Test individual verification first
    for ((sig, msg), vk) in signatures.iter().zip(messages.iter()).zip(verification_keys.iter()) {
        sig.verify_message(b"batch_test", msg.as_bytes(), *vk)?;
    }
    
    // Now test batch verification
    let mut batch = BatchVerifier::new(rand::thread_rng());
    
    for ((sig, msg), vk) in signatures.iter().zip(messages.iter()).zip(verification_keys.iter()) {
        let mut transcript = Transcript::new(b"Elgamal.sign_message");
        transcript.append_message(b"batch_test", msg.as_bytes());
        sig.verify_batched(&mut transcript, *vk, &mut batch);
    }
    
    batch.verify()?;
    
    println!("✓ Batch verification example works!");
    Ok(())
}

fn test_serialization() -> Result<(), ZkSchnorrError> {
    println!("Testing serialization...");
    
    let private_key = Scalar::random(&mut rand::thread_rng());
    let nonce = Scalar::random(&mut rand::thread_rng());
    let verification_key = VerificationKey::from_secret(&private_key, &nonce);
    
    // Sign something
    let signature = Signature::sign_message(b"doc", b"content", verification_key, private_key);
    
    // Serialize to bytes
    let signature_bytes = signature.to_bytes();
    let pubkey_bytes = verification_key.to_bytes();
    
    // Deserialize later
    let recovered_signature = Signature::from_bytes(signature_bytes)?;
    
    // Reconstruct verification key - need to convert Vec to [u8; 32] arrays
    let mut g_bytes = [0u8; 32];
    let mut h_bytes = [0u8; 32];
    g_bytes.copy_from_slice(&pubkey_bytes[..32]);
    h_bytes.copy_from_slice(&pubkey_bytes[32..]);
    
    let g = curve25519_dalek::ristretto::CompressedRistretto(g_bytes);
    let h = curve25519_dalek::ristretto::CompressedRistretto(h_bytes);
    let recovered_verification_key = VerificationKey::new(g, h);
    
    // Verify recovered signature
    recovered_signature.verify_message(b"doc", b"content", recovered_verification_key)?;
    
    println!("✓ Serialization example works!");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing zkschnorr documentation examples...\n");
    
    test_simple_signing_example()?;
    test_document_authentication()?;
    test_multi_context_signing()?;
    test_batch_verification_simple()?;
    test_serialization()?;
    
    println!("\n🎉 All examples passed!");
    Ok(())
}
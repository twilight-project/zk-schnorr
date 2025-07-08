use crate::{
    batch::BatchVerifier, errors::ZkSchnorrError, key::VerificationKey, signature::Signature,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[test]
fn sign_and_verify_single() {
    let privkey = Scalar::from(1u64);
    let r = Scalar::from(10987u64);

    let X = VerificationKey::from_secret(&privkey, &r);

    let sig = Signature::sign(&mut Transcript::new(b"example transcript"), X, privkey);

    assert!(sig
        .verify(&mut Transcript::new(b"example transcript"), X)
        .is_ok());

    let priv_bad = Scalar::from(2u64);

    let X_bad = VerificationKey::from_secret(&priv_bad, &r);
    assert!(sig
        .verify(&mut Transcript::new(b"example transcript"), X_bad)
        .is_err());
    assert!(sig
        .verify(&mut Transcript::new(b"invalid transcript"), X)
        .is_err());
}

#[test]
fn sign_and_verify_single_msg() {
    let privkey = Scalar::from(1u64);
    let r = Scalar::from(10987u64);

    let X = VerificationKey::from_secret(&privkey, &r);

    let sig = Signature::sign_message(
        ("transcript label").as_bytes(),
        ("account").as_bytes(),
        X,
        privkey,
    );

    assert!(sig
        .verify_message(("transcript label").as_bytes(), ("account").as_bytes(), X)
        .is_ok());

    let priv_bad = Scalar::from(2u64);

    let X_bad = VerificationKey::from_secret(&priv_bad, &r);
    assert!(sig
        .verify_message(
            ("transcript label").as_bytes(),
            ("account").as_bytes(),
            X_bad
        )
        .is_err());
    assert!(sig
        .verify_message(
            ("transcript label").as_bytes(),
            ("Invalid Message").as_bytes(),
            X
        )
        .is_err());
}

#[test]
fn empty_batch() {
    let batch = BatchVerifier::new(rand::thread_rng());
    assert_eq!(batch.verify(), Ok(()));
}

#[test]
fn sign_and_verify_batch() {
    let prv1 = Scalar::from(1u64);
    let prv2 = Scalar::from(2u64);
    let prv3 = Scalar::from(3u64);

    let pub1 = VerificationKey::from_secret(&prv1, &Scalar::random(&mut rand::thread_rng()));
    let pub2 = VerificationKey::from_secret(&prv2, &Scalar::random(&mut rand::thread_rng()));
    let pub3 = VerificationKey::from_secret(&prv3, &Scalar::random(&mut rand::thread_rng()));

    let sig1 = Signature::sign(&mut Transcript::new(b"example transcript 1"), pub1, prv1);
    let sig2 = Signature::sign(&mut Transcript::new(b"example transcript 2"), pub2, prv2);
    let sig3 = Signature::sign(&mut Transcript::new(b"example transcript 3"), pub3, prv3);

    assert!(sig1
        .verify(&mut Transcript::new(b"example transcript 1"), pub1)
        .is_ok());
    assert!(sig2
        .verify(&mut Transcript::new(b"example transcript 2"), pub2)
        .is_ok());
    assert!(sig3
        .verify(&mut Transcript::new(b"example transcript 3"), pub3)
        .is_ok());

    let mut batch = BatchVerifier::new(rand::thread_rng());

    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 1"),
        pub1,
        &mut batch,
    );
    sig2.verify_batched(
        &mut Transcript::new(b"example transcript 2"),
        pub2,
        &mut batch,
    );
    sig3.verify_batched(
        &mut Transcript::new(b"example transcript 3"),
        pub3,
        &mut batch,
    );

    assert!(batch.verify().is_ok());

    // Invalid batch (wrong message):

    let mut bad_batch = BatchVerifier::new(rand::thread_rng());

    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 1"),
        pub1,
        &mut bad_batch,
    );
    sig2.verify_batched(&mut Transcript::new(b"wrong message"), pub2, &mut bad_batch);
    sig3.verify_batched(
        &mut Transcript::new(b"example transcript 3"),
        pub3,
        &mut bad_batch,
    );

    assert_eq!(bad_batch.verify(), Err(ZkSchnorrError::InvalidBatch));
}

#[test]
fn signature_serialization() {
    let privkey = Scalar::from(12345u64);
    let r = Scalar::from(67890u64);
    let pubkey = VerificationKey::from_secret(&privkey, &r);

    let sig = Signature::sign_message(b"test", b"hello world", pubkey, privkey);

    // Test serialization round trip
    let sig_bytes = sig.to_bytes();
    let sig_decoded = Signature::from_bytes(sig_bytes).unwrap();

    assert_eq!(sig, sig_decoded);

    // Test verification of decoded signature
    assert!(sig_decoded
        .verify_message(b"test", b"hello world", pubkey)
        .is_ok());

    // Test invalid signature bytes - flip a bit should make verification fail
    let mut bad_bytes = sig_bytes;
    bad_bytes[0] ^= 1; // flip a bit
    if let Ok(bad_sig) = Signature::from_bytes(bad_bytes) {
        // Deserialization might succeed but verification should fail
        assert!(bad_sig
            .verify_message(b"test", b"hello world", pubkey)
            .is_err());
    }

    // Test wrong length
    assert!(Signature::from_bytes(&[0u8; 63][..]).is_err());
    assert!(Signature::from_bytes(&[0u8; 65][..]).is_err());
}

#[test]
fn verification_key_serialization() {
    let privkey = Scalar::from(11111u64);
    let r = Scalar::from(22222u64);
    let pubkey = VerificationKey::from_secret(&privkey, &r);

    // Test serialization round trip
    let pubkey_bytes = pubkey.to_bytes();
    let pubkey_decoded = VerificationKey::from_bytes(&pubkey_bytes).unwrap();

    assert_eq!(pubkey, pubkey_decoded);

    // Test fixed array serialization
    let pubkey_array = pubkey.to_bytes_array();
    let pubkey_from_array = VerificationKey::from_bytes(&pubkey_array).unwrap();
    assert_eq!(pubkey, pubkey_from_array);

    // Test invalid key bytes
    assert!(VerificationKey::from_bytes(&[0u8; 63]).is_err());
    assert!(VerificationKey::from_bytes(&[0u8; 65]).is_err());
}

#[test]
fn signature_non_deterministic() {
    let privkey = Scalar::from(42u64);
    let r = Scalar::from(123u64);
    let pubkey = VerificationKey::from_secret(&privkey, &r);

    // Different signatures for same input (due to randomness) but both should verify
    let sig1 = Signature::sign(&mut Transcript::new(b"test"), pubkey, privkey);
    let sig2 = Signature::sign(&mut Transcript::new(b"test"), pubkey, privkey);

    // Signatures should be different (non-deterministic)
    assert_ne!(sig1, sig2);

    // But both should verify correctly
    assert!(sig1.verify(&mut Transcript::new(b"test"), pubkey).is_ok());
    assert!(sig2.verify(&mut Transcript::new(b"test"), pubkey).is_ok());
}

#[test]
fn large_batch_verification() {
    let batch_size = 10;
    let mut batch = BatchVerifier::new(rand::thread_rng());

    for i in 0..batch_size {
        let privkey = Scalar::from(i as u64 + 1);
        let r = Scalar::random(&mut rand::thread_rng());
        let pubkey = VerificationKey::from_secret(&privkey, &r);

        let message = format!("message {i}");
        let sig = Signature::sign_message(b"test", message.as_bytes(), pubkey, privkey);

        // Verify individually first
        assert!(sig
            .verify_message(b"test", message.as_bytes(), pubkey)
            .is_ok());

        // Add to batch
        sig.verify_batched(
            &mut Transcript::new(b"zkschnorr.sign_message")
                .tap(|t| t.append_message(b"test", message.as_bytes())),
            pubkey,
            &mut batch,
        );
    }

    // Verify entire batch
    assert!(batch.verify().is_ok());
}

// Extension trait for convenient transcript setup
trait TranscriptExt {
    fn tap<F: FnOnce(&mut Self)>(mut self, f: F) -> Self
    where
        Self: Sized,
    {
        f(&mut self);
        self
    }
}

impl TranscriptExt for Transcript {}

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use std::fmt;

use super::batch::{BatchVerification, SingleVerifier};
use super::errors::ZkSchnorrError;
use super::key::VerificationKey;
use super::transcript::TranscriptProtocol;
use core::iter;
use merlin::Transcript;

/// A Schnorr signature.
#[derive(Copy, Clone)]
pub struct Signature {
    /// Signature using nonce, message, and private key
    pub s: Scalar,
    /// Nonce commitment
    pub R: CompressedRistretto,
}

impl Signature {
    /// Creates a signature for a single private key and single message
    pub fn sign(
        transcript: &mut Transcript,
        pubkey: VerificationKey,
        privkey: Scalar,
    ) -> Signature {
        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"x", &privkey.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let r = Scalar::random(&mut rng);
        // R = generator * r
        let R = (pubkey.g.decompress().unwrap() * r).compress();

        let c = {
            transcript.zkschnorr_domain_sep();
            transcript.append_point(b"G", &pubkey.g);
            transcript.append_point(b"H", &pubkey.h);
            transcript.append_point(b"R", &R);
            transcript.challenge_scalar(b"challenge")
        };

        let s = r + c * privkey;

        Signature { s, R }
    }

    /// Verifies the signature over a transcript using the provided verification key.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        pubkey: VerificationKey,
    ) -> Result<(), ZkSchnorrError> {
        SingleVerifier::verify(|verifier| self.verify_batched(transcript, pubkey, verifier))
    }

    /// Verifies the signature against a given verification key in a batch.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify_batched(
        &self,
        transcript: &mut Transcript,
        pubkey: VerificationKey,
        batch: &mut impl BatchVerification,
    ) {
        // Make c = H(pubkey, R, m)
        // The message has already been fed into the transcript
        let c = {
            transcript.zkschnorr_domain_sep();
            transcript.append_point(b"G", &pubkey.g);
            transcript.append_point(b"H", &pubkey.h);
            transcript.append_point(b"R", &self.R);
            transcript.challenge_scalar(b"challenge")
        };

        // Form the final linear combination:
        // The equation is: s * G = R + c * H
        // Rearranged: 0 = -s * G + 1 * R + c * H
        // Where G is pubkey.g, R is self.R, H is pubkey.h
        batch.append(
            -self.s,
            iter::once(Scalar::one()).chain(iter::once(c)),
            iter::once(pubkey.g.decompress())
                .chain(iter::once(self.R.decompress()))
                .chain(iter::once(pubkey.h.decompress())),
        );
    }
}

// Message-oriented API
impl Signature {
    /// Signs a message with a given domain-separation label.
    /// This is a simpler byte-oriented API over more flexible Transcript-based API.
    /// Internally it creates a Transcript instance labelled "zkschnorr.sign_message",
    /// and appends to it message bytes labelled with a user-provided `label`.
    pub fn sign_message(
        label: &'static [u8],
        message: &[u8],
        pubkey: VerificationKey,
        privkey: Scalar,
    ) -> Signature {
        Self::sign(
            &mut Self::transcript_for_message(label, message),
            pubkey,
            privkey,
        )
    }

    /// Verifies the signature over a message using the provided verification key.
    /// Internally it creates a Transcript instance labelled "zkschnorr.sign_message",
    /// and appends to it message bytes labelled with a user-provided `label`.
    pub fn verify_message(
        &self,
        label: &'static [u8],
        message: &[u8],
        pubkey: VerificationKey,
    ) -> Result<(), ZkSchnorrError> {
        self.verify(&mut Self::transcript_for_message(label, message), pubkey)
    }

    fn transcript_for_message(label: &'static [u8], message: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"zkschnorr.sign_message");
        t.append_message(label, message);
        t
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Without hex crate we'd do this, but it outputs comma-separated numbers: [aa, 11, 5a, ...]
        write!(
            f,
            "Signature({}{})",
            hex::encode(self.s.as_bytes()),
            hex::encode(self.R.as_bytes())
        )
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        (self.R == other.R) && (self.s == other.s)
    }
}

impl Eq for Signature {}

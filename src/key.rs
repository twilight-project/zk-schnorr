use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use super::errors::ZkSchnorrError;
//use serde::{Deserialize, Serialize};

/// Signing key (aka "privkey") is a type alias for the scalar in Ristretto255 group.
pub type SigningKey = Scalar;

/// Verification key (aka "pubkey") is a wrapper type around two Ristretto points
/// that lets the verifier to check the signature.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]//, Serialize, Deserialize)]
//#[serde(from = "CompressedRistretto", into = "CompressedRistretto")]
pub struct VerificationKey {
  pub(crate)  g: CompressedRistretto,     //G.r
  pub(crate)  h: CompressedRistretto,     //(G.r).sk
}

impl VerificationKey {

  ///set verification key
  pub fn new(g: CompressedRistretto, h: CompressedRistretto)->Self{
  Self{g,h}
  }
    /// Constructs a VerificationKey from a private key and some randomness.
    pub fn from_secret(privkey: &Scalar, r: &Scalar) -> Self {
        let g = Self::from_secret_decompressed(r);
        let h = privkey * &g;
        Self::from_compressed(g.compress(),h.compress())
    }

    /// Constructs first point of VerificationKey from randomness.
    pub fn from_secret_decompressed(r: &Scalar) -> RistrettoPoint {
        r * RISTRETTO_BASEPOINT_POINT
    }

    /// Creates new key from a compressed form, remembers the compressed point.
    pub fn from_compressed(p: CompressedRistretto, q: CompressedRistretto) -> Self {
        VerificationKey { 
            g: p,
            h: q
        }
    }

    /// Converts the Verification key to compressed points
    pub fn into_point(self) -> (CompressedRistretto, CompressedRistretto) {
        (self.g, self.h)
    }

    /// Returns a reference to the compressed ristretto points
    pub fn as_point(&self) -> (&CompressedRistretto, &CompressedRistretto) {
        (&self.g, &self.h)
    }

    /// Returns the byte representation of the verification key
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(64);
        bytes.extend_from_slice(self.g.as_bytes());
        bytes.extend_from_slice(self.h.as_bytes());
        bytes
    }

    /// Creates a VerificationKey from a 64-byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkSchnorrError> {
        if bytes.len() != 64 {
            return Err(ZkSchnorrError::InvalidSignature);
        }
        
        let mut g_bytes = [0u8; 32];
        let mut h_bytes = [0u8; 32];
        g_bytes.copy_from_slice(&bytes[0..32]);
        h_bytes.copy_from_slice(&bytes[32..64]);
        
        Ok(VerificationKey {
            g: CompressedRistretto(g_bytes),
            h: CompressedRistretto(h_bytes),
        })
    }

    /// Returns the byte representation of the verification key as a fixed-size array
    pub fn to_bytes_array(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(self.g.as_bytes());
        bytes[32..64].copy_from_slice(self.h.as_bytes());
        bytes
    }
}


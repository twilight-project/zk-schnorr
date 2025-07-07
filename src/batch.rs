use core::borrow::Borrow;
use core::iter;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};

use super::errors::ZkSchnorrError;

/// Trait for a batch verification of signatures.
/// If you are only verifying signatures, without other proofs, you can use
/// concrete implementation `BatchVerifier` without rolling out your own.
pub trait BatchVerification {
    /// Adds scalar for multiplying by a base point and pairs of dynamic scalars/points.
    /// The API admits variable-length iterators of scalars/points
    /// for compatibility with multi-key signatures (see Musig).
    /// It is responsibility of the caller to provide iterators of scalars and points with matching lengths.
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator<Item = Scalar>,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>;
}

/// Single signature verifier that implements batching interface.
pub struct SingleVerifier {
    result: Result<(), ZkSchnorrError>,
}

impl SingleVerifier {
    /// Creates a new verifier
    pub fn verify<F>(closure: F) -> Result<(), ZkSchnorrError>
    where
        F: FnOnce(&mut Self),
    {
        let mut verifier = Self {
            result: Err(ZkSchnorrError::InvalidSignature),
        };
        closure(&mut verifier);
        verifier.result
    }
}

impl BatchVerification for SingleVerifier {
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>,
    {
        // Collect all scalars (basepoint_scalar + dynamic_scalars) and points
        let scalars = iter::once(basepoint_scalar)
            .chain(dynamic_scalars)
            .map(|s| *s.borrow())
            .collect::<Vec<_>>();
        let points = dynamic_points.into_iter().collect::<Vec<_>>();
        
        self.result = RistrettoPoint::optional_multiscalar_mul(scalars, points)
            .ok_or(ZkSchnorrError::InvalidSignature)
            .and_then(|result| {
                if result.is_identity() {
                    Ok(())
                } else {
                    Err(ZkSchnorrError::InvalidSignature)
                }
            })
    }
}

/// Batch signature verifier for use with `Signature::verify_batched`.
pub struct BatchVerifier<R: RngCore + CryptoRng> {
    rng: R,
    dyn_weights: Vec<Scalar>,
    dyn_points: Vec<Option<RistrettoPoint>>,
}

impl<R: RngCore + CryptoRng> BatchVerifier<R> {
    /// Returns a new instance for batch verification
    pub fn new(rng: R) -> Self {
        Self::with_capacity(rng, 0)
    }

    /// Returns a new instance for batch verification with pre-allocated capacity `n`
    /// for verifying `n` simple schnorr signatures.
    pub fn with_capacity(rng: R, capacity: usize) -> Self {
        Self {
            rng,
            dyn_weights: Vec::with_capacity(capacity * 3), // 3 scalars per signature
            dyn_points: Vec::with_capacity(capacity * 3), // 3 points per signature
        }
    }

    /// Performs the verification and returns the result.
    pub fn verify(self) -> Result<(), ZkSchnorrError> {
        // Handle empty batch case
        if self.dyn_weights.is_empty() && self.dyn_points.is_empty() {
            return Ok(());
        }

        let result = RistrettoPoint::optional_multiscalar_mul(
            self.dyn_weights.into_iter(),
            self.dyn_points.into_iter(),
        )
        .ok_or(ZkSchnorrError::InvalidBatch)?;
        if result.is_identity() {
            Ok(())
        } else {
            Err(ZkSchnorrError::InvalidBatch)
        }
    }
}

impl<R: RngCore + CryptoRng> BatchVerification for BatchVerifier<R> {
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>,
    {
        // Random factor `r` for each set of operations guarantees that
        // individual operations are unlikely (p < 2^-252) to cancel each other,
        // and therefore each operation must produce an identity point.
        let r = Scalar::random(&mut self.rng);
        
        // Add the basepoint scalar as the first dynamic scalar
        self.dyn_weights.push(r * basepoint_scalar.borrow());
        
        // Add all other dynamic scalars
        self.dyn_weights
            .extend(dynamic_scalars.into_iter().map(|f| r * f.borrow()));
        
        // Add all dynamic points (including the "basepoint" as first point)
        self.dyn_points.extend(dynamic_points);
    }
}

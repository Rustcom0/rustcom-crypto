use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;
use crate::xwing::{EntropySource, OsEntropy};

/// Length of an Ed25519 public verifying key (`32 B`).
pub const ED25519_PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Length of an Ed25519 private signing seed (`32 B`).
pub const ED25519_SECRET_SEED_LEN: usize = ed25519_dalek::SECRET_KEY_LENGTH;
/// Length of an Ed25519 signature (`64 B`).
pub const ED25519_SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

// Compile-time checks ensuring ed25519-dalek SigningKey and SHA-2 hash states zeroize on drop.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SigningKey>();
    assert_zeroize_on_drop::<sha2::Sha256>();
    assert_zeroize_on_drop::<sha2::Sha512>();
};

/// Ed25519 public verifying key enforcing strict verification and rejecting weak/small-order
/// and non-canonical (`y >= 2^255 - 19`) encodings.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519VerifyingKey {
    inner: VerifyingKey,
}

impl Ed25519VerifyingKey {
    /// Parses a canonical 32-byte Ed25519 public key, rejecting non-canonical `y >= 2^255 - 19`
    /// encodings, invalid curve points, and small-order weak keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: &[u8; ED25519_PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        // Reject the 19 non-canonical y-coordinates in [2^255 - 19, 2^255 - 1] (ignoring sign bit).
        if (arr[31] & 0x7F) == 0x7F && arr[1..31] == [0xFF; 30] && arr[0] >= 0xED {
            return Err(CryptoError::InvalidPublicKey);
        }
        let inner = VerifyingKey::from_bytes(arr).map_err(|_| CryptoError::InvalidPublicKey)?;
        if inner.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self { inner })
    }

    /// Serializes the Ed25519 public key to its canonical 32-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Derives a 16-byte key identifier (`BLAKE3(pub_key)[0..16]`).
    #[must_use]
    pub fn key_id(&self) -> [u8; 16] {
        let pk_bytes = self.to_bytes();
        let digest = blake3::hash(&pk_bytes);
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        id
    }

    /// Strictly verifies a 64-byte Ed25519 signature (`verify_strict`), rejecting small-order
    /// components and signature malleability.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig_arr: &[u8; ED25519_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = Signature::from_bytes(sig_arr);
        self.inner
            .verify_strict(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519VerifyingKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

/// Ed25519 private signing key (`32 B` seed) that zeroizes automatically on drop and redacts `Debug`.
pub struct Ed25519SigningKey {
    inner: SigningKey,
}

impl ZeroizeOnDrop for Ed25519SigningKey {}

impl Ed25519SigningKey {
    fn from_seed_ref(seed: &[u8; ED25519_SECRET_SEED_LEN]) -> (Self, Ed25519VerifyingKey) {
        let inner = SigningKey::from_bytes(seed);
        let vk = Ed25519VerifyingKey {
            inner: inner.verifying_key(),
        };
        (Self { inner }, vk)
    }

    /// Generates a new Ed25519 keypair using the platform CSPRNG (`getrandom`).
    pub fn generate() -> Result<(Self, Ed25519VerifyingKey), CryptoError> {
        let mut seed = Zeroizing::new([0_u8; ED25519_SECRET_SEED_LEN]);
        OsEntropy.fill_random(seed.as_mut())?;
        Ok(Self::from_seed_ref(&seed))
    }

    /// Generates a new Ed25519 keypair using a caller-supplied `CryptoRng`.
    #[must_use]
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, Ed25519VerifyingKey) {
        let mut seed = Zeroizing::new([0_u8; ED25519_SECRET_SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed_ref(&seed)
    }

    /// Expands a 32-byte seed slice into an Ed25519 keypair without an unzeroized stack copy.
    pub fn from_seed_slice(slice: &[u8]) -> Result<(Self, Ed25519VerifyingKey), CryptoError> {
        if slice.len() != ED25519_SECRET_SEED_LEN {
            return Err(CryptoError::InvalidSecretKey);
        }
        let mut seed = Zeroizing::new([0_u8; ED25519_SECRET_SEED_LEN]);
        seed.copy_from_slice(slice);
        Ok(Self::from_seed_ref(&seed))
    }

    /// Expands a 32-byte seed into an Ed25519 keypair, zeroizing the callee's parameter copy.
    ///
    /// Note: `[u8; 32]` is `Copy`, so callers holding live secrets should prefer
    /// [`Self::from_seed_slice`] backed by a [`Zeroizing`] buffer.
    #[must_use]
    pub fn from_seed_bytes(mut seed: [u8; ED25519_SECRET_SEED_LEN]) -> (Self, Ed25519VerifyingKey) {
        let mut guarded = Zeroizing::new([0_u8; ED25519_SECRET_SEED_LEN]);
        guarded.copy_from_slice(&seed);
        seed.zeroize();
        Self::from_seed_ref(&guarded)
    }

    /// Exports the 32-byte private signing seed wrapped in [`Zeroizing`].
    #[must_use]
    pub fn to_seed_bytes(&self) -> Zeroizing<[u8; ED25519_SECRET_SEED_LEN]> {
        let mut out = Zeroizing::new([0_u8; ED25519_SECRET_SEED_LEN]);
        out.copy_from_slice(self.inner.as_bytes());
        out
    }

    /// Returns the corresponding public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Produces a deterministic RFC 8032 Ed25519 signature over `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        self.inner.sign(message).to_bytes()
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SigningKey([REDACTED])")
    }
}

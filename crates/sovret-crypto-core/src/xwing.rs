use alloc::boxed::Box;
use core::fmt;

use rand_core::CryptoRng;
use x_wing::{
    CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE, DecapsulationKey, DecapsulationKeyRejectNonContrib,
    Decapsulator, ENCAPSULATION_KEY_SIZE, ENCAPSULATION_RANDOMNESS_SIZE, EncapsulationKey,
    KeyExport, KeyInit, TryDecapsulate,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, SymmetricKey};

/// Size of an X-Wing (`ML-KEM-768 + X25519`) public key in bytes (`1,216 B`).
pub const XWING_PUBLIC_KEY_LEN: usize = ENCAPSULATION_KEY_SIZE;
/// Size of a compact X-Wing private seed in bytes (`32 B`).
pub const XWING_SECRET_SEED_LEN: usize = DECAPSULATION_KEY_SIZE;
/// Size of an X-Wing KEM ciphertext in bytes (`1,120 B`).
pub const XWING_CIPHERTEXT_LEN: usize = CIPHERTEXT_SIZE;
/// Byte offset of the 32-byte X25519 public key inside a 1,216-byte X-Wing public key.
const XWING_X25519_PK_OFFSET: usize = 1184;

// Compile-time check ensuring x-wing's inner DecapsulationKey keeps ZeroizeOnDrop enabled.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<DecapsulationKey>();
};

/// Internal fallible entropy source unifying `getrandom` (production) and `CryptoRng` (tests/KATs).
pub(crate) trait EntropySource {
    fn fill_random(&mut self, dst: &mut [u8]) -> Result<(), CryptoError>;
}

pub(crate) struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_random(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(dst).map_err(|_| CryptoError::RngFailure)
    }
}

pub(crate) struct RngEntropy<'a, R: CryptoRng + ?Sized>(pub(crate) &'a mut R);

impl<R: CryptoRng + ?Sized> EntropySource for RngEntropy<'_, R> {
    fn fill_random(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

/// Checks in constant time that a 32-byte Curve25519 u-coordinate is NOT a low-order point
/// (order 1, 2, 4, or 8 on Curve25519 or its quadratic twist, including non-canonical `u >= p`).
///
/// `X25519StaticSecret::from([0; 32])` clamps to the pure power-of-two scalar `2^254`, which is
/// divisible by cofactor 8 and coprime to both prime subgroup orders `l` and `l'`. Therefore
/// `[2^254] P == 0` iff `order(P) | 8`.
fn is_contributory_x25519_pk(x_bytes: [u8; 32]) -> bool {
    let probe_scalar = X25519StaticSecret::from([0_u8; 32]);
    let peer = X25519PublicKey::from(x_bytes);
    probe_scalar.diffie_hellman(&peer).was_contributory()
}

/// Heap-allocated X-Wing (`ML-KEM-768 + X25519`) public encapsulation key (`1,216 B`).
///
/// Heap allocation (`Box`) prevents `wasm32` stack overflow from ML-KEM polynomial structures.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingPublicKey {
    inner: Box<EncapsulationKey>,
}

impl XWingPublicKey {
    /// Parses a 1,216-byte X-Wing encapsulation key, rejecting malformed ML-KEM keys and
    /// low-order / non-contributory Curve25519 public keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let pk = EncapsulationKey::try_from(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        let x_bytes: [u8; 32] = bytes
            .get(XWING_X25519_PK_OFFSET..XWING_PUBLIC_KEY_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(CryptoError::InvalidPublicKey)?;
        if !is_contributory_x25519_pk(x_bytes) {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self {
            inner: Box::new(pk),
        })
    }

    /// Serializes the X-Wing encapsulation key to 1,216 bytes (`ML-KEM-768 || X25519`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING_PUBLIC_KEY_LEN] {
        self.inner.to_bytes().0
    }

    /// Derives the canonical 16-byte `key_id` (`BLAKE3(pub_key)[0..16]`).
    #[must_use]
    pub fn key_id(&self) -> [u8; 16] {
        let pk_bytes = self.to_bytes();
        let digest = blake3::hash(&pk_bytes);
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        id
    }

    pub(crate) fn encapsulate_with_entropy<E: EntropySource>(
        &self,
        entropy: &mut E,
    ) -> Result<(Box<[u8; XWING_CIPHERTEXT_LEN]>, SymmetricKey), CryptoError> {
        let mut randomness = Zeroizing::new([0_u8; ENCAPSULATION_RANDOMNESS_SIZE]);
        entropy.fill_random(randomness.as_mut())?;
        // Pass zero-copy reference `&Array<u8, U64>` directly from `Zeroizing` buffer.
        let (ct, mut ss) = self.inner.encapsulate_deterministic((&*randomness).into());
        let key = SymmetricKey::try_from_slice(ss.as_slice())?;
        ss.zeroize();
        Ok((Box::new(ct.0), key))
    }

    /// Encapsulates a fresh 32-byte shared secret using the platform CSPRNG (`getrandom`).
    pub fn encapsulate(
        &self,
    ) -> Result<(Box<[u8; XWING_CIPHERTEXT_LEN]>, SymmetricKey), CryptoError> {
        self.encapsulate_with_entropy(&mut OsEntropy)
    }

    /// Encapsulates a 32-byte shared secret using a caller-supplied `CryptoRng`.
    pub fn encapsulate_with_rng<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(Box<[u8; XWING_CIPHERTEXT_LEN]>, SymmetricKey), CryptoError> {
        self.encapsulate_with_entropy(&mut RngEntropy(rng))
    }
}

impl fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XWingPublicKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

/// Heap-allocated X-Wing (`ML-KEM-768 + X25519`) private decapsulation key (`32 B` seed).
///
/// Uses [`DecapsulationKeyRejectNonContrib`] to reject low-order non-contributory X25519
/// points during decapsulation and zeroizes its seed automatically on drop.
pub struct XWingSecretKey {
    inner: Box<DecapsulationKeyRejectNonContrib>,
}

impl ZeroizeOnDrop for XWingSecretKey {}

impl XWingSecretKey {
    pub(crate) fn from_seed_ref(seed: &[u8; XWING_SECRET_SEED_LEN]) -> (Self, XWingPublicKey) {
        let dk = Box::new(DecapsulationKeyRejectNonContrib::new(seed.into()));
        let pk = XWingPublicKey {
            inner: Box::new(dk.encapsulation_key().clone()),
        };
        (Self { inner: dk }, pk)
    }

    /// Generates a new X-Wing keypair using the platform CSPRNG (`getrandom`).
    pub fn generate() -> Result<(Self, XWingPublicKey), CryptoError> {
        let mut seed = Zeroizing::new([0_u8; XWING_SECRET_SEED_LEN]);
        OsEntropy.fill_random(seed.as_mut())?;
        Ok(Self::from_seed_ref(&seed))
    }

    /// Generates a new X-Wing keypair using a caller-supplied `CryptoRng`.
    #[must_use]
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, XWingPublicKey) {
        let mut seed = Zeroizing::new([0_u8; XWING_SECRET_SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed_ref(&seed)
    }

    /// Expands a 32-byte seed slice into a keypair without creating an unzeroized stack copy.
    pub fn from_seed_slice(slice: &[u8]) -> Result<(Self, XWingPublicKey), CryptoError> {
        if slice.len() != XWING_SECRET_SEED_LEN {
            return Err(CryptoError::InvalidSecretKey);
        }
        let mut seed = Zeroizing::new([0_u8; XWING_SECRET_SEED_LEN]);
        seed.copy_from_slice(slice);
        Ok(Self::from_seed_ref(&seed))
    }

    /// Expands a 32-byte seed into a keypair (useful for deterministic vault derivation).
    ///
    /// Note: `[u8; 32]` is `Copy`, so this zeroizes only the callee's parameter copy.
    /// Security-sensitive callers holding live secrets should prefer [`Self::from_seed_slice`]
    /// backed by a [`Zeroizing`] buffer.
    #[must_use]
    pub fn from_seed_bytes(mut seed: [u8; XWING_SECRET_SEED_LEN]) -> (Self, XWingPublicKey) {
        let mut guarded = Zeroizing::new([0_u8; XWING_SECRET_SEED_LEN]);
        guarded.copy_from_slice(&seed);
        seed.zeroize();
        Self::from_seed_ref(&guarded)
    }

    /// Exports the compact 32-byte private seed wrapped in [`Zeroizing`].
    #[must_use]
    pub fn to_seed_bytes(&self) -> Zeroizing<[u8; XWING_SECRET_SEED_LEN]> {
        let mut exported = self.inner.to_bytes();
        let mut out = Zeroizing::new([0_u8; XWING_SECRET_SEED_LEN]);
        out.copy_from_slice(exported.as_slice());
        exported.zeroize();
        out
    }

    /// Returns the corresponding heap-allocated public encapsulation key.
    #[must_use]
    pub fn public_key(&self) -> XWingPublicKey {
        XWingPublicKey {
            inner: Box::new(self.inner.encapsulation_key().clone()),
        }
    }

    /// Decapsulates an X-Wing ciphertext, rejecting malformed lengths or non-contributory points.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SymmetricKey, CryptoError> {
        let ct_arr: &[u8; XWING_CIPHERTEXT_LEN] = ciphertext
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let mut ss = self
            .inner
            .try_decapsulate(ct_arr.into())
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let key = SymmetricKey::try_from_slice(ss.as_slice())?;
        ss.zeroize();
        Ok(key)
    }
}

impl fmt::Debug for XWingSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingSecretKey([REDACTED])")
    }
}

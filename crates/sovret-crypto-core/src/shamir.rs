use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::xwing::{EntropySource, OsEntropy, RngEntropy};
use crate::{CryptoError, RECOVERY_SECRET_LEN, RecoveryMasterSecret};

/// Length of the secret split by `GF(256)` Shamir secret sharing (`32 B` = 256 bits).
pub const SHAMIR_SECRET_LEN: usize = RECOVERY_SECRET_LEN;
/// Minimum allowed Shamir threshold (`M >= 2`).
pub const MIN_SHAMIR_THRESHOLD: u8 = 2;
/// Maximum allowed Shamir total shares (`N <= 64`) to bound WASM Lagrange interpolation work.
pub const MAX_SHAMIR_SHARES: u8 = 64;
/// 5-byte magic prefix for serialized Shamir shares (`"RCSHR"`).
pub const SHAMIR_SHARE_MAGIC: &[u8; 5] = b"RCSHR";
/// Wire version byte for `RCSHR` v1 Shamir shares (`0x01`).
pub const SHAMIR_SHARE_VERSION_V1: u8 = 0x01;
/// Exact canonical binary length of a serialized `RCSHR` v1 share (`105 B`):
/// `"RCSHR"[5] || ver[1] || tenant_id[16] || split_id[16] || threshold[1] || total_shares[1]
/// || share_index[1] || share_value[32] || commitment_sha256[32]`.
pub const SHAMIR_SHARE_WIRE_LEN: usize = 5 + 1 + 16 + 16 + 1 + 1 + 1 + SHAMIR_SECRET_LEN + 32;
/// Domain-separation prefix for per-share `SHA-256` integrity commitments (`29 B`).
pub const SHAMIR_COMMIT_DOMAIN: &[u8; 29] = b"sovret-v1-shamir-share-commit";

/// Constant-time multiplication in `GF(2^8)` modulo the AES/Rijndael irreducible polynomial
/// `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
///
/// Uses zero lookup tables and zero secret-dependent branches.
#[inline]
#[must_use]
const fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0_u8;
    let mut i = 0;
    while i < 8 {
        let lsb_mask = 0_u8.wrapping_sub(b & 1);
        acc ^= a & lsb_mask;
        let hi_mask = 0_u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & hi_mask);
        b >>= 1;
        i += 1;
    }
    acc
}

/// Constant-time multiplicative inverse in `GF(2^8)` via Fermat's Little Theorem (`a^254`).
///
/// Maps `0 -> 0` and every non-zero `a` to `a^-1` using a fixed 11-multiplication addition chain
/// with zero branches and zero lookup tables.
#[inline]
#[must_use]
const fn gf256_inv(a: u8) -> u8 {
    let a2 = gf256_mul(a, a);
    let a3 = gf256_mul(a2, a);
    let a6 = gf256_mul(a3, a3);
    let a7 = gf256_mul(a6, a);
    let a14 = gf256_mul(a7, a7);
    let a15 = gf256_mul(a14, a);
    let a30 = gf256_mul(a15, a15);
    let a60 = gf256_mul(a30, a30);
    let a120 = gf256_mul(a60, a60);
    let a127 = gf256_mul(a120, a7);
    gf256_mul(a127, a127)
}

#[inline]
#[must_use]
const fn gf256_div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_inv(b))
}

/// Computes the unkeyed, domain-separated `SHA-256` per-share integrity commitment:
/// `SHA-256("sovret-v1-shamir-share-commit" || tenant_id || split_id || threshold
///          || total_shares || share_index || share_value)`.
///
/// **Security scope (integrity only, NOT share authenticity):** This digest detects accidental
/// share corruption and binds a share to an externally persisted commitment (e.g. in
/// `recovery_blobs.commitment_sha256` or printed out-of-band), while preserving full
/// information-theoretic secrecy for fewer than `threshold` shares. Because it is unkeyed, a
/// malicious holder can forge a self-consistent share with a recomputed commitment; verifying
/// authenticity against malicious share holders requires checking [`ShamirShare::verify_commitment`]
/// against an authenticated out-of-band/database commitment (or a future VSS scheme). Downstream
/// [`crate::unwrap_recovery_backup`] still rejects wrong reconstructed secrets via AEAD.
fn compute_share_commitment(
    tenant_id: &[u8; 16],
    split_id: &[u8; 16],
    threshold: u8,
    total_shares: u8,
    share_index: u8,
    share_value: &[u8; SHAMIR_SECRET_LEN],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SHAMIR_COMMIT_DOMAIN);
    hasher.update(tenant_id);
    hasher.update(split_id);
    hasher.update([threshold, total_shares, share_index]);
    hasher.update(share_value);
    let digest = Zeroizing::new(hasher.finalize());
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn validate_shamir_params(
    split_id: &[u8; 16],
    threshold: u8,
    total_shares: u8,
) -> Result<(), CryptoError> {
    if bool::from(split_id.ct_eq(&[0_u8; 16])) {
        return Err(CryptoError::InvalidShamirParams);
    }
    if threshold < MIN_SHAMIR_THRESHOLD
        || total_shares < threshold
        || total_shares > MAX_SHAMIR_SHARES
    {
        return Err(CryptoError::InvalidShamirParams);
    }
    Ok(())
}

/// Single `GF(256)` Shamir M-of-N recovery share with a domain-separated `SHA-256` integrity commitment.
///
/// Automatically zeroizes `share_value` on drop, redacts `Debug`, and uses constant-time equality.
/// Note: the embedded `commitment_sha256` provides integrity/corruption detection only; callers
/// requiring authenticity against malicious share holders must verify each share via
/// [`Self::verify_commitment`] against an authenticated stored or out-of-band commitment.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    tenant_id: [u8; 16],
    split_id: [u8; 16],
    threshold: u8,
    total_shares: u8,
    share_index: u8,
    share_value: [u8; SHAMIR_SECRET_LEN],
    commitment_sha256: [u8; 32],
}

impl ShamirShare {
    #[must_use]
    pub const fn tenant_id(&self) -> &[u8; 16] {
        &self.tenant_id
    }

    #[must_use]
    pub const fn split_id(&self) -> &[u8; 16] {
        &self.split_id
    }

    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    #[must_use]
    pub const fn total_shares(&self) -> u8 {
        self.total_shares
    }

    /// 1-based non-zero `GF(256)` x-coordinate (`1..=total_shares`).
    #[must_use]
    pub const fn share_index(&self) -> u8 {
        self.share_index
    }

    /// 32-byte `SHA-256` per-share commitment stored in `recovery_blobs.commitment_sha256`.
    #[must_use]
    pub const fn commitment_sha256(&self) -> &[u8; 32] {
        &self.commitment_sha256
    }

    /// Recomputes this share's `SHA-256` commitment and verifies in constant time that it matches
    /// both its embedded commitment and `expected_commitment_sha256` (e.g. from `recovery_blobs`).
    pub fn verify_commitment(
        &self,
        expected_commitment_sha256: &[u8; 32],
    ) -> Result<(), CryptoError> {
        let recomputed = compute_share_commitment(
            &self.tenant_id,
            &self.split_id,
            self.threshold,
            self.total_shares,
            self.share_index,
            &self.share_value,
        );
        let ok = recomputed.ct_eq(&self.commitment_sha256)
            & recomputed.ct_eq(expected_commitment_sha256);
        if !bool::from(ok) {
            return Err(CryptoError::InvalidShamirShare);
        }
        Ok(())
    }

    /// Serializes this share into its canonical 105-byte `RCSHR` v1 binary frame wrapped in
    /// [`Zeroizing`].
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SHAMIR_SHARE_WIRE_LEN]> {
        let mut out = Zeroizing::new([0_u8; SHAMIR_SHARE_WIRE_LEN]);
        out[0..5].copy_from_slice(SHAMIR_SHARE_MAGIC);
        out[5] = SHAMIR_SHARE_VERSION_V1;
        out[6..22].copy_from_slice(&self.tenant_id);
        out[22..38].copy_from_slice(&self.split_id);
        out[38] = self.threshold;
        out[39] = self.total_shares;
        out[40] = self.share_index;
        out[41..73].copy_from_slice(&self.share_value);
        out[73..105].copy_from_slice(&self.commitment_sha256);
        out
    }

    /// Parses and verifies a 105-byte `RCSHR` v1 Shamir share, checking parameter bounds and the
    /// embedded `SHA-256` commitment in constant time.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SHAMIR_SHARE_WIRE_LEN {
            return Err(CryptoError::TruncatedInput);
        }
        if bytes.len() > SHAMIR_SHARE_WIRE_LEN {
            return Err(CryptoError::TrailingBytes);
        }
        if bytes[0..5] != *SHAMIR_SHARE_MAGIC {
            return Err(CryptoError::InvalidMagic);
        }
        if bytes[5] != SHAMIR_SHARE_VERSION_V1 {
            return Err(CryptoError::UnsupportedFormatVersion(bytes[5]));
        }

        let mut tenant_id = [0_u8; 16];
        tenant_id.copy_from_slice(&bytes[6..22]);
        let mut split_id = [0_u8; 16];
        split_id.copy_from_slice(&bytes[22..38]);
        let threshold = bytes[38];
        let total_shares = bytes[39];
        let share_index = bytes[40];

        validate_shamir_params(&split_id, threshold, total_shares)?;
        if share_index == 0 || share_index > total_shares {
            return Err(CryptoError::InvalidShamirParams);
        }

        let mut commitment_sha256 = [0_u8; 32];
        commitment_sha256.copy_from_slice(&bytes[73..105]);

        let mut share = Self {
            tenant_id,
            split_id,
            threshold,
            total_shares,
            share_index,
            share_value: [0_u8; SHAMIR_SECRET_LEN],
            commitment_sha256,
        };
        share.share_value.copy_from_slice(&bytes[41..73]);

        let expected = compute_share_commitment(
            &share.tenant_id,
            &share.split_id,
            share.threshold,
            share.total_shares,
            share.share_index,
            &share.share_value,
        );
        if !bool::from(expected.ct_eq(&share.commitment_sha256)) {
            return Err(CryptoError::InvalidShamirShare);
        }

        Ok(share)
    }
}

impl fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShamirShare")
            .field("tenant_id", &self.tenant_id)
            .field("split_id", &self.split_id)
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("share_index", &self.share_index)
            .field("share_value", &"[REDACTED]")
            .field("commitment_sha256", &self.commitment_sha256)
            .finish()
    }
}

impl PartialEq for ShamirShare {
    fn eq(&self, other: &Self) -> bool {
        let eq = self.tenant_id.ct_eq(&other.tenant_id)
            & self.split_id.ct_eq(&other.split_id)
            & self.threshold.ct_eq(&other.threshold)
            & self.total_shares.ct_eq(&other.total_shares)
            & self.share_index.ct_eq(&other.share_index)
            & self.share_value.ct_eq(&other.share_value)
            & self.commitment_sha256.ct_eq(&other.commitment_sha256);
        bool::from(eq)
    }
}

impl Eq for ShamirShare {}

fn split_recovery_secret_with_entropy<E: EntropySource>(
    entropy: &mut E,
    secret: &RecoveryMasterSecret,
    tenant_id: [u8; 16],
    split_id: [u8; 16],
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<ShamirShare>, CryptoError> {
    validate_shamir_params(&split_id, threshold, total_shares)?;

    let m = usize::from(threshold);
    let n = usize::from(total_shares);
    // Draw `(m - 1)` uniform random coefficients in GF(256) for each of the 32 secret bytes.
    let mut random_coeffs = Zeroizing::new(vec![0_u8; SHAMIR_SECRET_LEN * (m - 1)]);
    entropy.fill_random(random_coeffs.as_mut_slice())?;

    let mut shares = Vec::with_capacity(n);
    for share_idx_u8 in 1..=total_shares {
        let mut share_value = Zeroizing::new([0_u8; SHAMIR_SECRET_LEN]);
        for (byte_pos, &secret_byte) in secret.as_bytes().iter().enumerate() {
            // Horner's method: P(x) = (((c_{m-1} * x + c_{m-2}) * x + ... ) * x + c_0)
            let coeff_base = byte_pos * (m - 1);
            let mut y = 0_u8;
            for coeff_offset in (0..(m - 1)).rev() {
                y = gf256_mul(y, share_idx_u8) ^ random_coeffs[coeff_base + coeff_offset];
            }
            y = gf256_mul(y, share_idx_u8) ^ secret_byte;
            share_value[byte_pos] = y;
        }

        let commitment_sha256 = compute_share_commitment(
            &tenant_id,
            &split_id,
            threshold,
            total_shares,
            share_idx_u8,
            &share_value,
        );
        let mut share = ShamirShare {
            tenant_id,
            split_id,
            threshold,
            total_shares,
            share_index: share_idx_u8,
            share_value: [0_u8; SHAMIR_SECRET_LEN],
            commitment_sha256,
        };
        share.share_value.copy_from_slice(share_value.as_ref());
        shares.push(share);
    }

    Ok(shares)
}

/// Splits a 256-bit [`RecoveryMasterSecret`] into `total_shares` `GF(256)` Shamir shares requiring
/// any `threshold` (`2 <= threshold <= total_shares <= 64`) shares to reconstruct, using the
/// platform CSPRNG (`getrandom`) for both the 16-byte `split_id` and polynomial coefficients.
pub fn split_recovery_secret(
    secret: &RecoveryMasterSecret,
    tenant_id: [u8; 16],
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<ShamirShare>, CryptoError> {
    if threshold < MIN_SHAMIR_THRESHOLD
        || total_shares < threshold
        || total_shares > MAX_SHAMIR_SHARES
    {
        return Err(CryptoError::InvalidShamirParams);
    }

    let mut split_id = [0_u8; 16];
    OsEntropy.fill_random(&mut split_id)?;
    // Reject the negligible 2^-128 probability all-zero split_id by retrying once.
    if bool::from(split_id.ct_eq(&[0_u8; 16])) {
        OsEntropy.fill_random(&mut split_id)?;
    }

    split_recovery_secret_with_entropy(
        &mut OsEntropy,
        secret,
        tenant_id,
        split_id,
        threshold,
        total_shares,
    )
}

/// Deterministic `CryptoRng` variant of [`split_recovery_secret`] with caller-supplied `split_id`
/// for KAT vectors and tests.
pub fn split_recovery_secret_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    secret: &RecoveryMasterSecret,
    tenant_id: [u8; 16],
    split_id: [u8; 16],
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<ShamirShare>, CryptoError> {
    split_recovery_secret_with_entropy(
        &mut RngEntropy(rng),
        secret,
        tenant_id,
        split_id,
        threshold,
        total_shares,
    )
}

/// Evaluates the unique degree-`(m - 1)` polynomial defined by `basis` (`m` shares with distinct
/// non-zero x-coordinates) at `eval_x` across all 32 secret bytes in constant time.
fn lagrange_eval_at(basis: &[ShamirShare], eval_x: u8) -> Zeroizing<[u8; SHAMIR_SECRET_LEN]> {
    let m = basis.len();
    let mut weights = Zeroizing::new(vec![0_u8; m]);

    for i in 0..m {
        let x_i = basis[i].share_index;
        let mut num = 1_u8;
        let mut den = 1_u8;
        for (j, share_j) in basis.iter().enumerate() {
            if i != j {
                let x_j = share_j.share_index;
                num = gf256_mul(num, eval_x ^ x_j);
                den = gf256_mul(den, x_i ^ x_j);
            }
        }
        weights[i] = gf256_div(num, den);
    }

    let mut out = Zeroizing::new([0_u8; SHAMIR_SECRET_LEN]);
    for (share, &lambda) in basis.iter().zip(weights.iter()) {
        for (dst, &y_byte) in out.iter_mut().zip(share.share_value.iter()) {
            *dst ^= gf256_mul(y_byte, lambda);
        }
    }
    out
}

/// Reconstructs a 256-bit [`RecoveryMasterSecret`] from `threshold..=total_shares` `GF(256)`
/// [`ShamirShare`]s via constant-time Lagrange interpolation.
///
/// Enforces:
/// - All shares belong to `expected_tenant_id` and the exact same `(split_id, threshold, total_shares)`.
/// - Every share's `SHA-256` integrity commitment is valid in constant time.
/// - All `share_index` values are in `1..=total_shares` and strictly unique.
/// - If more than `threshold` shares are supplied, every extra share is verified in constant time
///   to lie on the exact same degree-`(threshold - 1)` polynomial (catching inconsistent shares
///   when redundant shares are supplied).
///
/// **Threat-model note:** Commitments are unkeyed `SHA-256` integrity checks, not share
/// authenticity proofs (not Feldman/Pedersen VSS). Exactly `threshold` colluding/forged shares
/// with recomputed commitments will reconstruct a different secret (which will subsequently fail
/// `RCREC` AEAD authentication during [`crate::unwrap_recovery_backup`], without identifying the
/// malicious share unless callers pre-check each share with [`ShamirShare::verify_commitment`]
/// against an authenticated commitment record).
pub fn combine_recovery_shares(
    expected_tenant_id: &[u8; 16],
    shares: &[ShamirShare],
) -> Result<RecoveryMasterSecret, CryptoError> {
    let first = shares.first().ok_or(CryptoError::InvalidShamirShare)?;
    validate_shamir_params(&first.split_id, first.threshold, first.total_shares)?;

    let m = usize::from(first.threshold);
    let n = usize::from(first.total_shares);
    if shares.len() < m || shares.len() > n {
        return Err(CryptoError::InvalidShamirShare);
    }

    let mut seen_indices = [false; (MAX_SHAMIR_SHARES as usize) + 1];
    for share in shares {
        let meta_match = share.tenant_id.ct_eq(expected_tenant_id)
            & share.split_id.ct_eq(&first.split_id)
            & share.threshold.ct_eq(&first.threshold)
            & share.total_shares.ct_eq(&first.total_shares);
        if !bool::from(meta_match) {
            return Err(CryptoError::InvalidShamirShare);
        }
        if share.share_index == 0 || share.share_index > first.total_shares {
            return Err(CryptoError::InvalidShamirShare);
        }
        let idx = usize::from(share.share_index);
        if seen_indices[idx] {
            return Err(CryptoError::InvalidShamirShare);
        }
        seen_indices[idx] = true;

        let expected_commit = compute_share_commitment(
            &share.tenant_id,
            &share.split_id,
            share.threshold,
            share.total_shares,
            share.share_index,
            &share.share_value,
        );
        if !bool::from(expected_commit.ct_eq(&share.commitment_sha256)) {
            return Err(CryptoError::InvalidShamirShare);
        }
    }

    let basis = &shares[..m];
    if shares.len() > m {
        let mut all_consistent = Choice::from(1_u8);
        for extra in &shares[m..] {
            let expected_y = lagrange_eval_at(basis, extra.share_index);
            all_consistent &= expected_y.as_slice().ct_eq(&extra.share_value);
        }
        if !bool::from(all_consistent) {
            return Err(CryptoError::InvalidShamirShare);
        }
    }

    let recovered = lagrange_eval_at(basis, 0);
    RecoveryMasterSecret::from_slice(recovered.as_slice())
}

#[cfg(test)]
mod gf256_tests {
    use super::*;

    #[test]
    fn gf256_field_axioms_exhaustive() {
        // Exhaustively verify multiplicative identity, zero annihilation, commutativity,
        // and exact inverse across all 256 elements of GF(2^8).
        assert_eq!(gf256_inv(0), 0);
        for a in 0_u8..=255 {
            assert_eq!(gf256_mul(a, 0), 0);
            assert_eq!(gf256_mul(0, a), 0);
            assert_eq!(gf256_mul(a, 1), a);
            assert_eq!(gf256_mul(1, a), a);
            if a != 0 {
                let inv = gf256_inv(a);
                assert_ne!(inv, 0);
                assert_eq!(gf256_mul(a, inv), 1);
                assert_eq!(gf256_mul(inv, a), 1);
                assert_eq!(gf256_div(a, a), 1);
            }
            for b in 0_u8..=255 {
                assert_eq!(gf256_mul(a, b), gf256_mul(b, a));
            }
        }
        // Known AES GF(2^8) test vector: 0x57 * 0x83 == 0xC1, 0x53^-1 == 0xCA.
        assert_eq!(gf256_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf256_inv(0x53), 0xCA);
    }
}

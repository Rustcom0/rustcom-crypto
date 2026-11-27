use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// 3-tier GDPR / E2EE privacy level bound into `RCENC` `canonical_aad` (`ADR-030`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PrivacyTier {
    Legacy = 1,
    #[default]
    Enhanced = 2,
    Strict = 3,
}

impl PrivacyTier {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(Self::Legacy),
            2 => Ok(Self::Enhanced),
            3 => Ok(Self::Strict),
            other => Err(CryptoError::InvalidPrivacyTier(other)),
        }
    }
}

/// Domain-separated `RCENC` v1 envelope purpose byte (bound in header & `canonical_aad`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EnvelopeKind {
    OrderFulfillment = 0x01,
    OrderAccounting = 0x02,
    PortalMessage = 0x03,
    PrivateProduct = 0x04,
    StaffKeyWrap = 0x05,
    RecoveryBackup = 0x06,
}

impl EnvelopeKind {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            0x01 => Ok(Self::OrderFulfillment),
            0x02 => Ok(Self::OrderAccounting),
            0x03 => Ok(Self::PortalMessage),
            0x04 => Ok(Self::PrivateProduct),
            0x05 => Ok(Self::StaffKeyWrap),
            0x06 => Ok(Self::RecoveryBackup),
            other => Err(CryptoError::InvalidEnvelopeKind(other)),
        }
    }
}

/// `RCENC` v1 recipient slot type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecipientType {
    XWingOrgKey = 0x01,
    XWingCustomerVault = 0x02,
    XWingStaffKey = 0x03,
    XWingVipGroup = 0x04,
    Argon2idPassword = 0x05,
    RecoveryBip39 = 0x06,
}

impl RecipientType {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            0x01 => Ok(Self::XWingOrgKey),
            0x02 => Ok(Self::XWingCustomerVault),
            0x03 => Ok(Self::XWingStaffKey),
            0x04 => Ok(Self::XWingVipGroup),
            0x05 => Ok(Self::Argon2idPassword),
            0x06 => Ok(Self::RecoveryBip39),
            other => Err(CryptoError::InvalidRecipientType(other)),
        }
    }

    /// Returns `true` if this recipient type uses an X-Wing (`ML-KEM-768 + X25519`) slot.
    #[must_use]
    pub const fn is_xwing(self) -> bool {
        matches!(
            self,
            Self::XWingOrgKey
                | Self::XWingCustomerVault
                | Self::XWingStaffKey
                | Self::XWingVipGroup
        )
    }

    /// Exact expected `kem_data_len` on the wire for this recipient type.
    #[must_use]
    pub const fn expected_kem_data_len(self) -> usize {
        match self {
            Self::XWingOrgKey
            | Self::XWingCustomerVault
            | Self::XWingStaffKey
            | Self::XWingVipGroup => x_wing::CIPHERTEXT_SIZE,
            // 32-byte salt || m_cost_kib (4B BE) || t_cost (4B BE) || p_cost (4B BE)
            Self::Argon2idPassword => 44,
            // RecoveryKEK uses tenant_id as HKDF salt directly; no per-slot KEM bytes needed.
            Self::RecoveryBip39 => 0,
        }
    }
}

/// Bitflag byte in the `RCENC` v1 header:
/// - `bit0` (`0x01`): `compressed_zstd`
/// - `bit1` (`0x02`): internal `rcstr_header` domain-separation flag (set exclusively by `RCSTR` v1;
///   rejected by standalone `rcenc::decrypt` to prevent cross-protocol `FileDEK` disclosure)
/// - `bits2..=7`: reserved `0`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EnvelopeFlags {
    pub compressed_zstd: bool,
    pub(crate) rcstr_header: bool,
}

impl EnvelopeFlags {
    pub const BIT_COMPRESSED_ZSTD: u8 = 0x01;
    pub const BIT_RCSTR_HEADER: u8 = 0x02;
    const ALLOWED_MASK: u8 = Self::BIT_COMPRESSED_ZSTD | Self::BIT_RCSTR_HEADER;

    #[must_use]
    pub const fn new(compressed_zstd: bool) -> Self {
        Self {
            compressed_zstd,
            rcstr_header: false,
        }
    }

    #[must_use]
    pub(crate) const fn rcstr_header() -> Self {
        Self {
            compressed_zstd: false,
            rcstr_header: true,
        }
    }

    #[must_use]
    pub const fn is_rcstr_header(self) -> bool {
        self.rcstr_header
    }

    #[must_use]
    pub const fn to_byte(self) -> u8 {
        let mut raw = 0_u8;
        if self.compressed_zstd {
            raw |= Self::BIT_COMPRESSED_ZSTD;
        }
        if self.rcstr_header {
            raw |= Self::BIT_RCSTR_HEADER;
        }
        raw
    }

    pub const fn from_byte(raw: u8) -> Result<Self, CryptoError> {
        if raw & !Self::ALLOWED_MASK != 0 {
            return Err(CryptoError::UnsupportedFlags(raw));
        }
        Ok(Self {
            compressed_zstd: (raw & Self::BIT_COMPRESSED_ZSTD) != 0,
            rcstr_header: (raw & Self::BIT_RCSTR_HEADER) != 0,
        })
    }
}

/// Application context bound cryptographically into `canonical_aad`.
///
/// Recomputed independently by both encryptor and decryptor from trusted application state
/// (never read from the untrusted ciphertext envelope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeContext {
    pub envelope_kind: EnvelopeKind,
    pub tenant_id: [u8; 16],
    pub resource_id: [u8; 16],
    pub privacy_tier: PrivacyTier,
    pub schema_version: u16,
}

/// 32-byte symmetric secret key (DEK, KEK, or wrap key) zeroized on drop and masked in `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copies a 32-byte slice directly into a `ZeroizeOnDrop` buffer without intermediate stack copies.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }
        let mut key = Self([0_u8; 32]);
        key.0.copy_from_slice(slice);
        Ok(key)
    }

    /// Initializes a `SymmetricKey` directly in-place inside its `ZeroizeOnDrop` storage.
    pub(crate) fn init_with<E, F>(f: F) -> Result<Self, E>
    where
        F: FnOnce(&mut [u8; 32]) -> Result<(), E>,
    {
        let mut key = Self([0_u8; 32]);
        f(&mut key.0)?;
        Ok(key)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey([REDACTED])")
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for SymmetricKey {}

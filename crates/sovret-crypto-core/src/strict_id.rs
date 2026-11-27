use alloc::string::String;
use core::fmt;

use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::xwing::{EntropySource, OsEntropy};
use crate::{
    CryptoError, Ed25519SigningKey, Ed25519VerifyingKey, RecipientCredential, RecipientSpec,
    RecipientType, SymmetricKey, XWingPublicKey, XWingSecretKey,
};

/// Raw entropy length of a Mullvad/IVPN-style Strict Account ID (`128 bits = 16 B`).
pub const STRICT_ACCOUNT_ID_BYTES_LEN: usize = 16;
/// Number of Crockford Base32 data symbols (`26 * 5 = 130 bits`, top 2 pad bits `00`).
pub const STRICT_ACCOUNT_ID_DATA_CHARS: usize = 26;
/// Number of Crockford Base32 checksum symbols (`2 * 5 = 10 bits`).
pub const STRICT_ACCOUNT_ID_CHECKSUM_CHARS: usize = 2;
/// Total unformatted Crockford Base32 length (`28` characters).
pub const STRICT_ACCOUNT_ID_TOTAL_CHARS: usize =
    STRICT_ACCOUNT_ID_DATA_CHARS + STRICT_ACCOUNT_ID_CHECKSUM_CHARS;
/// Canonical human display length (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` = `34` chars).
pub const STRICT_ACCOUNT_ID_FORMATTED_LEN: usize = STRICT_ACCOUNT_ID_TOTAL_CHARS + 6;
/// Maximum input string length accepted by [`StrictAccountId::parse`] to bound untrusted input work.
pub const STRICT_ACCOUNT_ID_MAX_INPUT_LEN: usize = 128;

/// Crockford Base32 canonical alphabet (excludes `I`, `L`, `O`, `U`).
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Domain-separation context for the 10-bit `BLAKE3_derive_key` Account ID checksum.
pub const STRICT_ACCOUNT_ID_CHK_CONTEXT: &str = "sovret-v1-account-id-chk";
/// HKDF `info` for the 16-byte client-derived `auth_lookup_id`.
pub const STRICT_LOOKUP_INFO: &[u8] = b"sovret-v1-strict-lookup";
/// HKDF `info` for the 32-byte OPAQUE client password `auth_secret`.
pub const STRICT_AUTH_INFO: &[u8] = b"sovret-v1-strict-auth";
/// HKDF `info` for the 32-byte `customer_vault_seed`.
pub const STRICT_VAULT_INFO: &[u8] = b"sovret-v1-strict-vault";
/// HKDF `info` deriving the buyer's 32-byte X-Wing seed from `customer_vault_seed`.
pub const STRICT_VAULT_XWING_INFO: &[u8] = b"sovret-v1-strict-vault-xwing";
/// HKDF `info` deriving the buyer's 32-byte Ed25519 seed from `customer_vault_seed`.
pub const STRICT_VAULT_ED25519_INFO: &[u8] = b"sovret-v1-strict-vault-ed25519";

/// Constant-time 5-bit symbol (`0..=31`) to canonical uppercase Crockford ASCII byte.
fn ct_encode_crockford_symbol(symbol: u8) -> u8 {
    let mut out = 0_u8;
    let mut idx = 0_u8;
    while usize::from(idx) < CROCKFORD_ALPHABET.len() {
        let eq = symbol.ct_eq(&idx);
        out = u8::conditional_select(&out, &CROCKFORD_ALPHABET[usize::from(idx)], eq);
        idx += 1;
    }
    out
}

/// Branchless constant-time Crockford Base32 ASCII byte decoder.
///
/// Case-insensitively normalizes `i`/`I`/`l`/`L` -> `1` and `o`/`O` -> `0`, while strictly
/// rejecting `u`/`U` and all non-Crockford characters.
fn ct_decode_crockford_char(byte: u8) -> (Choice, u8) {
    // Pure arithmetic range check: byte in b'a'..=b'z' iff (byte - b'a') < 26.
    let (_, is_lower_bool) = byte.wrapping_sub(b'a').overflowing_sub(26);
    let is_lower = Choice::from(u8::from(is_lower_bool));
    let upper = u8::conditional_select(&byte, &byte.wrapping_sub(32), is_lower);

    let is_i_or_l = upper.ct_eq(&b'I') | upper.ct_eq(&b'L');
    let norm1 = u8::conditional_select(&upper, &b'1', is_i_or_l);
    let is_o = norm1.ct_eq(&b'O');
    let norm = u8::conditional_select(&norm1, &b'0', is_o);

    let mut found = Choice::from(0_u8);
    let mut value = 0_u8;
    let mut idx = 0_u8;
    while usize::from(idx) < CROCKFORD_ALPHABET.len() {
        let eq = norm.ct_eq(&CROCKFORD_ALPHABET[usize::from(idx)]);
        value = u8::conditional_select(&value, &idx, eq);
        found |= eq;
        idx += 1;
    }
    (found, value)
}

/// Computes the 2-symbol (10-bit) checksum from the top 10 bits of
/// `BLAKE3_derive_key("sovret-v1-account-id-chk", raw_16b)[0..2]`.
fn compute_checksum_symbols(raw_16b: &[u8; STRICT_ACCOUNT_ID_BYTES_LEN]) -> [u8; 2] {
    let digest = Zeroizing::new(blake3::derive_key(STRICT_ACCOUNT_ID_CHK_CONTEXT, raw_16b));
    let top10 = u16::from_be_bytes([digest[0], digest[1]]) >> 6;
    let hi = u8::try_from((top10 >> 5) & 0x1F).unwrap_or(0);
    let lo = u8::try_from(top10 & 0x1F).unwrap_or(0);
    [hi, lo]
}

/// Encodes 16 secret bytes + 2 checksum symbols into 28 uppercase Crockford Base32 ASCII bytes
/// using a zeroized 16-bit shift register (no unzeroized `u128` stack copies).
fn encode_symbols(raw_16b: &[u8; STRICT_ACCOUNT_ID_BYTES_LEN]) -> Zeroizing<[u8; 28]> {
    let mut chars = Zeroizing::new([0_u8; STRICT_ACCOUNT_ID_TOTAL_CHARS]);
    let mut buf = Zeroizing::new(0_u16);
    let mut bits = 2_u32; // Leading 2 zero pad bits (top 2 bits of symbol 0 are always 00).
    let mut out_idx = 0_usize;

    for &byte in raw_16b {
        *buf = (*buf << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let sym = u8::try_from((*buf >> bits) & 0x1F).unwrap_or(0);
            chars[out_idx] = ct_encode_crockford_symbol(sym);
            out_idx += 1;
        }
    }

    let chk = Zeroizing::new(compute_checksum_symbols(raw_16b));
    chars[26] = ct_encode_crockford_symbol(chk[0]);
    chars[27] = ct_encode_crockford_symbol(chk[1]);
    chars
}

/// 128-bit Mullvad / IVPN-style Strict Zero-Knowledge Account ID.
///
/// Encodes as 26 Crockford Base32 data characters (big-endian, top 2 pad bits `00`) plus a
/// 2-character (10-bit) `BLAKE3_derive_key` checksum, displayed as 7 groups of 4:
/// `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
///
/// Automatically zeroizes its 128-bit root secret on drop, masks `Debug`, and uses constant-time
/// equality.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StrictAccountId([u8; STRICT_ACCOUNT_ID_BYTES_LEN]);

impl StrictAccountId {
    /// Generates a new 128-bit Strict Account ID using the platform CSPRNG (`getrandom`).
    pub fn generate() -> Result<Self, CryptoError> {
        let mut id = Self([0_u8; STRICT_ACCOUNT_ID_BYTES_LEN]);
        OsEntropy.fill_random(&mut id.0)?;
        Ok(id)
    }

    /// Generates a new 128-bit Strict Account ID using a caller-supplied `CryptoRng`.
    #[must_use]
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut id = Self([0_u8; STRICT_ACCOUNT_ID_BYTES_LEN]);
        rng.fill_bytes(&mut id.0);
        id
    }

    /// Constructs a Strict Account ID from a 16-byte slice directly into `ZeroizeOnDrop` storage.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != STRICT_ACCOUNT_ID_BYTES_LEN {
            return Err(CryptoError::InvalidAccountIdFormat);
        }
        let mut id = Self([0_u8; STRICT_ACCOUNT_ID_BYTES_LEN]);
        id.0.copy_from_slice(slice);
        Ok(id)
    }

    /// Constructs a Strict Account ID from 16 raw bytes, zeroizing the callee's parameter copy.
    ///
    /// Note: `[u8; 16]` is `Copy`, so callers holding live secrets should prefer
    /// [`Self::from_slice`] backed by a [`Zeroizing`] buffer.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; STRICT_ACCOUNT_ID_BYTES_LEN]) -> Self {
        let mut id = Self([0_u8; STRICT_ACCOUNT_ID_BYTES_LEN]);
        id.0.copy_from_slice(&bytes);
        bytes.zeroize();
        id
    }

    /// Returns a reference to the 16-byte raw entropy.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STRICT_ACCOUNT_ID_BYTES_LEN] {
        &self.0
    }

    /// Formats the Account ID as 28 uppercase Crockford Base32 characters without hyphens.
    #[must_use]
    pub fn to_compact_string(&self) -> Zeroizing<String> {
        let chars = encode_symbols(&self.0);
        let mut out = Zeroizing::new(String::with_capacity(STRICT_ACCOUNT_ID_TOTAL_CHARS));
        for &b in chars.iter() {
            out.push(char::from(b));
        }
        out
    }

    /// Formats the Account ID in canonical display form (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`).
    #[must_use]
    pub fn to_formatted_string(&self) -> Zeroizing<String> {
        let chars = encode_symbols(&self.0);
        let mut out = Zeroizing::new(String::with_capacity(STRICT_ACCOUNT_ID_FORMATTED_LEN));
        for (idx, &b) in chars.iter().enumerate() {
            if idx > 0 && idx % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(b));
        }
        out
    }

    /// Parses and validates a Crockford Base32 Strict Account ID string.
    ///
    /// - Ignores ASCII whitespace (`u8::is_ascii_whitespace`) and hyphens (`-`).
    /// - Case-insensitively normalizes `i`/`l` -> `1` and `o` -> `0`; rejects `u`/`U`.
    /// - Requires exactly 28 Crockford characters and canonical top 2 pad bits `00` (`sym[0] <= 7`).
    /// - Verifies the 2-char (10-bit) `BLAKE3_derive_key` checksum in constant time.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        if input.len() > STRICT_ACCOUNT_ID_MAX_INPUT_LEN {
            return Err(CryptoError::InvalidAccountIdFormat);
        }

        let mut cleaned = Zeroizing::new([0_u8; STRICT_ACCOUNT_ID_TOTAL_CHARS]);
        let mut count = 0_usize;
        for &b in input.as_bytes() {
            if b.is_ascii_whitespace() || b == b'-' {
                continue;
            }
            if count >= STRICT_ACCOUNT_ID_TOTAL_CHARS {
                return Err(CryptoError::InvalidAccountIdFormat);
            }
            cleaned[count] = b;
            count += 1;
        }
        if count != STRICT_ACCOUNT_ID_TOTAL_CHARS {
            return Err(CryptoError::InvalidAccountIdFormat);
        }

        let mut symbols = Zeroizing::new([0_u8; STRICT_ACCOUNT_ID_TOTAL_CHARS]);
        let mut all_valid = Choice::from(1_u8);
        for (dst, &byte) in symbols.iter_mut().zip(cleaned.iter()) {
            let (ok, sym) = ct_decode_crockford_char(byte);
            all_valid &= ok;
            *dst = sym;
        }

        // Canonical bijective encoding requires the top 2 pad bits of the first 5-bit symbol to be 00.
        let pad_zero = (symbols[0] & 0b11000_u8).ct_eq(&0_u8);
        if !bool::from(all_valid & pad_zero) {
            return Err(CryptoError::InvalidAccountIdFormat);
        }

        let mut id = Self([0_u8; STRICT_ACCOUNT_ID_BYTES_LEN]);
        let mut buf = Zeroizing::new(u16::from(symbols[0] & 0x07));
        let mut bits = 3_u32;
        let mut out_idx = 0_usize;
        for &sym in symbols
            .iter()
            .skip(1)
            .take(STRICT_ACCOUNT_ID_DATA_CHARS - 1)
        {
            *buf = (*buf << 5) | u16::from(sym);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                id.0[out_idx] = u8::try_from((*buf >> bits) & 0xFF).unwrap_or(0);
                out_idx += 1;
            }
        }

        let expected_chk = Zeroizing::new(compute_checksum_symbols(&id.0));
        if !bool::from(expected_chk.as_slice().ct_eq(&symbols[26..28])) {
            return Err(CryptoError::InvalidAccountIdChecksum);
        }

        Ok(id)
    }

    /// Derives the 3 tenant-scoped, domain-separated client keys via `HKDF-SHA256`:
    /// 1. `auth_lookup_id` (`16 B`, `info = "sovret-v1-strict-lookup"`)
    /// 2. `auth_secret` (`32 B`, `info = "sovret-v1-strict-auth"`, OPAQUE password)
    /// 3. `customer_vault_seed` (`32 B`, `info = "sovret-v1-strict-vault"`)
    pub fn derive_keys(&self, tenant_id: &[u8; 16]) -> Result<StrictClientKeys, CryptoError> {
        let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(tenant_id.as_slice()), &self.0);
        prk.zeroize();

        let mut auth_lookup_id = Zeroizing::new([0_u8; 16]);
        hk.expand(STRICT_LOOKUP_INFO, auth_lookup_id.as_mut())
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let auth_secret = SymmetricKey::init_with(|okm| {
            hk.expand(STRICT_AUTH_INFO, okm)
                .map_err(|_| CryptoError::KeyDerivationFailed)
        })?;

        let customer_vault_seed = SymmetricKey::init_with(|okm| {
            hk.expand(STRICT_VAULT_INFO, okm)
                .map_err(|_| CryptoError::KeyDerivationFailed)
        })?;

        let mut keys = StrictClientKeys {
            tenant_id: *tenant_id,
            auth_lookup_id: [0_u8; 16],
            auth_secret,
            customer_vault_seed,
        };
        keys.auth_lookup_id.copy_from_slice(auth_lookup_id.as_ref());
        Ok(keys)
    }

    /// Convenience helper deriving the buyer's full browser-only `X-Wing + Ed25519` vault keypairs
    /// scoped to `tenant_id`.
    pub fn derive_vault(&self, tenant_id: &[u8; 16]) -> Result<StrictCustomerVault, CryptoError> {
        self.derive_keys(tenant_id)?.derive_vault()
    }
}

impl fmt::Debug for StrictAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StrictAccountId([REDACTED])")
    }
}

impl PartialEq for StrictAccountId {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for StrictAccountId {}

/// The 3 tenant-scoped client keys derived from a [`StrictAccountId`] inside browser WASM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StrictClientKeys {
    tenant_id: [u8; 16],
    auth_lookup_id: [u8; 16],
    auth_secret: SymmetricKey,
    customer_vault_seed: SymmetricKey,
}

impl StrictClientKeys {
    #[must_use]
    pub const fn tenant_id(&self) -> &[u8; 16] {
        &self.tenant_id
    }

    /// 16-byte client lookup identifier sent to the server to index the account under `kms_pepper`.
    #[must_use]
    pub const fn auth_lookup_id(&self) -> &[u8; 16] {
        &self.auth_lookup_id
    }

    /// 32-byte OPAQUE client password (never transmitted to the server).
    #[must_use]
    pub const fn auth_secret(&self) -> &SymmetricKey {
        &self.auth_secret
    }

    /// 32-byte seed used exclusively inside browser WASM to derive buyer vault keypairs.
    #[must_use]
    pub const fn customer_vault_seed(&self) -> &SymmetricKey {
        &self.customer_vault_seed
    }

    /// Expands `customer_vault_seed` into domain-separated buyer `X-Wing` and `Ed25519` keypairs
    /// bound to `self.tenant_id`.
    pub fn derive_vault(&self) -> Result<StrictCustomerVault, CryptoError> {
        let (mut prk, hk) = Hkdf::<Sha256>::extract(
            Some(self.tenant_id.as_slice()),
            self.customer_vault_seed.as_bytes(),
        );
        prk.zeroize();

        let mut xwing_seed = Zeroizing::new([0_u8; 32]);
        hk.expand(STRICT_VAULT_XWING_INFO, xwing_seed.as_mut())
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let mut ed25519_seed = Zeroizing::new([0_u8; 32]);
        hk.expand(STRICT_VAULT_ED25519_INFO, ed25519_seed.as_mut())
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let (xwing_secret, xwing_public) = XWingSecretKey::from_seed_slice(xwing_seed.as_slice())?;
        let (ed25519_signing, ed25519_verifying) =
            Ed25519SigningKey::from_seed_slice(ed25519_seed.as_slice())?;

        Ok(StrictCustomerVault {
            xwing_secret,
            xwing_public,
            ed25519_signing,
            ed25519_verifying,
        })
    }
}

impl fmt::Debug for StrictClientKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictClientKeys")
            .field("tenant_id", &self.tenant_id)
            .field("auth_lookup_id", &"[REDACTED]")
            .field("auth_secret", &"[REDACTED]")
            .field("customer_vault_seed", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for StrictClientKeys {
    fn eq(&self, other: &Self) -> bool {
        let eq = self.tenant_id.ct_eq(&other.tenant_id)
            & self.auth_lookup_id.ct_eq(&other.auth_lookup_id)
            & self
                .auth_secret
                .as_bytes()
                .ct_eq(other.auth_secret.as_bytes())
            & self
                .customer_vault_seed
                .as_bytes()
                .ct_eq(other.customer_vault_seed.as_bytes());
        bool::from(eq)
    }
}

impl Eq for StrictClientKeys {}

/// Browser-only buyer keypairs derived deterministically from a Strict Account ID's
/// `customer_vault_seed` for dual-wrapped Strict orders, portal messaging, and VIP membership.
pub struct StrictCustomerVault {
    xwing_secret: XWingSecretKey,
    xwing_public: XWingPublicKey,
    ed25519_signing: Ed25519SigningKey,
    ed25519_verifying: Ed25519VerifyingKey,
}

impl ZeroizeOnDrop for StrictCustomerVault {}

impl StrictCustomerVault {
    #[must_use]
    pub const fn xwing_secret(&self) -> &XWingSecretKey {
        &self.xwing_secret
    }

    #[must_use]
    pub const fn xwing_public(&self) -> &XWingPublicKey {
        &self.xwing_public
    }

    #[must_use]
    pub const fn ed25519_signing(&self) -> &Ed25519SigningKey {
        &self.ed25519_signing
    }

    #[must_use]
    pub const fn ed25519_verifying(&self) -> &Ed25519VerifyingKey {
        &self.ed25519_verifying
    }

    /// Builds an `RCENC` / `RCSTR` [`RecipientSpec`] targeting this customer's `XWingCustomerVault`.
    #[must_use]
    pub fn recipient_spec(&self, key_version: u32) -> RecipientSpec<'_> {
        RecipientSpec::XWing {
            recipient_type: RecipientType::XWingCustomerVault,
            key_id: self.xwing_public.key_id(),
            key_version,
            public_key: &self.xwing_public,
        }
    }

    /// Builds an `RCENC` / `RCSTR` [`RecipientCredential`] to decrypt envelopes wrapped to this
    /// customer's `XWingCustomerVault`.
    #[must_use]
    pub fn recipient_credential(&self, key_version: u32) -> RecipientCredential<'_> {
        RecipientCredential::XWing {
            recipient_type: RecipientType::XWingCustomerVault,
            key_id: self.xwing_public.key_id(),
            key_version,
            secret_key: &self.xwing_secret,
        }
    }
}

impl fmt::Debug for StrictCustomerVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictCustomerVault")
            .field("xwing_secret", &self.xwing_secret)
            .field("xwing_public", &self.xwing_public)
            .field("ed25519_signing", &self.ed25519_signing)
            .field("ed25519_verifying", &self.ed25519_verifying)
            .finish()
    }
}

/// Computes the 32-byte server-side indexed lookup digest for a Strict Account:
/// `BLAKE3_keyed(kms_pepper, tenant_id || auth_lookup_id)`.
#[must_use]
pub fn compute_strict_lookup_index(
    kms_pepper: &SymmetricKey,
    tenant_id: &[u8; 16],
    auth_lookup_id: &[u8; 16],
) -> [u8; 32] {
    let mut msg = Zeroizing::new([0_u8; 32]);
    msg[0..16].copy_from_slice(tenant_id);
    msg[16..32].copy_from_slice(auth_lookup_id);
    *blake3::keyed_hash(kms_pepper.as_bytes(), msg.as_ref()).as_bytes()
}

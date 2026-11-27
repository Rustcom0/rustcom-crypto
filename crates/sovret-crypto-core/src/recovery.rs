use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bip39_wordlist::BIP39_ENGLISH;
use crate::rcenc::{
    AEAD_TAG_LEN, RecipientCredential, RecipientSpec, decrypt_parsed, encrypt_with_entropy,
    parse_envelope,
};
use crate::xwing::{EntropySource, OsEntropy, RngEntropy, XWING_SECRET_SEED_LEN};
use crate::{
    CryptoError, ED25519_SECRET_SEED_LEN, Ed25519SigningKey, EnvelopeContext, EnvelopeFlags,
    EnvelopeKind, PrivacyTier, RecipientType, SymmetricKey, VaultRole, XWingSecretKey,
};

/// Raw entropy length of a `RecoveryMasterSecret` (`256 bits = 32 B`).
pub const RECOVERY_SECRET_LEN: usize = 32;
/// Number of English words in a 256-bit BIP-39 Recovery Kit phrase (`24` words).
pub const BIP39_WORD_COUNT: usize = 24;
/// Maximum accepted byte length of a user-entered BIP-39 phrase to bound untrusted input work.
pub const BIP39_MAX_INPUT_LEN: usize = 512;
/// Maximum ASCII character length of any official BIP-39 English word (`8` bytes).
const BIP39_MAX_WORD_LEN: usize = 8;

/// HKDF `info` deriving the 32-byte `RecoveryKEK` from `RecoveryMasterSecret` and `tenant_id`.
pub const RECOVERY_KEK_INFO: &[u8] = b"sovret-v1-recovery-kek";

/// `RCENC` `schema_version` (`1`) for `RCREC` v1 disaster-recovery backups.
pub const RECOVERY_BACKUP_SCHEMA_VERSION: u16 = 1;
/// Inner payload magic for `RCREC` v1 recovery bundles (`"RCREC"`).
pub const RECOVERY_BACKUP_MAGIC: &[u8; 5] = b"RCREC";
/// Inner payload version for `RCREC` v1 (`0x01`).
pub const RECOVERY_BACKUP_VERSION_V1: u8 = 0x01;
/// Maximum role-split org keys inside one `RCREC` bundle (`OrgMaster`, `Fulfillment`, `Accounting`).
pub const RECOVERY_BACKUP_MAX_KEYS: usize = 3;
/// Fixed header size of `RCREC` v1 before the per-key entries (`59 B`):
/// `"RCREC"[5] || ver[1] || tenant_id[16] || recovery_ver[4 BE] || identity_ed25519_seed[32] || count[1]`.
pub const RECOVERY_BACKUP_HEADER_LEN: usize = 5 + 1 + 16 + 4 + ED25519_SECRET_SEED_LEN + 1;
/// Fixed size of each `(vault_role[1] || key_version[4 BE] || xwing_seed[32])` entry (`37 B`).
pub const RECOVERY_BACKUP_ENTRY_LEN: usize = 1 + 4 + XWING_SECRET_SEED_LEN;

// Compile-time check ensuring RecoveryBundle and RecoveredOrgKey maintain ZeroizeOnDrop.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<RecoveryMasterSecret>();
    assert_zeroize_on_drop::<RecoveredOrgKey>();
    assert_zeroize_on_drop::<RecoveryBundle>();
};

/// Constant-time lookup of an 11-bit BIP-39 word index (`0..2048`) returning the zero-padded
/// 8-byte lowercase ASCII word without secret-dependent table indexing.
fn ct_bip39_word(index: u16) -> Zeroizing<[u8; BIP39_MAX_WORD_LEN]> {
    let mut out = Zeroizing::new([0_u8; BIP39_MAX_WORD_LEN]);
    for (i, entry) in BIP39_ENGLISH.iter().enumerate() {
        let i_u16 = u16::try_from(i).unwrap_or(0);
        let eq = index.ct_eq(&i_u16);
        for (dst, &src) in out.iter_mut().zip(entry.iter()) {
            *dst = u8::conditional_select(dst, &src, eq);
        }
    }
    out
}

/// Branchless constant-time lookup of a zero-padded 8-byte lowercase ASCII word across all 2,048
/// BIP-39 English entries. Passed by reference intentionally to avoid unzeroized stack copies of
/// secret mnemonic words.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn ct_lookup_bip39_word(word: &[u8; BIP39_MAX_WORD_LEN]) -> (Choice, u16) {
    let mut found = Choice::from(0_u8);
    let mut matched_idx = 0_u16;
    for (i, entry) in BIP39_ENGLISH.iter().enumerate() {
        let eq = word.ct_eq(entry);
        let i_u16 = u16::try_from(i).unwrap_or(0);
        matched_idx = u16::conditional_select(&matched_idx, &i_u16, eq);
        found |= eq;
    }
    (found, matched_idx)
}

/// Branchless ASCII letter check + lowercasing (`A..=Z -> a..=z`), rejecting digits, punctuation,
/// NUL bytes (`0x00`), and non-ASCII bytes so padding bytes can never be spoofed.
fn ct_ascii_alpha_lower(byte: u8) -> (Choice, u8) {
    let (_, is_upper_b) = byte.wrapping_sub(b'A').overflowing_sub(26);
    let (_, is_lower_b) = byte.wrapping_sub(b'a').overflowing_sub(26);
    let is_upper = Choice::from(u8::from(is_upper_b));
    let is_lower = Choice::from(u8::from(is_lower_b));
    let lower = u8::conditional_select(&byte, &byte.wrapping_add(32), is_upper);
    (is_upper | is_lower, lower)
}

/// 256-bit Store Recovery Master Secret encoded as a standard 24-word BIP-39 English mnemonic
/// and optionally split via `GF(256)` Shamir secret sharing.
///
/// Automatically zeroizes on drop, redacts `Debug`, and compares in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryMasterSecret([u8; RECOVERY_SECRET_LEN]);

impl RecoveryMasterSecret {
    /// Generates a fresh 256-bit `RecoveryMasterSecret` using the platform CSPRNG (`getrandom`).
    pub fn generate() -> Result<Self, CryptoError> {
        let mut secret = Self([0_u8; RECOVERY_SECRET_LEN]);
        OsEntropy.fill_random(&mut secret.0)?;
        Ok(secret)
    }

    /// Generates a fresh 256-bit `RecoveryMasterSecret` using a caller-supplied `CryptoRng`.
    #[must_use]
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut secret = Self([0_u8; RECOVERY_SECRET_LEN]);
        rng.fill_bytes(&mut secret.0);
        secret
    }

    /// Constructs a `RecoveryMasterSecret` directly from a 32-byte slice inside `ZeroizeOnDrop` storage.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != RECOVERY_SECRET_LEN {
            return Err(CryptoError::InvalidSecretKey);
        }
        let mut secret = Self([0_u8; RECOVERY_SECRET_LEN]);
        secret.0.copy_from_slice(slice);
        Ok(secret)
    }

    /// Constructs a `RecoveryMasterSecret` from 32 raw bytes, zeroizing the callee's parameter copy.
    ///
    /// Prefer [`Self::from_slice`] backed by a [`Zeroizing`] buffer for live secrets.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; RECOVERY_SECRET_LEN]) -> Self {
        let mut secret = Self([0_u8; RECOVERY_SECRET_LEN]);
        secret.0.copy_from_slice(&bytes);
        bytes.zeroize();
        secret
    }

    /// Returns a reference to the 32-byte master recovery secret.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RECOVERY_SECRET_LEN] {
        &self.0
    }

    /// Encodes the 256-bit secret + 8-bit `SHA-256` checksum into a canonical 24-word BIP-39
    /// English mnemonic phrase wrapped in [`Zeroizing`], using constant-time wordlist lookups.
    #[must_use]
    pub fn to_mnemonic(&self) -> Zeroizing<String> {
        let digest = Zeroizing::new(Sha256::digest(self.0.as_slice()));
        let checksum_byte = digest[0];

        let mut buf = Zeroizing::new(0_u32);
        let mut bits = 0_u32;
        let mut indices = Zeroizing::new([0_u16; BIP39_WORD_COUNT]);
        let mut out_idx = 0_usize;

        for &byte in self.0.iter().chain(core::iter::once(&checksum_byte)) {
            *buf = (*buf << 8) | u32::from(byte);
            bits += 8;
            while bits >= 11 {
                bits -= 11;
                indices[out_idx] = u16::try_from((*buf >> bits) & 0x07FF).unwrap_or(0);
                out_idx += 1;
            }
        }

        // Max length of 24 words (<= 8 chars each) + 23 spaces = 215 bytes.
        let mut phrase = Zeroizing::new(String::with_capacity(215));
        for (word_pos, &word_idx) in indices.iter().enumerate() {
            if word_pos > 0 {
                phrase.push(' ');
            }
            let word = ct_bip39_word(word_idx);
            for &b in word.iter() {
                if b != 0 {
                    phrase.push(char::from(b));
                }
            }
        }
        phrase
    }

    /// Parses and validates a 24-word BIP-39 English mnemonic phrase in constant time.
    ///
    /// - Tolerates leading/trailing/repeated ASCII whitespace and uppercase ASCII letters.
    /// - Strictly rejects non-ASCII bytes, digits, punctuation, NUL bytes, wrong word counts,
    ///   unknown BIP-39 words, and invalid 8-bit `SHA-256` checksums.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, CryptoError> {
        if phrase.len() > BIP39_MAX_INPUT_LEN {
            return Err(CryptoError::InvalidMnemonicFormat);
        }

        let mut packed_words = Zeroizing::new([[0_u8; BIP39_MAX_WORD_LEN]; BIP39_WORD_COUNT]);
        let mut word_count = 0_usize;
        let mut in_word = false;
        let mut char_pos = 0_usize;
        let mut all_chars_valid = Choice::from(1_u8);

        for &byte in phrase.as_bytes() {
            if byte.is_ascii_whitespace() {
                if in_word {
                    in_word = false;
                    char_pos = 0;
                    word_count += 1;
                }
                continue;
            }
            if !in_word {
                if word_count >= BIP39_WORD_COUNT {
                    return Err(CryptoError::InvalidMnemonicFormat);
                }
                in_word = true;
                char_pos = 0;
            }
            if char_pos >= BIP39_MAX_WORD_LEN {
                return Err(CryptoError::InvalidMnemonicFormat);
            }
            let (is_alpha, lower) = ct_ascii_alpha_lower(byte);
            all_chars_valid &= is_alpha;
            packed_words[word_count][char_pos] = lower;
            char_pos += 1;
        }
        if in_word {
            word_count += 1;
        }

        if word_count != BIP39_WORD_COUNT || !bool::from(all_chars_valid) {
            return Err(CryptoError::InvalidMnemonicFormat);
        }

        let mut indices = Zeroizing::new([0_u16; BIP39_WORD_COUNT]);
        let mut all_words_found = Choice::from(1_u8);
        for (dst, word) in indices.iter_mut().zip(packed_words.iter()) {
            let (found, idx) = ct_lookup_bip39_word(word);
            all_words_found &= found;
            *dst = idx;
        }
        if !bool::from(all_words_found) {
            return Err(CryptoError::InvalidMnemonicFormat);
        }

        let mut raw_33 = Zeroizing::new([0_u8; RECOVERY_SECRET_LEN + 1]);
        let mut buf = Zeroizing::new(0_u32);
        let mut bits = 0_u32;
        let mut out_idx = 0_usize;

        for &word_idx in indices.iter() {
            *buf = (*buf << 11) | u32::from(word_idx);
            bits += 11;
            while bits >= 8 {
                bits -= 8;
                raw_33[out_idx] = u8::try_from((*buf >> bits) & 0xFF).unwrap_or(0);
                out_idx += 1;
            }
        }

        let digest = Zeroizing::new(Sha256::digest(&raw_33[..RECOVERY_SECRET_LEN]));
        let expected_chk = digest[0];
        let provided_chk = raw_33[RECOVERY_SECRET_LEN];
        if !bool::from(provided_chk.ct_eq(&expected_chk)) {
            return Err(CryptoError::InvalidMnemonicChecksum);
        }

        Self::from_slice(&raw_33[..RECOVERY_SECRET_LEN])
    }

    /// Derives the tenant-scoped 32-byte `RecoveryKEK`:
    /// `HKDF-SHA256(ikm = secret[32B], salt = tenant_id[16B], info = "sovret-v1-recovery-kek")`.
    pub fn derive_recovery_kek(&self, tenant_id: &[u8; 16]) -> Result<SymmetricKey, CryptoError> {
        let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(tenant_id.as_slice()), &self.0);
        prk.zeroize();
        SymmetricKey::init_with(|okm| {
            hk.expand(RECOVERY_KEK_INFO, okm)
                .map_err(|_| CryptoError::KeyDerivationFailed)
        })
    }
}

impl fmt::Debug for RecoveryMasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryMasterSecret([REDACTED])")
    }
}

impl PartialEq for RecoveryMasterSecret {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for RecoveryMasterSecret {}

/// Borrowed store organization key entry supplied when creating an `RCREC` v1 recovery backup.
pub struct OrgKeyBackupEntry<'a> {
    pub vault_role: VaultRole,
    pub key_version: u32,
    pub xwing_secret: &'a XWingSecretKey,
}

/// Recovered role-split store organization key unwrapped from an `RCREC` v1 backup.
pub struct RecoveredOrgKey {
    vault_role: VaultRole,
    key_version: u32,
    xwing_secret: XWingSecretKey,
}

impl ZeroizeOnDrop for RecoveredOrgKey {}

impl RecoveredOrgKey {
    #[must_use]
    pub const fn vault_role(&self) -> VaultRole {
        self.vault_role
    }

    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    #[must_use]
    pub const fn xwing_secret(&self) -> &XWingSecretKey {
        &self.xwing_secret
    }
}

impl fmt::Debug for RecoveredOrgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredOrgKey")
            .field("vault_role", &self.vault_role)
            .field("key_version", &self.key_version)
            .field("xwing_secret", &self.xwing_secret)
            .finish()
    }
}

/// Full store cryptographic material recovered from a BIP-39 / Shamir `RCREC` v1 backup.
///
/// Restores both the store's `StoreIdentity_Ed25519` signing key (to sign subsequent SKL
/// rotations) and its active role-split `X-Wing` organization keys.
pub struct RecoveryBundle {
    tenant_id: [u8; 16],
    recovery_version: u32,
    store_identity_sk: Ed25519SigningKey,
    org_keys: Vec<RecoveredOrgKey>,
}

impl ZeroizeOnDrop for RecoveryBundle {}

impl RecoveryBundle {
    #[must_use]
    pub const fn tenant_id(&self) -> &[u8; 16] {
        &self.tenant_id
    }

    #[must_use]
    pub const fn recovery_version(&self) -> u32 {
        self.recovery_version
    }

    #[must_use]
    pub const fn store_identity_sk(&self) -> &Ed25519SigningKey {
        &self.store_identity_sk
    }

    #[must_use]
    pub fn org_keys(&self) -> &[RecoveredOrgKey] {
        &self.org_keys
    }

    /// Convenience lookup for a recovered role key inside this bundle.
    #[must_use]
    pub fn org_key_for_role(&self, role: VaultRole) -> Option<&RecoveredOrgKey> {
        self.org_keys.iter().find(|k| k.vault_role == role)
    }
}

impl fmt::Debug for RecoveryBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryBundle")
            .field("tenant_id", &self.tenant_id)
            .field("recovery_version", &self.recovery_version)
            .field("store_identity_sk", &self.store_identity_sk)
            .field("org_keys", &self.org_keys)
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
fn wrap_recovery_backup_with_entropy<E: EntropySource>(
    entropy: &mut E,
    recovery_secret: &RecoveryMasterSecret,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    recovery_version: u32,
    store_identity_sk: &Ed25519SigningKey,
    org_keys: &[OrgKeyBackupEntry<'_>],
) -> Result<Vec<u8>, CryptoError> {
    if recovery_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    if org_keys.is_empty() || org_keys.len() > RECOVERY_BACKUP_MAX_KEYS {
        return Err(CryptoError::InvalidRecoveryPayload);
    }

    let mut seen_roles = [false; 3];
    let mut seen_pk_hashes = [[0_u8; 32]; RECOVERY_BACKUP_MAX_KEYS];
    for (idx, entry) in org_keys.iter().enumerate() {
        if entry.key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        let r_idx = entry.vault_role.index();
        if seen_roles[r_idx] {
            return Err(CryptoError::InvalidRecoveryPayload);
        }
        seen_roles[r_idx] = true;

        let pk_hash = crate::staff_grant::hash_xwing_public_key(&entry.xwing_secret.public_key());
        if seen_pk_hashes[..idx]
            .iter()
            .any(|prev| bool::from(prev.ct_eq(&pk_hash)))
        {
            return Err(CryptoError::InvalidRecoveryPayload);
        }
        seen_pk_hashes[idx] = pk_hash;
    }

    let payload_len = RECOVERY_BACKUP_HEADER_LEN + org_keys.len() * RECOVERY_BACKUP_ENTRY_LEN;
    let mut payload = Zeroizing::new(Vec::with_capacity(payload_len));
    payload.extend_from_slice(RECOVERY_BACKUP_MAGIC);
    payload.push(RECOVERY_BACKUP_VERSION_V1);
    payload.extend_from_slice(&tenant_id);
    payload.extend_from_slice(&recovery_version.to_be_bytes());
    let id_seed = store_identity_sk.to_seed_bytes();
    payload.extend_from_slice(id_seed.as_ref());
    let key_count_u8 =
        u8::try_from(org_keys.len()).map_err(|_| CryptoError::InvalidRecoveryPayload)?;
    payload.push(key_count_u8);

    for entry in org_keys {
        payload.push(entry.vault_role.as_u8());
        payload.extend_from_slice(&entry.key_version.to_be_bytes());
        let sk_seed = entry.xwing_secret.to_seed_bytes();
        payload.extend_from_slice(sk_seed.as_ref());
    }

    let recovery_kek = recovery_secret.derive_recovery_kek(&tenant_id)?;
    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::RecoveryBackup,
        tenant_id,
        resource_id: tenant_id,
        privacy_tier,
        schema_version: RECOVERY_BACKUP_SCHEMA_VERSION,
    };
    let recipient = RecipientSpec::SymmetricKek {
        recipient_type: RecipientType::RecoveryBip39,
        key_id: tenant_id,
        key_version: recovery_version,
        kem_data: &[],
        kek: &recovery_kek,
    };

    encrypt_with_entropy(
        entropy,
        payload.as_slice(),
        &ctx,
        EnvelopeFlags::default(),
        &[recipient],
    )
}

/// Encrypts a store's `StoreIdentity_Ed25519_SK` and active role-split `StoreOrgKey`s (`1..=3`)
/// into an `RCENC(kind = RecoveryBackup, schema_version = 1)` (`RCREC` v1) envelope under
/// `RecoveryKEK`.
pub fn wrap_recovery_backup(
    recovery_secret: &RecoveryMasterSecret,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    recovery_version: u32,
    store_identity_sk: &Ed25519SigningKey,
    org_keys: &[OrgKeyBackupEntry<'_>],
) -> Result<Vec<u8>, CryptoError> {
    wrap_recovery_backup_with_entropy(
        &mut OsEntropy,
        recovery_secret,
        tenant_id,
        privacy_tier,
        recovery_version,
        store_identity_sk,
        org_keys,
    )
}

/// Deterministic `CryptoRng` variant of [`wrap_recovery_backup`] for KAT vectors and tests.
pub fn wrap_recovery_backup_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    recovery_secret: &RecoveryMasterSecret,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    recovery_version: u32,
    store_identity_sk: &Ed25519SigningKey,
    org_keys: &[OrgKeyBackupEntry<'_>],
) -> Result<Vec<u8>, CryptoError> {
    wrap_recovery_backup_with_entropy(
        &mut RngEntropy(rng),
        recovery_secret,
        tenant_id,
        privacy_tier,
        recovery_version,
        store_identity_sk,
        org_keys,
    )
}

fn parse_recovery_bundle_payload(
    pt: &[u8],
    expected_tenant_id: &[u8; 16],
    expected_recovery_version: u32,
) -> Result<RecoveryBundle, CryptoError> {
    if pt.len() < RECOVERY_BACKUP_HEADER_LEN {
        return Err(CryptoError::InvalidRecoveryPayload);
    }
    if pt[0..5] != *RECOVERY_BACKUP_MAGIC || pt[5] != RECOVERY_BACKUP_VERSION_V1 {
        return Err(CryptoError::InvalidRecoveryPayload);
    }

    let rec_ver = u32::from_be_bytes([pt[22], pt[23], pt[24], pt[25]]);
    let hdr_match = pt[6..22].ct_eq(expected_tenant_id)
        & rec_ver
            .to_be_bytes()
            .ct_eq(&expected_recovery_version.to_be_bytes());
    if !bool::from(hdr_match) {
        return Err(CryptoError::InvalidRecoveryPayload);
    }

    let (store_identity_sk, _) = Ed25519SigningKey::from_seed_slice(&pt[26..58])?;
    let key_count = usize::from(pt[58]);
    if key_count == 0
        || key_count > RECOVERY_BACKUP_MAX_KEYS
        || pt.len() != RECOVERY_BACKUP_HEADER_LEN + key_count * RECOVERY_BACKUP_ENTRY_LEN
    {
        return Err(CryptoError::InvalidRecoveryPayload);
    }

    let mut seen_roles = [false; 3];
    let mut seen_pk_hashes = [[0_u8; 32]; RECOVERY_BACKUP_MAX_KEYS];
    let mut org_keys = Vec::with_capacity(key_count);
    for idx in 0..key_count {
        let base = RECOVERY_BACKUP_HEADER_LEN + idx * RECOVERY_BACKUP_ENTRY_LEN;
        let vault_role = VaultRole::from_u8(pt[base])?;
        let r_idx = vault_role.index();
        if seen_roles[r_idx] {
            return Err(CryptoError::InvalidRecoveryPayload);
        }
        seen_roles[r_idx] = true;

        let key_version =
            u32::from_be_bytes([pt[base + 1], pt[base + 2], pt[base + 3], pt[base + 4]]);
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }

        let (xwing_secret, xwing_pk) = XWingSecretKey::from_seed_slice(&pt[base + 5..base + 37])?;
        let pk_hash = crate::staff_grant::hash_xwing_public_key(&xwing_pk);
        if seen_pk_hashes[..idx]
            .iter()
            .any(|prev| bool::from(prev.ct_eq(&pk_hash)))
        {
            return Err(CryptoError::InvalidRecoveryPayload);
        }
        seen_pk_hashes[idx] = pk_hash;

        org_keys.push(RecoveredOrgKey {
            vault_role,
            key_version,
            xwing_secret,
        });
    }

    Ok(RecoveryBundle {
        tenant_id: *expected_tenant_id,
        recovery_version: expected_recovery_version,
        store_identity_sk,
        org_keys,
    })
}

/// Decrypts and validates an `RCREC` v1 `RecoveryBackup` envelope using `recovery_secret`.
pub fn unwrap_recovery_backup(
    envelope_bytes: &[u8],
    recovery_secret: &RecoveryMasterSecret,
    expected_tenant_id: &[u8; 16],
    privacy_tier: PrivacyTier,
    expected_recovery_version: u32,
) -> Result<RecoveryBundle, CryptoError> {
    if expected_recovery_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }

    let parsed = parse_envelope(envelope_bytes)?;
    if parsed.header.flags.to_byte() != 0 {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::RecoveryBackup {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }
    if parsed.slots.len() != 1 {
        return Err(CryptoError::InvalidRecoveryPayload);
    }

    let min_ct_len = RECOVERY_BACKUP_HEADER_LEN + RECOVERY_BACKUP_ENTRY_LEN + AEAD_TAG_LEN;
    let max_ct_len = RECOVERY_BACKUP_HEADER_LEN
        + RECOVERY_BACKUP_MAX_KEYS * RECOVERY_BACKUP_ENTRY_LEN
        + AEAD_TAG_LEN;
    let ct_len = parsed.ciphertext.len();
    if ct_len < min_ct_len
        || ct_len > max_ct_len
        || !(ct_len - RECOVERY_BACKUP_HEADER_LEN - AEAD_TAG_LEN)
            .is_multiple_of(RECOVERY_BACKUP_ENTRY_LEN)
    {
        return Err(CryptoError::InvalidRecoveryPayload);
    }

    let recovery_kek = recovery_secret.derive_recovery_kek(expected_tenant_id)?;
    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::RecoveryBackup,
        tenant_id: *expected_tenant_id,
        resource_id: *expected_tenant_id,
        privacy_tier,
        schema_version: RECOVERY_BACKUP_SCHEMA_VERSION,
    };
    let cred = RecipientCredential::SymmetricKek {
        recipient_type: RecipientType::RecoveryBip39,
        key_id: *expected_tenant_id,
        key_version: expected_recovery_version,
        kek: &recovery_kek,
    };
    let decrypted = decrypt_parsed(&parsed, &ctx, &cred)?;
    parse_recovery_bundle_payload(
        decrypted.plaintext.as_slice(),
        expected_tenant_id,
        expected_recovery_version,
    )
}

#[cfg(test)]
mod wordlist_tests {
    use super::*;

    #[test]
    fn embedded_bip39_english_wordlist_matches_official_sha256() {
        // Official Bitcoin BIP-0039 english.txt SHA-256:
        // 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
        let expected: [u8; 32] = [
            0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19,
            0x9e, 0xfc, 0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed,
            0x3b, 0x24, 0xdb, 0xda,
        ];
        let mut hasher = Sha256::new();
        for entry in &BIP39_ENGLISH {
            let mut seen_zero = false;
            let mut len = 0_usize;
            for &b in entry {
                if b == 0 {
                    seen_zero = true;
                } else {
                    assert!(!seen_zero, "non-zero byte after zero padding");
                    assert!(b.is_ascii_lowercase(), "non-lowercase ASCII in wordlist");
                    hasher.update([b]);
                    len += 1;
                }
            }
            assert!((3..=8).contains(&len), "unexpected BIP-39 word length");
            hasher.update(b"\n");
        }
        let actual = hasher.finalize();
        assert_eq!(actual.as_slice(), expected.as_slice());
    }
}

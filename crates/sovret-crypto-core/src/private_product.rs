use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::rcenc::{
    AEAD_TAG_LEN, DecryptedEnvelope, MAX_RECIPIENTS, RecipientCredential, RecipientSpec, decrypt,
    decrypt_parsed, encrypt_with_entropy, parse_envelope, validate_payload_len,
    validate_recipients,
};
use crate::xwing::{EntropySource, OsEntropy, RngEntropy, XWING_SECRET_SEED_LEN};
use crate::{
    CryptoError, EnvelopeContext, EnvelopeFlags, EnvelopeKind, PrivacyTier, RecipientType,
    SymmetricKey, XWingPublicKey, XWingSecretKey,
};

/// Length of the per-product Argon2id random salt (`32 B`).
pub const ARGON2_SALT_LEN: usize = 32;
/// Exact `kem_data` wire length for `RecipientType::Argon2idPassword`:
/// `salt[32B] || m_cost_kib[4B BE] || t_cost[4B BE] || p_cost[4B BE] = 44 B`.
pub const ARGON2_KEM_DATA_LEN: usize = ARGON2_SALT_LEN + 12;

/// Protocol-specified default Argon2id memory cost (`65,536 KiB = 64 MiB`).
pub const DEFAULT_ARGON2_M_COST_KIB: u32 = 65_536;
/// Protocol-specified default Argon2id time cost (`3` iterations).
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
/// Protocol-specified default Argon2id parallelism (`1` lane for deterministic WASM execution).
pub const DEFAULT_ARGON2_P_COST: u32 = 1;

/// OWASP minimum Argon2id memory floor (`19,456 KiB = 19 MiB`) preventing downgrade attacks.
pub const MIN_ARGON2_M_COST_KIB: u32 = 19_456;
/// Maximum protocol Argon2id memory bound (`131,072 KiB = 128 MiB`) preventing OOM `DoS`.
pub const MAX_ARGON2_M_COST_KIB: u32 = 131_072;
/// Minimum Argon2id time cost (`2` iterations).
pub const MIN_ARGON2_T_COST: u32 = 2;
/// Maximum protocol Argon2id time cost (`8` iterations) preventing CPU `DoS`.
pub const MAX_ARGON2_T_COST: u32 = 8;
/// Minimum Argon2id parallelism (`1` lane).
pub const MIN_ARGON2_P_COST: u32 = 1;
/// Maximum protocol Argon2id parallelism (`4` lanes).
pub const MAX_ARGON2_P_COST: u32 = 4;
/// Maximum protocol Argon2id total work factor (`m_cost_kib * t_cost <= 128 MiB * 8`).
pub const MAX_ARGON2_WORK_KIB_ITERS: u64 = 1_048_576;

/// Tighter browser WASM client memory ceiling (`65,536 KiB = 64 MiB`) mitigating single-threaded
/// browser tab memory/CPU `DoS` from hostile password-protected Private Product envelopes.
pub const WASM_MAX_ARGON2_M_COST_KIB: u32 = 65_536;
/// Tighter browser WASM client iteration ceiling (`4` iterations).
pub const WASM_MAX_ARGON2_T_COST: u32 = 4;
/// Tighter browser WASM client lane ceiling (`2` lanes).
pub const WASM_MAX_ARGON2_P_COST: u32 = 2;
/// Tighter browser WASM client work-factor ceiling (`64 MiB * 4 = 262,144 KiB-iters`).
pub const WASM_MAX_ARGON2_WORK_KIB_ITERS: u64 = 262_144;
/// Maximum accepted private product password length in bytes (`1,024 B`).
pub const MAX_PASSWORD_LEN: usize = 1_024;

/// Reserved `schema_version` (`0x8001`) domain-separating wrapped `RCVIP` VIP group keys from
/// Private Product metadata envelopes within `EnvelopeKind::PrivateProduct`.
pub const VIP_GROUP_KEY_WRAP_SCHEMA_VERSION: u16 = 0x8001;
/// 5-byte magic prefix inside wrapped VIP group key payloads (`"RCVIP"`).
pub const VIP_KEY_WRAP_MAGIC: &[u8; 5] = b"RCVIP";
/// Version byte for `RCVIP` wrapped VIP group key payloads (`0x01`).
pub const VIP_KEY_WRAP_VERSION_V1: u8 = 0x01;
/// Exact byte length of an `RCVIP` v1 inner payload:
/// `"RCVIP"[5] || ver[1] || tenant_id[16] || vip_group_id[16] || key_version[4] || seed[32] = 74 B`.
pub const VIP_KEY_WRAP_PAYLOAD_LEN: usize = 5 + 1 + 16 + 16 + 4 + XWING_SECRET_SEED_LEN;

/// Version byte for `#k=...` VIP invite URL fragments (`0x01`).
pub const VIP_FRAGMENT_VERSION_V1: u8 = 0x01;
/// Exact raw binary length of a `#k=...` VIP invite payload (`39 B`, multiple of 3 -> 0 pad bits):
/// `version[1] || key_version[4 BE] || vip_group_seed[32] || blake3_chk[2]`.
pub const VIP_FRAGMENT_RAW_LEN: usize = 1 + 4 + XWING_SECRET_SEED_LEN + 2;
/// Exact Base64URL-unpadded character length of a `#k=...` token (`52` chars).
pub const VIP_FRAGMENT_TOKEN_LEN: usize = 52;
/// Maximum input string length accepted by [`VipInviteFragment::parse_url_fragment`].
pub const VIP_FRAGMENT_MAX_INPUT_LEN: usize = 512;
/// Domain-separation context for the 16-bit `BLAKE3_derive_key` VIP invite fragment checksum.
pub const VIP_FRAGMENT_CHK_CONTEXT: &str = "sovret-v1-vip-fragment-chk";

/// Client-side upper-bound resource budget for Argon2id Private Product decryption.
///
/// Use [`Self::WASM_CLIENT`] in single-threaded browser WASM contexts to bound memory/CPU `DoS`
/// from untrusted envelopes while keeping [`Self::PROTOCOL_MAX`] available for native clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idBudget {
    pub max_m_cost_kib: u32,
    pub max_t_cost: u32,
    pub max_p_cost: u32,
    pub max_work_kib_iters: u64,
}

impl Argon2idBudget {
    /// Full protocol ceiling (`m <= 128 MiB`, `t <= 8`, `p <= 4`, `m * t <= 1,048,576 KiB-iters`).
    pub const PROTOCOL_MAX: Self = Self {
        max_m_cost_kib: MAX_ARGON2_M_COST_KIB,
        max_t_cost: MAX_ARGON2_T_COST,
        max_p_cost: MAX_ARGON2_P_COST,
        max_work_kib_iters: MAX_ARGON2_WORK_KIB_ITERS,
    };

    /// Stricter browser WASM budget (`m <= 64 MiB`, `t <= 4`, `p <= 2`, `m * t <= 262,144 KiB-iters`).
    pub const WASM_CLIENT: Self = Self {
        max_m_cost_kib: WASM_MAX_ARGON2_M_COST_KIB,
        max_t_cost: WASM_MAX_ARGON2_T_COST,
        max_p_cost: WASM_MAX_ARGON2_P_COST,
        max_work_kib_iters: WASM_MAX_ARGON2_WORK_KIB_ITERS,
    };
}

/// Bounded Argon2id KDF cost parameters for Private Product password slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Argon2idParams {
    /// Spec default: `m = 65,536 KiB` (64 MiB), `t = 3`, `p = 1`.
    pub const DEFAULT: Self = Self {
        m_cost_kib: DEFAULT_ARGON2_M_COST_KIB,
        t_cost: DEFAULT_ARGON2_T_COST,
        p_cost: DEFAULT_ARGON2_P_COST,
    };

    /// Validates and constructs bounded Argon2id parameters, rejecting downgrade or `DoS` values.
    pub const fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        if m_cost_kib < MIN_ARGON2_M_COST_KIB || m_cost_kib > MAX_ARGON2_M_COST_KIB {
            return Err(CryptoError::InvalidArgon2Params);
        }
        if t_cost < MIN_ARGON2_T_COST || t_cost > MAX_ARGON2_T_COST {
            return Err(CryptoError::InvalidArgon2Params);
        }
        if p_cost < MIN_ARGON2_P_COST || p_cost > MAX_ARGON2_P_COST {
            return Err(CryptoError::InvalidArgon2Params);
        }
        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
        })
    }

    /// Checks that these parameters fit inside a stricter client-side [`Argon2idBudget`].
    pub const fn check_budget(self, budget: Argon2idBudget) -> Result<(), CryptoError> {
        let work = (self.m_cost_kib as u64).saturating_mul(self.t_cost as u64);
        if self.m_cost_kib > budget.max_m_cost_kib
            || self.t_cost > budget.max_t_cost
            || self.p_cost > budget.max_p_cost
            || work > budget.max_work_kib_iters
        {
            return Err(CryptoError::InvalidArgon2Params);
        }
        Ok(())
    }

    #[must_use]
    pub const fn m_cost_kib(self) -> u32 {
        self.m_cost_kib
    }

    #[must_use]
    pub const fn t_cost(self) -> u32 {
        self.t_cost
    }

    #[must_use]
    pub const fn p_cost(self) -> u32 {
        self.p_cost
    }
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Canonical 44-byte `kem_data` payload stored in `RecipientType::Argon2idPassword` slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idKemData {
    salt: [u8; ARGON2_SALT_LEN],
    params: Argon2idParams,
}

impl Argon2idKemData {
    /// Constructs validated `Argon2idKemData`, rejecting an all-zero salt.
    pub fn new(salt: [u8; ARGON2_SALT_LEN], params: Argon2idParams) -> Result<Self, CryptoError> {
        if bool::from(salt.ct_eq(&[0_u8; ARGON2_SALT_LEN])) {
            return Err(CryptoError::InvalidArgon2Params);
        }
        Ok(Self { salt, params })
    }

    /// Parses and bounds-checks a 44-byte `Argon2idPassword` slot `kem_data` buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ARGON2_KEM_DATA_LEN {
            return Err(CryptoError::InvalidKemDataLength {
                expected: ARGON2_KEM_DATA_LEN,
                actual: bytes.len(),
            });
        }
        let mut salt = [0_u8; ARGON2_SALT_LEN];
        salt.copy_from_slice(&bytes[0..ARGON2_SALT_LEN]);

        let m_cost_kib = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let t_cost = u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let p_cost = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        let params = Argon2idParams::new(m_cost_kib, t_cost, p_cost)?;

        Self::new(salt, params)
    }

    /// Encodes into the canonical 44-byte big-endian `kem_data` wire format.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ARGON2_KEM_DATA_LEN] {
        let mut out = [0_u8; ARGON2_KEM_DATA_LEN];
        out[0..ARGON2_SALT_LEN].copy_from_slice(&self.salt);
        out[32..36].copy_from_slice(&self.params.m_cost_kib.to_be_bytes());
        out[36..40].copy_from_slice(&self.params.t_cost.to_be_bytes());
        out[40..44].copy_from_slice(&self.params.p_cost.to_be_bytes());
        out
    }

    #[must_use]
    pub const fn salt(&self) -> &[u8; ARGON2_SALT_LEN] {
        &self.salt
    }

    #[must_use]
    pub const fn params(&self) -> Argon2idParams {
        self.params
    }
}

fn validate_password(password: &[u8]) -> Result<(), CryptoError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return Err(CryptoError::InvalidPassword);
    }
    Ok(())
}

fn validate_private_product_ctx(ctx: &EnvelopeContext) -> Result<(), CryptoError> {
    if ctx.envelope_kind != EnvelopeKind::PrivateProduct {
        return Err(CryptoError::InvalidEnvelopeKind(ctx.envelope_kind.as_u8()));
    }
    if ctx.schema_version == VIP_GROUP_KEY_WRAP_SCHEMA_VERSION {
        return Err(CryptoError::ReservedSchemaVersion(ctx.schema_version));
    }
    Ok(())
}

/// Derives the 32-byte Private Product password KEK directly into `ZeroizeOnDrop` storage via
/// `Argon2id(v0x13, password, kem_data.salt, m_cost_kib, t_cost, p_cost)`.
///
/// Callers decrypting a Private Product's metadata plus multiple `RCSTR` images/files should call
/// this once (using [`extract_password_slot`]) and reuse the returned [`SymmetricKey`].
pub fn derive_password_kek(
    password: &[u8],
    kem_data: &Argon2idKemData,
) -> Result<SymmetricKey, CryptoError> {
    validate_password(password)?;
    let argon_params = Params::new(
        kem_data.params.m_cost_kib,
        kem_data.params.t_cost,
        kem_data.params.p_cost,
        Some(32),
    )
    .map_err(|_| CryptoError::InvalidArgon2Params)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    SymmetricKey::init_with(|okm| {
        hasher
            .hash_password_into(password, &kem_data.salt, okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)
    })
}

/// Inspects an `RCENC` Private Product envelope and extracts the validated `(password_version, Argon2idKemData)`
/// for `product_id` without decrypting the payload.
///
/// Rejects `RCSTR` internal header flags, non-`PrivateProduct` envelopes, out-of-bounds Argon2id
/// parameters, and ambiguous duplicate `Argon2idPassword` slots for `product_id`.
pub fn extract_password_slot(
    envelope_bytes: &[u8],
    product_id: &[u8; 16],
) -> Result<(u32, Argon2idKemData), CryptoError> {
    let parsed = parse_envelope(envelope_bytes)?;
    if parsed.header.flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::PrivateProduct {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }

    let mut matched: Option<(u32, &[u8])> = None;
    for slot in &parsed.slots {
        if slot.recipient_type == RecipientType::Argon2idPassword
            && bool::from(slot.key_id.ct_eq(product_id))
        {
            if matched.is_some() {
                return Err(CryptoError::AmbiguousRecipientSlot);
            }
            matched = Some((slot.key_version, slot.kem_data));
        }
    }

    let (key_version, raw_kem) = matched.ok_or(CryptoError::RecipientNotFound)?;
    if key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    let kem_data = Argon2idKemData::from_bytes(raw_kem)?;
    Ok((key_version, kem_data))
}

#[allow(clippy::too_many_arguments)]
fn encrypt_private_product_password_with_entropy<E: EntropySource>(
    entropy: &mut E,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    password: &[u8],
    password_version: u32,
    params: Argon2idParams,
    additional_recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    if password_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    validate_private_product_ctx(ctx)?;
    validate_password(password)?;
    if flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(flags.to_byte()));
    }
    validate_payload_len(plaintext.len())?;
    if additional_recipients.len() >= MAX_RECIPIENTS {
        return Err(CryptoError::InvalidRecipientCount(
            additional_recipients.len().saturating_add(1),
        ));
    }

    // Validate full recipient list before allocating 64 MiB for Argon2id or consuming CSPRNG bytes.
    let dummy_slot_params = [0_u8; ARGON2_KEM_DATA_LEN];
    let dummy_key = SymmetricKey::from_bytes([0_u8; 32]);
    let mut precheck = Vec::with_capacity(additional_recipients.len() + 1);
    precheck.push(RecipientSpec::SymmetricKek {
        recipient_type: RecipientType::Argon2idPassword,
        key_id: ctx.resource_id,
        key_version: password_version,
        kem_data: &dummy_slot_params,
        kek: &dummy_key,
    });
    precheck.extend_from_slice(additional_recipients);
    validate_recipients(&precheck)?;

    let mut salt = [0_u8; ARGON2_SALT_LEN];
    entropy.fill_random(&mut salt)?;
    let kem_data = Argon2idKemData::new(salt, params)?;
    let kem_bytes = kem_data.to_bytes();
    let password_kek = derive_password_kek(password, &kem_data)?;

    let mut recipients = Vec::with_capacity(additional_recipients.len() + 1);
    recipients.push(RecipientSpec::SymmetricKek {
        recipient_type: RecipientType::Argon2idPassword,
        key_id: ctx.resource_id,
        key_version: password_version,
        kem_data: &kem_bytes,
        kek: &password_kek,
    });
    recipients.extend_from_slice(additional_recipients);

    encrypt_with_entropy(entropy, plaintext, ctx, flags, &recipients)
}

/// Encrypts Private Product metadata into a canonical `RCENC(kind = PrivateProduct)` envelope
/// protected by an Argon2id password slot plus any `additional_recipients` (e.g. `StoreOrgKey`).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_private_product_password(
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    password: &[u8],
    password_version: u32,
    params: Argon2idParams,
    additional_recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_private_product_password_with_entropy(
        &mut OsEntropy,
        plaintext,
        ctx,
        flags,
        password,
        password_version,
        params,
        additional_recipients,
    )
}

/// Deterministic `CryptoRng` variant of [`encrypt_private_product_password`] for KATs and tests.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_private_product_password_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    password: &[u8],
    password_version: u32,
    params: Argon2idParams,
    additional_recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_private_product_password_with_entropy(
        &mut RngEntropy(rng),
        plaintext,
        ctx,
        flags,
        password,
        password_version,
        params,
        additional_recipients,
    )
}

/// Decrypts a password-protected Private Product `RCENC` envelope by locating the unique
/// `Argon2idPassword` slot for `expected_ctx.resource_id`, bounds-checking its Argon2id parameters
/// against [`Argon2idBudget::PROTOCOL_MAX`], deriving the KEK, and authenticating the envelope.
pub fn decrypt_private_product_password(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    password: &[u8],
) -> Result<DecryptedEnvelope, CryptoError> {
    decrypt_private_product_password_with_budget(
        envelope_bytes,
        expected_ctx,
        password,
        Argon2idBudget::PROTOCOL_MAX,
    )
}

/// Decrypts a password-protected Private Product `RCENC` envelope enforcing a caller-selected
/// client-side [`Argon2idBudget`] (such as [`Argon2idBudget::WASM_CLIENT`]) before executing KDF.
pub fn decrypt_private_product_password_with_budget(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    password: &[u8],
    budget: Argon2idBudget,
) -> Result<DecryptedEnvelope, CryptoError> {
    validate_private_product_ctx(expected_ctx)?;
    validate_password(password)?;

    let parsed = parse_envelope(envelope_bytes)?;
    if parsed.header.flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::PrivateProduct {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }

    let mut matched: Option<(u32, &[u8])> = None;
    for slot in &parsed.slots {
        if slot.recipient_type == RecipientType::Argon2idPassword
            && bool::from(slot.key_id.ct_eq(&expected_ctx.resource_id))
        {
            if matched.is_some() {
                return Err(CryptoError::AmbiguousRecipientSlot);
            }
            matched = Some((slot.key_version, slot.kem_data));
        }
    }

    let (password_version, raw_kem) = matched.ok_or(CryptoError::RecipientNotFound)?;
    if password_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    let kem_data = Argon2idKemData::from_bytes(raw_kem)?;
    kem_data.params().check_budget(budget)?;
    let password_kek = derive_password_kek(password, &kem_data)?;

    decrypt_parsed(
        &parsed,
        expected_ctx,
        &RecipientCredential::SymmetricKek {
            recipient_type: RecipientType::Argon2idPassword,
            key_id: expected_ctx.resource_id,
            key_version: password_version,
            kek: &password_kek,
        },
    )
}

/// Decrypts a password-protected Private Product `RCENC` envelope targeting a specific
/// `password_version` under [`Argon2idBudget::PROTOCOL_MAX`].
pub fn decrypt_private_product_password_version(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    password_version: u32,
    password: &[u8],
) -> Result<DecryptedEnvelope, CryptoError> {
    decrypt_private_product_password_version_with_budget(
        envelope_bytes,
        expected_ctx,
        password_version,
        password,
        Argon2idBudget::PROTOCOL_MAX,
    )
}

/// Decrypts a password-protected Private Product `RCENC` envelope targeting a specific
/// `password_version` while enforcing a caller-selected [`Argon2idBudget`].
pub fn decrypt_private_product_password_version_with_budget(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    password_version: u32,
    password: &[u8],
    budget: Argon2idBudget,
) -> Result<DecryptedEnvelope, CryptoError> {
    if password_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    validate_private_product_ctx(expected_ctx)?;
    validate_password(password)?;

    let parsed = parse_envelope(envelope_bytes)?;
    if parsed.header.flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::PrivateProduct {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }

    let slot = parsed
        .slots
        .iter()
        .find(|s| {
            s.recipient_type == RecipientType::Argon2idPassword
                && s.key_version == password_version
                && bool::from(s.key_id.ct_eq(&expected_ctx.resource_id))
        })
        .ok_or(CryptoError::RecipientNotFound)?;

    let kem_data = Argon2idKemData::from_bytes(slot.kem_data)?;
    kem_data.params().check_budget(budget)?;
    let password_kek = derive_password_kek(password, &kem_data)?;

    decrypt_parsed(
        &parsed,
        expected_ctx,
        &RecipientCredential::SymmetricKek {
            recipient_type: RecipientType::Argon2idPassword,
            key_id: expected_ctx.resource_id,
            key_version: password_version,
            kek: &password_kek,
        },
    )
}

fn compute_vip_fragment_checksum(prefix_37b: &[u8]) -> [u8; 2] {
    let digest = Zeroizing::new(blake3::derive_key(VIP_FRAGMENT_CHK_CONTEXT, prefix_37b));
    [digest[0], digest[1]]
}

/// Client-only URL hash fragment (`#k=<52-char Base64URL>`) carrying a versioned VIP Group
/// X-Wing secret seed.
///
/// Binary layout (`39 B`, zero `Base64URL` padding bits):
/// `version[1B = 0x01] || key_version[4B BE] || vip_group_seed[32B] || blake3_chk[2B]`.
///
/// Never transmitted to HTTP servers per RFC 3986 fragment semantics.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VipInviteFragment {
    key_version: u32,
    vip_group_seed: [u8; XWING_SECRET_SEED_LEN],
}

const _: () = assert!(
    VIP_FRAGMENT_RAW_LEN.is_multiple_of(3)
        && (VIP_FRAGMENT_RAW_LEN / 3) * 4 == VIP_FRAGMENT_TOKEN_LEN
);

impl VipInviteFragment {
    /// Creates a `#k=...` invite fragment from a versioned (`>= 1`) VIP group's `XWingSecretKey`.
    pub fn from_secret_key(
        key_version: u32,
        secret_key: &XWingSecretKey,
    ) -> Result<Self, CryptoError> {
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        let seed = secret_key.to_seed_bytes();
        let mut out = Self {
            key_version,
            vip_group_seed: [0_u8; XWING_SECRET_SEED_LEN],
        };
        out.vip_group_seed.copy_from_slice(seed.as_ref());
        Ok(out)
    }

    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Expands the VIP group seed into its heap-allocated `(XWingSecretKey, XWingPublicKey)`.
    #[must_use]
    pub fn to_xwing_keypair(&self) -> (XWingSecretKey, XWingPublicKey) {
        XWingSecretKey::from_seed_ref(&self.vip_group_seed)
    }

    /// Encodes the 52-character constant-time Base64URL-unpadded token value (without `#k=`).
    #[must_use]
    pub fn to_token(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0_u8; VIP_FRAGMENT_RAW_LEN]);
        raw[0] = VIP_FRAGMENT_VERSION_V1;
        raw[1..5].copy_from_slice(&self.key_version.to_be_bytes());
        raw[5..37].copy_from_slice(&self.vip_group_seed);
        let chk = Zeroizing::new(compute_vip_fragment_checksum(&raw[0..37]));
        raw[37..39].copy_from_slice(chk.as_ref());

        let mut encoded = Zeroizing::new([0_u8; VIP_FRAGMENT_TOKEN_LEN]);
        // `39` bytes always encodes to exactly `52` unpadded Base64URL ASCII bytes.
        let _ = Base64UrlUnpadded::encode(raw.as_ref(), encoded.as_mut());

        let mut out = Zeroizing::new(String::with_capacity(VIP_FRAGMENT_TOKEN_LEN));
        for &b in encoded.iter() {
            out.push(char::from(b));
        }
        out
    }

    /// Encodes the canonical URL hash fragment `"#k=<52-char Base64URL>"`.
    #[must_use]
    pub fn to_url_fragment(&self) -> Zeroizing<String> {
        let token = self.to_token();
        let mut out = Zeroizing::new(String::with_capacity(3 + VIP_FRAGMENT_TOKEN_LEN));
        out.push_str("#k=");
        out.push_str(&token);
        out
    }

    /// Parses and checksum-verifies a raw 52-character Base64URL-unpadded VIP invite token.
    pub fn parse_token(token: &str) -> Result<Self, CryptoError> {
        if token.len() != VIP_FRAGMENT_TOKEN_LEN {
            return Err(CryptoError::InvalidInviteFragment);
        }

        let mut raw = Zeroizing::new([0_u8; VIP_FRAGMENT_RAW_LEN]);
        let decoded = Base64UrlUnpadded::decode(token.as_bytes(), raw.as_mut())
            .map_err(|_| CryptoError::InvalidInviteFragment)?;
        if decoded.len() != VIP_FRAGMENT_RAW_LEN {
            return Err(CryptoError::InvalidInviteFragment);
        }
        let expected_chk = Zeroizing::new(compute_vip_fragment_checksum(&raw[0..37]));
        let valid = raw[0].ct_eq(&VIP_FRAGMENT_VERSION_V1) & expected_chk.ct_eq(&raw[37..39]);
        if !bool::from(valid) {
            return Err(CryptoError::InvalidInviteFragment);
        }

        let key_version = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        let mut out = Self {
            key_version,
            vip_group_seed: [0_u8; XWING_SECRET_SEED_LEN],
        };
        out.vip_group_seed.copy_from_slice(&raw[5..37]);
        Ok(out)
    }

    /// Extracts and parses the unique `k=<token>` parameter from a browser URL hash fragment
    /// (e.g. `"#k=..."`, `"k=..."`, or `"#tab=details&k=..."`).
    ///
    /// Rejects duplicate `k=` parameters as well as server-visible query strings (`?`) and full
    /// URLs (`://`, `/`, `:`) so callers fail closed if `location.search` or `location.href` is
    /// mistakenly passed instead of `location.hash`.
    pub fn parse_url_fragment(fragment: &str) -> Result<Self, CryptoError> {
        if fragment.len() > VIP_FRAGMENT_MAX_INPUT_LEN {
            return Err(CryptoError::InvalidInviteFragment);
        }
        let trimmed = fragment.trim();
        let (had_hash, body) = match trimmed.strip_prefix('#') {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        };
        if body.is_empty()
            || body.contains('#')
            || body.contains('?')
            || body.contains("://")
            || (!had_hash && (body.contains('/') || body.contains(':')))
        {
            return Err(CryptoError::InvalidInviteFragment);
        }

        let mut found_token: Option<&str> = None;
        for part in body.split('&') {
            if let Some(val) = part.strip_prefix("k=") {
                if found_token.is_some() {
                    return Err(CryptoError::InvalidInviteFragment);
                }
                found_token = Some(val);
            }
        }

        let token = found_token.ok_or(CryptoError::InvalidInviteFragment)?;
        Self::parse_token(token)
    }
}

impl fmt::Debug for VipInviteFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VipInviteFragment")
            .field("key_version", &self.key_version)
            .field("vip_group_seed", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for VipInviteFragment {
    fn eq(&self, other: &Self) -> bool {
        let eq = self
            .key_version
            .to_be_bytes()
            .ct_eq(&other.key_version.to_be_bytes())
            & self.vip_group_seed.ct_eq(&other.vip_group_seed);
        bool::from(eq)
    }
}

impl Eq for VipInviteFragment {}

fn build_vip_wrap_context(
    tenant_id: [u8; 16],
    vip_group_id: [u8; 16],
    privacy_tier: PrivacyTier,
) -> EnvelopeContext {
    EnvelopeContext {
        envelope_kind: EnvelopeKind::PrivateProduct,
        tenant_id,
        resource_id: vip_group_id,
        privacy_tier,
        schema_version: VIP_GROUP_KEY_WRAP_SCHEMA_VERSION,
    }
}

fn wrap_vip_group_key_with_entropy<E: EntropySource>(
    entropy: &mut E,
    tenant_id: [u8; 16],
    vip_group_id: [u8; 16],
    group_key_version: u32,
    privacy_tier: PrivacyTier,
    vip_group_secret: &XWingSecretKey,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    if group_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    // Disallow self-wrapping a VIP group key to an XWingVipGroup slot or password slot.
    for r in recipients {
        let rtype = match r {
            RecipientSpec::XWing { recipient_type, .. }
            | RecipientSpec::SymmetricKek { recipient_type, .. } => *recipient_type,
        };
        if matches!(
            rtype,
            RecipientType::XWingVipGroup | RecipientType::Argon2idPassword
        ) {
            return Err(CryptoError::InvalidRecipientType(rtype.as_u8()));
        }
    }

    let seed = vip_group_secret.to_seed_bytes();
    let mut payload = Zeroizing::new([0_u8; VIP_KEY_WRAP_PAYLOAD_LEN]);
    payload[0..5].copy_from_slice(VIP_KEY_WRAP_MAGIC);
    payload[5] = VIP_KEY_WRAP_VERSION_V1;
    payload[6..22].copy_from_slice(&tenant_id);
    payload[22..38].copy_from_slice(&vip_group_id);
    payload[38..42].copy_from_slice(&group_key_version.to_be_bytes());
    payload[42..74].copy_from_slice(seed.as_ref());

    let ctx = build_vip_wrap_context(tenant_id, vip_group_id, privacy_tier);
    encrypt_with_entropy(
        entropy,
        payload.as_ref(),
        &ctx,
        EnvelopeFlags::default(),
        recipients,
    )
}

/// Wraps a VIP Group's 32-byte X-Wing secret seed inside a domain-separated `RCVIP` v1 `RCENC`
/// envelope for `1..=8` recipients (e.g. `XWingCustomerVault` for a VIP member row, or
/// `XWingOrgKey` for the merchant's group storage row).
pub fn wrap_vip_group_key(
    tenant_id: [u8; 16],
    vip_group_id: [u8; 16],
    group_key_version: u32,
    privacy_tier: PrivacyTier,
    vip_group_secret: &XWingSecretKey,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    wrap_vip_group_key_with_entropy(
        &mut OsEntropy,
        tenant_id,
        vip_group_id,
        group_key_version,
        privacy_tier,
        vip_group_secret,
        recipients,
    )
}

/// Deterministic `CryptoRng` variant of [`wrap_vip_group_key`] for KATs and tests.
pub fn wrap_vip_group_key_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    tenant_id: [u8; 16],
    vip_group_id: [u8; 16],
    group_key_version: u32,
    privacy_tier: PrivacyTier,
    vip_group_secret: &XWingSecretKey,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    wrap_vip_group_key_with_entropy(
        &mut RngEntropy(rng),
        tenant_id,
        vip_group_id,
        group_key_version,
        privacy_tier,
        vip_group_secret,
        recipients,
    )
}

/// Authenticates and unwraps an `RCVIP` v1 VIP group key envelope, verifying exact length,
/// magic, version, and bound `(tenant_id, vip_group_id, expected_group_key_version)` in constant time.
pub fn unwrap_vip_group_key(
    envelope_bytes: &[u8],
    tenant_id: [u8; 16],
    vip_group_id: [u8; 16],
    expected_group_key_version: u32,
    privacy_tier: PrivacyTier,
    credential: &RecipientCredential<'_>,
) -> Result<(XWingSecretKey, XWingPublicKey), CryptoError> {
    if expected_group_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    let rtype = match credential {
        RecipientCredential::XWing { recipient_type, .. }
        | RecipientCredential::SymmetricKek { recipient_type, .. } => *recipient_type,
    };
    if matches!(
        rtype,
        RecipientType::XWingVipGroup | RecipientType::Argon2idPassword
    ) {
        return Err(CryptoError::InvalidRecipientType(rtype.as_u8()));
    }

    let parsed = parse_envelope(envelope_bytes)?;
    if parsed.header.flags != EnvelopeFlags::default() {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::PrivateProduct {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }
    // Pre-decapsulation exact payload length check defeats 64 MiB browser WASM DoS envelopes.
    if parsed.ciphertext.len() != VIP_KEY_WRAP_PAYLOAD_LEN + AEAD_TAG_LEN {
        return Err(CryptoError::InvalidVipKeyPayload);
    }

    let ctx = build_vip_wrap_context(tenant_id, vip_group_id, privacy_tier);
    let decrypted = decrypt_parsed(&parsed, &ctx, credential)?;
    let pt = decrypted.plaintext.as_slice();
    if pt.len() != VIP_KEY_WRAP_PAYLOAD_LEN {
        return Err(CryptoError::InvalidVipKeyPayload);
    }

    let ok = pt[0..5].ct_eq(VIP_KEY_WRAP_MAGIC)
        & pt[5].ct_eq(&VIP_KEY_WRAP_VERSION_V1)
        & pt[6..22].ct_eq(&tenant_id)
        & pt[22..38].ct_eq(&vip_group_id)
        & pt[38..42].ct_eq(&expected_group_key_version.to_be_bytes());
    if !bool::from(ok) {
        return Err(CryptoError::InvalidVipKeyPayload);
    }

    XWingSecretKey::from_seed_slice(&pt[42..74])
}

#[allow(clippy::too_many_arguments)]
fn encrypt_private_product_vip_with_entropy<E: EntropySource>(
    entropy: &mut E,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    vip_group_id: [u8; 16],
    vip_key_version: u32,
    vip_public_key: &XWingPublicKey,
    additional_recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    if vip_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    validate_private_product_ctx(ctx)?;
    if flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(flags.to_byte()));
    }
    if additional_recipients.len() >= MAX_RECIPIENTS {
        return Err(CryptoError::InvalidRecipientCount(
            additional_recipients.len().saturating_add(1),
        ));
    }

    let mut recipients = Vec::with_capacity(additional_recipients.len() + 1);
    recipients.push(RecipientSpec::XWing {
        recipient_type: RecipientType::XWingVipGroup,
        key_id: vip_group_id,
        key_version: vip_key_version,
        public_key: vip_public_key,
    });
    recipients.extend_from_slice(additional_recipients);

    encrypt_with_entropy(entropy, plaintext, ctx, flags, &recipients)
}

/// Encrypts Private Product metadata into a canonical `RCENC(kind = PrivateProduct)` envelope
/// for a VIP group (`RecipientType::XWingVipGroup`) plus any `additional_recipients` (e.g. `StoreOrgKey`).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_private_product_vip(
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    vip_group_id: [u8; 16],
    vip_key_version: u32,
    vip_public_key: &XWingPublicKey,
    additional_recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_private_product_vip_with_entropy(
        &mut OsEntropy,
        plaintext,
        ctx,
        flags,
        vip_group_id,
        vip_key_version,
        vip_public_key,
        additional_recipients,
    )
}

/// Deterministic `CryptoRng` variant of [`encrypt_private_product_vip`] for KATs and tests.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_private_product_vip_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    vip_group_id: [u8; 16],
    vip_key_version: u32,
    vip_public_key: &XWingPublicKey,
    additional_recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_private_product_vip_with_entropy(
        &mut RngEntropy(rng),
        plaintext,
        ctx,
        flags,
        vip_group_id,
        vip_key_version,
        vip_public_key,
        additional_recipients,
    )
}

/// Decrypts a VIP-group Private Product `RCENC` envelope using the group's `XWingSecretKey`.
pub fn decrypt_private_product_vip(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    vip_group_id: [u8; 16],
    vip_key_version: u32,
    vip_secret_key: &XWingSecretKey,
) -> Result<DecryptedEnvelope, CryptoError> {
    if vip_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    validate_private_product_ctx(expected_ctx)?;
    decrypt(
        envelope_bytes,
        expected_ctx,
        &RecipientCredential::XWing {
            recipient_type: RecipientType::XWingVipGroup,
            key_id: vip_group_id,
            key_version: vip_key_version,
            secret_key: vip_secret_key,
        },
    )
}

/// Decrypts a VIP-group Private Product `RCENC` envelope directly from a parsed `#k=...`
/// [`VipInviteFragment`].
pub fn decrypt_private_product_vip_fragment(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    vip_group_id: [u8; 16],
    fragment: &VipInviteFragment,
) -> Result<DecryptedEnvelope, CryptoError> {
    let (vip_sk, _) = fragment.to_xwing_keypair();
    decrypt_private_product_vip(
        envelope_bytes,
        expected_ctx,
        vip_group_id,
        fragment.key_version(),
        &vip_sk,
    )
}

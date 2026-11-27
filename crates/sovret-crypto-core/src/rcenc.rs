use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::xwing::{EntropySource, OsEntropy, RngEntropy, XWING_CIPHERTEXT_LEN};
use crate::{
    CryptoError, EnvelopeContext, EnvelopeFlags, EnvelopeKind, RecipientType, SymmetricKey,
    XWingPublicKey, XWingSecretKey,
};

/// 5-byte canonical envelope magic (`"RCENC"`).
pub const RCENC_MAGIC: &[u8; 5] = b"RCENC";
/// `RCENC` format version 1.
pub const RCENC_FORMAT_VERSION_V1: u8 = 0x01;
/// Cipher suite `0x01`: `X-Wing (ML-KEM-768 + X25519) + XChaCha20-Poly1305`.
pub const CIPHER_SUITE_XWING_XCHACHA20_POLY1305: u8 = 0x01;
/// Fixed header length in bytes.
pub const RCENC_HEADER_LEN: usize = 10;
/// Maximum recipients permitted per envelope (`1..=8`).
pub const MAX_RECIPIENTS: usize = 8;
/// Length of an XChaCha20-Poly1305 nonce (`24 B`).
pub const XCHACHA_NONCE_LEN: usize = 24;
/// Length of an XChaCha20-Poly1305 authentication tag (`16 B`).
pub const AEAD_TAG_LEN: usize = 16;
/// Length of a wrapped 32-byte DEK (`32 B CT + 16 B tag = 48 B`).
pub const WRAPPED_DEK_LEN: usize = 32 + AEAD_TAG_LEN;
/// Upper bound on single `RCENC` payload ciphertext (`64 MiB`) to prevent allocation `DoS`.
pub const MAX_RCENC_PAYLOAD_CIPHERTEXT_LEN: usize = 64 * 1024 * 1024;

const DEK_WRAP_INFO: &[u8] = b"sovret-v1-dek-wrap";
const CANONICAL_AAD_PREFIX: &[u8; 13] = b"sovret-v1-aad";
const CANONICAL_AAD_LEN: usize = 13 + 1 + 16 + 16 + 1 + 2 + 32;
const SLOT_AAD_LEN: usize = RCENC_HEADER_LEN + 1 + 16 + 4;

/// Recipient target specification when encrypting an `RCENC` v1 envelope.
#[derive(Debug, Clone, Copy)]
pub enum RecipientSpec<'a> {
    /// Post-quantum hybrid X-Wing recipient (`0x01..=0x04`).
    XWing {
        recipient_type: RecipientType,
        key_id: [u8; 16],
        key_version: u32,
        public_key: &'a XWingPublicKey,
    },
    /// Symmetric KEK recipient (`0x05` Argon2id password w/ 44B params, or `0x06` BIP-39 recovery w/ 0B).
    SymmetricKek {
        recipient_type: RecipientType,
        key_id: [u8; 16],
        key_version: u32,
        kem_data: &'a [u8],
        kek: &'a SymmetricKey,
    },
}

impl RecipientSpec<'_> {
    const fn slot_identity(&self) -> (RecipientType, [u8; 16], u32) {
        match self {
            Self::XWing {
                recipient_type,
                key_id,
                key_version,
                ..
            }
            | Self::SymmetricKek {
                recipient_type,
                key_id,
                key_version,
                ..
            } => (*recipient_type, *key_id, *key_version),
        }
    }
}

/// Recipient secret credential used to decrypt an `RCENC` v1 envelope.
pub enum RecipientCredential<'a> {
    /// X-Wing private decapsulation key matching an `0x01..=0x04` slot.
    XWing {
        recipient_type: RecipientType,
        key_id: [u8; 16],
        key_version: u32,
        secret_key: &'a XWingSecretKey,
    },
    /// 32-byte symmetric KEK matching an `0x05` or `0x06` slot.
    SymmetricKek {
        recipient_type: RecipientType,
        key_id: [u8; 16],
        key_version: u32,
        kek: &'a SymmetricKey,
    },
}

/// Parsed public header of an `RCENC` v1 envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub format_version: u8,
    pub cipher_suite: u8,
    pub envelope_kind: EnvelopeKind,
    pub flags: EnvelopeFlags,
    pub recipient_count: u8,
}

/// Public metadata for a single recipient slot (e.g. to inspect Argon2id salt/params before decrypt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecipientSlot<'a> {
    pub recipient_type: RecipientType,
    pub key_id: [u8; 16],
    pub key_version: u32,
    pub kem_data: &'a [u8],
    pub wrap_nonce: [u8; XCHACHA_NONCE_LEN],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
}

/// Parsed (unauthenticated) view over an `RCENC` v1 wire buffer.
#[derive(Debug, Clone)]
pub struct ParsedEnvelope<'a> {
    pub header: EnvelopeHeader,
    pub raw_header_and_slots: &'a [u8],
    pub slots: Vec<ParsedRecipientSlot<'a>>,
    pub payload_nonce: [u8; XCHACHA_NONCE_LEN],
    pub ciphertext: &'a [u8],
}

/// Successfully authenticated and decrypted `RCENC` v1 payload.
///
/// `Debug` is manually implemented to redact `plaintext` so PII or secret material can never
/// leak into logs or error reports.
pub struct DecryptedEnvelope {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub header: EnvelopeHeader,
}

impl fmt::Debug for DecryptedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedEnvelope")
            .field("plaintext", &"[REDACTED]")
            .field("header", &self.header)
            .finish()
    }
}

/// Derives the 32-byte slot DEK-wrapping key directly into a `ZeroizeOnDrop` [`SymmetricKey`]:
/// `HKDF-SHA256(ikm = shared_secret_32B, salt = key_id || key_version_be, info = "sovret-v1-dek-wrap")`.
pub(crate) fn derive_wrap_key(
    ikm: &SymmetricKey,
    key_id: &[u8; 16],
    key_version: u32,
) -> Result<SymmetricKey, CryptoError> {
    let mut salt = [0_u8; 20];
    salt[..16].copy_from_slice(key_id);
    salt[16..20].copy_from_slice(&key_version.to_be_bytes());

    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), ikm.as_bytes());
    prk.zeroize();
    SymmetricKey::init_with(|okm| {
        hk.expand(DEK_WRAP_INFO, okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)
    })
}

/// Builds the 31-byte `slot_aad = header[0..10] || recipient_type || key_id || key_version_be`.
fn build_slot_aad(
    header_bytes: &[u8; RCENC_HEADER_LEN],
    recipient_type: RecipientType,
    key_id: &[u8; 16],
    key_version: u32,
) -> [u8; SLOT_AAD_LEN] {
    let mut aad = [0_u8; SLOT_AAD_LEN];
    aad[..RCENC_HEADER_LEN].copy_from_slice(header_bytes);
    aad[RCENC_HEADER_LEN] = recipient_type.as_u8();
    aad[RCENC_HEADER_LEN + 1..RCENC_HEADER_LEN + 17].copy_from_slice(key_id);
    aad[RCENC_HEADER_LEN + 17..SLOT_AAD_LEN].copy_from_slice(&key_version.to_be_bytes());
    aad
}

/// Builds the 81-byte `canonical_aad` independently from trusted `EnvelopeContext` and the raw
/// `header || all_recipient_slots` prefix hash.
#[must_use]
pub fn build_canonical_aad(
    ctx: &EnvelopeContext,
    raw_header_and_slots: &[u8],
) -> [u8; CANONICAL_AAD_LEN] {
    let prefix_hash = blake3::hash(raw_header_and_slots);
    let mut aad = [0_u8; CANONICAL_AAD_LEN];
    aad[0..13].copy_from_slice(CANONICAL_AAD_PREFIX);
    aad[13] = ctx.envelope_kind.as_u8();
    aad[14..30].copy_from_slice(&ctx.tenant_id);
    aad[30..46].copy_from_slice(&ctx.resource_id);
    aad[46] = ctx.privacy_tier.as_u8();
    aad[47..49].copy_from_slice(&ctx.schema_version.to_be_bytes());
    aad[49..81].copy_from_slice(prefix_hash.as_bytes());
    aad
}

pub(crate) fn validate_payload_len(plaintext_len: usize) -> Result<usize, CryptoError> {
    let expected_ct_len = plaintext_len
        .checked_add(AEAD_TAG_LEN)
        .ok_or(CryptoError::InvalidPayloadLength)?;
    if expected_ct_len > MAX_RCENC_PAYLOAD_CIPHERTEXT_LEN {
        return Err(CryptoError::InvalidPayloadLength);
    }
    Ok(expected_ct_len)
}

pub(crate) fn validate_recipients(recipients: &[RecipientSpec<'_>]) -> Result<(), CryptoError> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(CryptoError::InvalidRecipientCount(recipients.len()));
    }

    for (idx, r) in recipients.iter().enumerate() {
        match r {
            RecipientSpec::XWing { recipient_type, .. } => {
                if !recipient_type.is_xwing() {
                    return Err(CryptoError::InvalidRecipientType(recipient_type.as_u8()));
                }
            }
            RecipientSpec::SymmetricKek {
                recipient_type,
                kem_data,
                ..
            } => {
                if recipient_type.is_xwing() {
                    return Err(CryptoError::InvalidRecipientType(recipient_type.as_u8()));
                }
                let expected = recipient_type.expected_kem_data_len();
                if kem_data.len() != expected {
                    return Err(CryptoError::InvalidKemDataLength {
                        expected,
                        actual: kem_data.len(),
                    });
                }
            }
        }

        let (t_i, id_i, ver_i) = r.slot_identity();
        if ver_i == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        for other in &recipients[idx + 1..] {
            let (t_j, id_j, ver_j) = other.slot_identity();
            if t_i == t_j && ver_i == ver_j && bool::from(id_i.ct_eq(&id_j)) {
                return Err(CryptoError::DuplicateRecipientSlot);
            }
        }
    }

    Ok(())
}

fn append_recipient_slot<E: EntropySource>(
    out: &mut Vec<u8>,
    entropy: &mut E,
    header_bytes: &[u8; RCENC_HEADER_LEN],
    dek: &SymmetricKey,
    recipient: &RecipientSpec<'_>,
) -> Result<(), CryptoError> {
    let mut wrap_nonce = [0_u8; XCHACHA_NONCE_LEN];
    entropy.fill_random(&mut wrap_nonce)?;

    let (recipient_type, key_id, key_version, kem_owned, kem_slice, wrap_key) = match recipient {
        RecipientSpec::XWing {
            recipient_type,
            key_id,
            key_version,
            public_key,
        } => {
            let (kem_ct, shared_secret) = public_key.encapsulate_with_entropy(entropy)?;
            let wrap_key = derive_wrap_key(&shared_secret, key_id, *key_version)?;
            (
                *recipient_type,
                key_id,
                *key_version,
                Some(kem_ct),
                &[][..],
                wrap_key,
            )
        }
        RecipientSpec::SymmetricKek {
            recipient_type,
            key_id,
            key_version,
            kem_data,
            kek,
        } => {
            let wrap_key = derive_wrap_key(kek, key_id, *key_version)?;
            (
                *recipient_type,
                key_id,
                *key_version,
                None,
                *kem_data,
                wrap_key,
            )
        }
    };

    let kem_bytes: &[u8] = kem_owned.as_deref().map_or(kem_slice, |ct| ct.as_slice());
    let slot_aad = build_slot_aad(header_bytes, recipient_type, key_id, key_version);
    // Zero-copy reference to key bytes avoids unzeroized stack `Key` copies.
    let cipher = XChaCha20Poly1305::new(wrap_key.as_bytes().into());
    let wrapped = cipher
        .encrypt(
            &XNonce::from(wrap_nonce),
            Payload {
                msg: dek.as_bytes(),
                aad: &slot_aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let kem_len =
        u16::try_from(kem_bytes.len()).map_err(|_| CryptoError::InvalidKemDataLength {
            expected: recipient_type.expected_kem_data_len(),
            actual: kem_bytes.len(),
        })?;
    out.push(recipient_type.as_u8());
    out.extend_from_slice(key_id);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(&kem_len.to_be_bytes());
    out.extend_from_slice(kem_bytes);
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&wrapped);
    Ok(())
}

pub(crate) fn encrypt_with_entropy<E: EntropySource>(
    entropy: &mut E,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    validate_recipients(recipients)?;
    let expected_ct_len = validate_payload_len(plaintext.len())?;

    let recipient_count = u8::try_from(recipients.len())
        .map_err(|_| CryptoError::InvalidRecipientCount(recipients.len()))?;

    let mut header_bytes = [0_u8; RCENC_HEADER_LEN];
    header_bytes[0..5].copy_from_slice(RCENC_MAGIC);
    header_bytes[5] = RCENC_FORMAT_VERSION_V1;
    header_bytes[6] = CIPHER_SUITE_XWING_XCHACHA20_POLY1305;
    header_bytes[7] = ctx.envelope_kind.as_u8();
    header_bytes[8] = flags.to_byte();
    header_bytes[9] = recipient_count;

    let dek = SymmetricKey::init_with(|buf| entropy.fill_random(buf))?;

    let slots_est = recipients.len().saturating_mul(
        1 + 16 + 4 + 2 + XWING_CIPHERTEXT_LEN + XCHACHA_NONCE_LEN + WRAPPED_DEK_LEN,
    );
    let mut out = Vec::with_capacity(
        RCENC_HEADER_LEN
            .saturating_add(slots_est)
            .saturating_add(XCHACHA_NONCE_LEN + 4)
            .saturating_add(expected_ct_len),
    );
    out.extend_from_slice(&header_bytes);

    for recipient in recipients {
        append_recipient_slot(&mut out, entropy, &header_bytes, &dek, recipient)?;
    }

    // Bind BLAKE3(header || all_recipient_slots) into canonical_aad.
    let canonical_aad = build_canonical_aad(ctx, &out);

    let mut payload_nonce = [0_u8; XCHACHA_NONCE_LEN];
    entropy.fill_random(&mut payload_nonce)?;

    let payload_cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
    let ciphertext = payload_cipher
        .encrypt(
            &XNonce::from(payload_nonce),
            Payload {
                msg: plaintext,
                aad: &canonical_aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let ct_len = u32::try_from(ciphertext.len()).map_err(|_| CryptoError::InvalidPayloadLength)?;
    out.extend_from_slice(&payload_nonce);
    out.extend_from_slice(&ct_len.to_be_bytes());
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Encrypts `plaintext` into a canonical standalone `RCENC` v1 binary envelope for `1..=8`
/// recipients using the platform CSPRNG (`getrandom`).
pub fn encrypt(
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    if flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(flags.to_byte()));
    }
    encrypt_with_entropy(&mut OsEntropy, plaintext, ctx, flags, recipients)
}

/// Encrypts `plaintext` into a canonical standalone `RCENC` v1 binary envelope using a
/// caller-supplied `CryptoRng` (for deterministic KAT vectors and `proptest`).
pub fn encrypt_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    flags: EnvelopeFlags,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    if flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(flags.to_byte()));
    }
    encrypt_with_entropy(&mut RngEntropy(rng), plaintext, ctx, flags, recipients)
}

fn take_slice<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], CryptoError> {
    let end = cursor.checked_add(len).ok_or(CryptoError::TruncatedInput)?;
    let slice = input.get(*cursor..end).ok_or(CryptoError::TruncatedInput)?;
    *cursor = end;
    Ok(slice)
}

/// Parses an `RCENC` v1 envelope from the front of `input`, returning `(ParsedEnvelope, consumed_bytes)`.
///
/// Enforces canonical uniqueness of `(recipient_type, key_id, key_version)` across all slots.
pub fn parse_envelope_prefix(input: &[u8]) -> Result<(ParsedEnvelope<'_>, usize), CryptoError> {
    let mut cursor = 0;

    let header_slice = take_slice(input, &mut cursor, RCENC_HEADER_LEN)?;
    if !bool::from(header_slice[0..5].ct_eq(RCENC_MAGIC)) {
        return Err(CryptoError::InvalidMagic);
    }

    let format_version = header_slice[5];
    if format_version != RCENC_FORMAT_VERSION_V1 {
        return Err(CryptoError::UnsupportedFormatVersion(format_version));
    }

    let cipher_suite = header_slice[6];
    if cipher_suite != CIPHER_SUITE_XWING_XCHACHA20_POLY1305 {
        return Err(CryptoError::UnsupportedCipherSuite(cipher_suite));
    }

    let envelope_kind = EnvelopeKind::from_u8(header_slice[7])?;
    let flags = EnvelopeFlags::from_byte(header_slice[8])?;
    let recipient_count_u8 = header_slice[9];
    let recipient_count = usize::from(recipient_count_u8);
    if recipient_count == 0 || recipient_count > MAX_RECIPIENTS {
        return Err(CryptoError::InvalidRecipientCount(recipient_count));
    }

    let mut slots: Vec<ParsedRecipientSlot<'_>> = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        let recipient_type = RecipientType::from_u8(take_slice(input, &mut cursor, 1)?[0])?;

        let mut key_id = [0_u8; 16];
        key_id.copy_from_slice(take_slice(input, &mut cursor, 16)?);

        let mut ver_bytes = [0_u8; 4];
        ver_bytes.copy_from_slice(take_slice(input, &mut cursor, 4)?);
        let key_version = u32::from_be_bytes(ver_bytes);
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }

        if slots.iter().any(|prev| {
            prev.recipient_type == recipient_type
                && prev.key_version == key_version
                && bool::from(prev.key_id.ct_eq(&key_id))
        }) {
            return Err(CryptoError::DuplicateRecipientSlot);
        }

        let mut kem_len_bytes = [0_u8; 2];
        kem_len_bytes.copy_from_slice(take_slice(input, &mut cursor, 2)?);
        let kem_len = usize::from(u16::from_be_bytes(kem_len_bytes));

        let expected_kem_len = recipient_type.expected_kem_data_len();
        if kem_len != expected_kem_len {
            return Err(CryptoError::InvalidKemDataLength {
                expected: expected_kem_len,
                actual: kem_len,
            });
        }

        let kem_data = take_slice(input, &mut cursor, kem_len)?;

        let mut wrap_nonce = [0_u8; XCHACHA_NONCE_LEN];
        wrap_nonce.copy_from_slice(take_slice(input, &mut cursor, XCHACHA_NONCE_LEN)?);

        let mut wrapped_dek = [0_u8; WRAPPED_DEK_LEN];
        wrapped_dek.copy_from_slice(take_slice(input, &mut cursor, WRAPPED_DEK_LEN)?);

        slots.push(ParsedRecipientSlot {
            recipient_type,
            key_id,
            key_version,
            kem_data,
            wrap_nonce,
            wrapped_dek,
        });
    }

    let raw_header_and_slots = &input[..cursor];

    let mut payload_nonce = [0_u8; XCHACHA_NONCE_LEN];
    payload_nonce.copy_from_slice(take_slice(input, &mut cursor, XCHACHA_NONCE_LEN)?);

    let mut ct_len_bytes = [0_u8; 4];
    ct_len_bytes.copy_from_slice(take_slice(input, &mut cursor, 4)?);
    let ct_len = usize::try_from(u32::from_be_bytes(ct_len_bytes))
        .map_err(|_| CryptoError::InvalidPayloadLength)?;

    if !(AEAD_TAG_LEN..=MAX_RCENC_PAYLOAD_CIPHERTEXT_LEN).contains(&ct_len) {
        return Err(CryptoError::InvalidPayloadLength);
    }

    let ciphertext = take_slice(input, &mut cursor, ct_len)?;

    let parsed = ParsedEnvelope {
        header: EnvelopeHeader {
            format_version,
            cipher_suite,
            envelope_kind,
            flags,
            recipient_count: recipient_count_u8,
        },
        raw_header_and_slots,
        slots,
        payload_nonce,
        ciphertext,
    };

    Ok((parsed, cursor))
}

/// Parses and validates an entire canonical `RCENC` v1 envelope without decrypting it
/// (e.g. to inspect recipient slots or Argon2id salt/params). Rejects trailing bytes.
pub fn parse_envelope(input: &[u8]) -> Result<ParsedEnvelope<'_>, CryptoError> {
    let (parsed, consumed) = parse_envelope_prefix(input)?;
    if consumed != input.len() {
        return Err(CryptoError::TrailingBytes);
    }
    Ok(parsed)
}

/// Decrypts an already-parsed `RCENC` v1 envelope against the expected `EnvelopeContext`.
pub(crate) fn decrypt_parsed(
    parsed: &ParsedEnvelope<'_>,
    expected_ctx: &EnvelopeContext,
    credential: &RecipientCredential<'_>,
) -> Result<DecryptedEnvelope, CryptoError> {
    if parsed.header.envelope_kind != expected_ctx.envelope_kind {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }

    let (want_type, want_key_id, want_version) = match credential {
        RecipientCredential::XWing {
            recipient_type,
            key_id,
            key_version,
            ..
        } => {
            if !recipient_type.is_xwing() {
                return Err(CryptoError::InvalidRecipientType(recipient_type.as_u8()));
            }
            (*recipient_type, key_id, *key_version)
        }
        RecipientCredential::SymmetricKek {
            recipient_type,
            key_id,
            key_version,
            ..
        } => {
            if recipient_type.is_xwing() {
                return Err(CryptoError::InvalidRecipientType(recipient_type.as_u8()));
            }
            (*recipient_type, key_id, *key_version)
        }
    };
    if want_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }

    let slot = parsed
        .slots
        .iter()
        .find(|s| {
            s.recipient_type == want_type
                && s.key_version == want_version
                && bool::from(s.key_id.ct_eq(want_key_id))
        })
        .ok_or(CryptoError::RecipientNotFound)?;

    let header_bytes: &[u8; RCENC_HEADER_LEN] = parsed
        .raw_header_and_slots
        .get(..RCENC_HEADER_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(CryptoError::TruncatedInput)?;

    let wrap_key = match credential {
        RecipientCredential::XWing { secret_key, .. } => {
            let shared_secret = secret_key.decapsulate(slot.kem_data)?;
            derive_wrap_key(&shared_secret, &slot.key_id, slot.key_version)?
        }
        RecipientCredential::SymmetricKek { kek, .. } => {
            derive_wrap_key(kek, &slot.key_id, slot.key_version)?
        }
    };

    let slot_aad = build_slot_aad(
        header_bytes,
        slot.recipient_type,
        &slot.key_id,
        slot.key_version,
    );
    let wrap_cipher = XChaCha20Poly1305::new(wrap_key.as_bytes().into());
    let dek_vec = Zeroizing::new(
        wrap_cipher
            .decrypt(
                &XNonce::from(slot.wrap_nonce),
                Payload {
                    msg: &slot.wrapped_dek,
                    aad: &slot_aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    let dek = SymmetricKey::try_from_slice(&dek_vec)?;

    let canonical_aad = build_canonical_aad(expected_ctx, parsed.raw_header_and_slots);
    let payload_cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
    let plaintext = Zeroizing::new(
        payload_cipher
            .decrypt(
                &XNonce::from(parsed.payload_nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &canonical_aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );

    Ok(DecryptedEnvelope {
        plaintext,
        header: parsed.header,
    })
}

/// Authenticates and decrypts a complete canonical standalone `RCENC` v1 envelope.
///
/// Rejects `RCSTR`-internal header envelopes (`flags` bit 1 set), trailing bytes, duplicate
/// recipient slots, mismatched `EnvelopeContext` (`tenant_id`, `resource_id`, `envelope_kind`,
/// `privacy_tier`, `schema_version`), recipient-slot tampering/stripping, reserved flag bits,
/// and non-contributory X25519 ciphertexts.
pub fn decrypt(
    envelope_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    credential: &RecipientCredential<'_>,
) -> Result<DecryptedEnvelope, CryptoError> {
    let parsed = parse_envelope(envelope_bytes)?;
    if parsed.header.flags.is_rcstr_header() {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    decrypt_parsed(&parsed, expected_ctx, credential)
}

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::rcenc::{
    AEAD_TAG_LEN, RecipientCredential, RecipientSpec, decrypt_parsed, encrypt_with_entropy,
    parse_envelope_prefix,
};
use crate::xwing::{EntropySource, OsEntropy, RngEntropy};
use crate::{CryptoError, EnvelopeContext, EnvelopeFlags, SymmetricKey};

/// 5-byte streaming magic (`"RCSTR"`).
pub const RCSTR_MAGIC: &[u8; 5] = b"RCSTR";
/// `RCSTR` format version 1.
pub const RCSTR_FORMAT_VERSION_V1: u8 = 0x01;
/// Default plaintext chunk size (`64 KiB`, keeping streaming RAM around ~128 KiB in WASM).
pub const DEFAULT_CHUNK_SIZE: u32 = 65_536;
/// Minimum permitted plaintext chunk size (`4 KiB`).
pub const MIN_CHUNK_SIZE: u32 = 4_096;
/// Maximum permitted plaintext chunk size (`4 MiB`).
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
/// Length of the random per-file nonce prefix (`16 B`).
pub const FILE_NONCE_PREFIX_LEN: usize = 16;
/// Fixed `RCSTR` header prefix length before the embedded `RCENC` envelope:
/// `"RCSTR"[5] || version[1] || chunk_size[4] || file_nonce_prefix[16] = 26 B`.
pub const RCSTR_FIXED_HEADER_LEN: usize = 26;
/// Plaintext length inside the embedded `RCENC` envelope: `FileDEK[32] || rcstr_fixed_header[26] = 58 B`.
const RCSTR_KEY_PAYLOAD_LEN: usize = 32 + RCSTR_FIXED_HEADER_LEN;
/// Exact ciphertext length of the embedded `RCENC` payload (`58 B + 16 B tag = 74 B`).
const RCSTR_KEY_CIPHERTEXT_LEN: usize = RCSTR_KEY_PAYLOAD_LEN + AEAD_TAG_LEN;
/// Maximum chunk index representable in the 7-byte big-endian nonce field (`2^56 - 1`).
pub const MAX_CHUNK_INDEX: u64 = (1_u64 << 56) - 1;

const STREAM_AAD_PREFIX: &[u8; 16] = b"sovret-v1-stream";
const STREAM_AAD_LEN: usize = 16 + 16 + 16 + 8 + 1;

fn validate_chunk_size(chunk_size: u32) -> Result<usize, CryptoError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CryptoError::InvalidChunkSize(chunk_size));
    }
    usize::try_from(chunk_size).map_err(|_| CryptoError::InvalidChunkSize(chunk_size))
}

fn build_fixed_header(
    chunk_size: u32,
    file_nonce_prefix: &[u8; FILE_NONCE_PREFIX_LEN],
) -> [u8; RCSTR_FIXED_HEADER_LEN] {
    let mut hdr = [0_u8; RCSTR_FIXED_HEADER_LEN];
    hdr[0..5].copy_from_slice(RCSTR_MAGIC);
    hdr[5] = RCSTR_FORMAT_VERSION_V1;
    hdr[6..10].copy_from_slice(&chunk_size.to_be_bytes());
    hdr[10..26].copy_from_slice(file_nonce_prefix);
    hdr
}

fn build_chunk_nonce(
    file_nonce_prefix: &[u8; FILE_NONCE_PREFIX_LEN],
    chunk_index: u64,
    is_final: bool,
) -> Result<[u8; 24], CryptoError> {
    if chunk_index > MAX_CHUNK_INDEX {
        return Err(CryptoError::ChunkIndexOverflow);
    }
    let idx_be = chunk_index.to_be_bytes();
    let mut nonce = [0_u8; 24];
    nonce[0..16].copy_from_slice(file_nonce_prefix);
    // Low 7 bytes of big-endian u64 (top byte guaranteed 0 because chunk_index < 2^56).
    nonce[16..23].copy_from_slice(&idx_be[1..8]);
    nonce[23] = u8::from(is_final);
    Ok(nonce)
}

fn build_chunk_aad(
    tenant_id: &[u8; 16],
    file_id: &[u8; 16],
    chunk_index: u64,
    is_final: bool,
) -> [u8; STREAM_AAD_LEN] {
    let mut aad = [0_u8; STREAM_AAD_LEN];
    aad[0..16].copy_from_slice(STREAM_AAD_PREFIX);
    aad[16..32].copy_from_slice(tenant_id);
    aad[32..48].copy_from_slice(file_id);
    aad[48..56].copy_from_slice(&chunk_index.to_be_bytes());
    aad[56] = u8::from(is_final);
    aad
}

/// Streaming `RCSTR` v1 chunk encryptor (constant ~128 KiB memory for multi-GB files).
///
/// Automatically zeroizes `file_dek` and `file_nonce_prefix` on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RcstrEncryptor {
    file_dek: SymmetricKey,
    file_nonce_prefix: [u8; FILE_NONCE_PREFIX_LEN],
    tenant_id: [u8; 16],
    file_id: [u8; 16],
    chunk_size: usize,
    next_chunk_index: u64,
    finished: bool,
}

impl RcstrEncryptor {
    fn new_with_entropy<E: EntropySource>(
        entropy: &mut E,
        ctx: &EnvelopeContext,
        chunk_size: u32,
        recipients: &[RecipientSpec<'_>],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let chunk_size_usize = validate_chunk_size(chunk_size)?;

        let file_dek = SymmetricKey::init_with(|buf| entropy.fill_random(buf))?;

        let mut file_nonce_prefix = [0_u8; FILE_NONCE_PREFIX_LEN];
        entropy.fill_random(&mut file_nonce_prefix)?;

        let fixed_header = build_fixed_header(chunk_size, &file_nonce_prefix);
        let mut key_payload = Zeroizing::new([0_u8; RCSTR_KEY_PAYLOAD_LEN]);
        key_payload[0..32].copy_from_slice(file_dek.as_bytes());
        key_payload[32..RCSTR_KEY_PAYLOAD_LEN].copy_from_slice(&fixed_header);

        // Domain-separate RCSTR-embedded RCENC via flags bit1 (`rcstr_header = true`).
        let rcenc_header = encrypt_with_entropy(
            entropy,
            key_payload.as_ref(),
            ctx,
            EnvelopeFlags::rcstr_header(),
            recipients,
        )?;

        let mut full_header = Vec::with_capacity(RCSTR_FIXED_HEADER_LEN + rcenc_header.len());
        full_header.extend_from_slice(&fixed_header);
        full_header.extend_from_slice(&rcenc_header);

        let encryptor = Self {
            file_dek,
            file_nonce_prefix,
            tenant_id: ctx.tenant_id,
            file_id: ctx.resource_id,
            chunk_size: chunk_size_usize,
            next_chunk_index: 0,
            finished: false,
        };
        Ok((encryptor, full_header))
    }

    /// Initializes a new `RCSTR` v1 stream using the platform CSPRNG (`getrandom`),
    /// returning `(encryptor, encoded_rcstr_header)`.
    pub fn new(
        ctx: &EnvelopeContext,
        chunk_size: u32,
        recipients: &[RecipientSpec<'_>],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        Self::new_with_entropy(&mut OsEntropy, ctx, chunk_size, recipients)
    }

    /// Initializes a new `RCSTR` v1 stream using a caller-supplied `CryptoRng`.
    pub fn new_with_rng<R: CryptoRng + ?Sized>(
        rng: &mut R,
        ctx: &EnvelopeContext,
        chunk_size: u32,
        recipients: &[RecipientSpec<'_>],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        Self::new_with_entropy(&mut RngEntropy(rng), ctx, chunk_size, recipients)
    }

    #[must_use]
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Encrypts the next chunk in order.
    ///
    /// Non-final chunks (`is_final == false`) must have `plaintext.len() == chunk_size`.
    /// The final chunk (`is_final == true`) may have `0..=chunk_size` bytes.
    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.finished {
            return Err(CryptoError::StreamFinished);
        }
        if (!is_final && plaintext.len() != self.chunk_size)
            || (is_final && plaintext.len() > self.chunk_size)
        {
            return Err(CryptoError::InvalidChunkLength);
        }

        let nonce = build_chunk_nonce(&self.file_nonce_prefix, self.next_chunk_index, is_final)?;
        let aad = build_chunk_aad(
            &self.tenant_id,
            &self.file_id,
            self.next_chunk_index,
            is_final,
        );

        let cipher = XChaCha20Poly1305::new(self.file_dek.as_bytes().into());
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        if is_final {
            self.finished = true;
        } else {
            self.next_chunk_index = self
                .next_chunk_index
                .checked_add(1)
                .ok_or(CryptoError::ChunkIndexOverflow)?;
        }

        Ok(ct)
    }
}

/// Streaming `RCSTR` v1 chunk decryptor.
///
/// Validates domain-separated `RCSTR` flags and exact wrapped payload length before
/// performing X-Wing decapsulation, authenticates the fixed header prefix in constant time,
/// and enforces strict chunk ordering and final-chunk authentication.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RcstrDecryptor {
    file_dek: SymmetricKey,
    file_nonce_prefix: [u8; FILE_NONCE_PREFIX_LEN],
    tenant_id: [u8; 16],
    file_id: [u8; 16],
    chunk_size: usize,
    next_chunk_index: u64,
    finished: bool,
}

impl RcstrDecryptor {
    /// Parses and authenticates the `RCSTR` v1 header at the start of `stream_prefix`,
    /// returning `(decryptor, consumed_header_bytes)`.
    pub fn new(
        stream_prefix: &[u8],
        expected_ctx: &EnvelopeContext,
        credential: &RecipientCredential<'_>,
    ) -> Result<(Self, usize), CryptoError> {
        let fixed_header = stream_prefix
            .get(..RCSTR_FIXED_HEADER_LEN)
            .ok_or(CryptoError::TruncatedInput)?;

        if !bool::from(fixed_header[0..5].ct_eq(RCSTR_MAGIC)) {
            return Err(CryptoError::InvalidMagic);
        }
        let version = fixed_header[5];
        if version != RCSTR_FORMAT_VERSION_V1 {
            return Err(CryptoError::UnsupportedFormatVersion(version));
        }

        let mut chunk_size_bytes = [0_u8; 4];
        chunk_size_bytes.copy_from_slice(&fixed_header[6..10]);
        let chunk_size = validate_chunk_size(u32::from_be_bytes(chunk_size_bytes))?;

        let mut file_nonce_prefix = [0_u8; FILE_NONCE_PREFIX_LEN];
        file_nonce_prefix.copy_from_slice(&fixed_header[10..26]);

        let rcenc_slice = &stream_prefix[RCSTR_FIXED_HEADER_LEN..];
        let (parsed_rcenc, rcenc_consumed) = parse_envelope_prefix(rcenc_slice)?;

        // Pre-decapsulation validation prevents DoS from forged 64 MiB headers or wrong flags.
        if parsed_rcenc.header.flags != EnvelopeFlags::rcstr_header() {
            return Err(CryptoError::UnsupportedFlags(
                parsed_rcenc.header.flags.to_byte(),
            ));
        }
        if parsed_rcenc.ciphertext.len() != RCSTR_KEY_CIPHERTEXT_LEN {
            return Err(CryptoError::StreamHeaderMismatch);
        }

        let decrypted = decrypt_parsed(&parsed_rcenc, expected_ctx, credential)?;
        if decrypted.plaintext.len() != RCSTR_KEY_PAYLOAD_LEN {
            return Err(CryptoError::StreamHeaderMismatch);
        }

        // Constant-time verify that the wire fixed header matches the AEAD-authenticated copy.
        let authed_fixed_header = &decrypted.plaintext[32..RCSTR_KEY_PAYLOAD_LEN];
        if !bool::from(authed_fixed_header.ct_eq(fixed_header)) {
            return Err(CryptoError::StreamHeaderMismatch);
        }

        let file_dek = SymmetricKey::try_from_slice(&decrypted.plaintext[0..32])?;

        let header_len = RCSTR_FIXED_HEADER_LEN
            .checked_add(rcenc_consumed)
            .ok_or(CryptoError::TruncatedInput)?;

        Ok((
            Self {
                file_dek,
                file_nonce_prefix,
                tenant_id: expected_ctx.tenant_id,
                file_id: expected_ctx.resource_id,
                chunk_size,
                next_chunk_index: 0,
                finished: false,
            },
            header_len,
        ))
    }

    #[must_use]
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Exact ciphertext length of each non-final chunk (`chunk_size + 16`).
    #[must_use]
    pub const fn ciphertext_chunk_len(&self) -> usize {
        self.chunk_size + AEAD_TAG_LEN
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Authenticates and decrypts the next chunk in order.
    pub fn decrypt_chunk(
        &mut self,
        ciphertext: &[u8],
        is_final: bool,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if self.finished {
            return Err(CryptoError::StreamFinished);
        }
        let max_ct_len = self.ciphertext_chunk_len();
        if (!is_final && ciphertext.len() != max_ct_len)
            || (is_final && !(AEAD_TAG_LEN..=max_ct_len).contains(&ciphertext.len()))
        {
            return Err(CryptoError::InvalidChunkLength);
        }

        let nonce = build_chunk_nonce(&self.file_nonce_prefix, self.next_chunk_index, is_final)?;
        let aad = build_chunk_aad(
            &self.tenant_id,
            &self.file_id,
            self.next_chunk_index,
            is_final,
        );

        let cipher = XChaCha20Poly1305::new(self.file_dek.as_bytes().into());
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::DecryptionFailed)?,
        );

        if is_final {
            self.finished = true;
        } else {
            self.next_chunk_index = self
                .next_chunk_index
                .checked_add(1)
                .ok_or(CryptoError::ChunkIndexOverflow)?;
        }

        Ok(pt)
    }
}

fn encrypt_all_chunks(
    encryptor: &mut RcstrEncryptor,
    header: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let chunk_size = encryptor.chunk_size();
    let chunk_count = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(chunk_size)
    };
    let mut out = Vec::with_capacity(
        header
            .len()
            .saturating_add(plaintext.len())
            .saturating_add(chunk_count.saturating_mul(AEAD_TAG_LEN)),
    );
    out.extend_from_slice(header);

    if plaintext.is_empty() {
        let final_ct = encryptor.encrypt_chunk(&[], true)?;
        out.extend_from_slice(&final_ct);
        return Ok(out);
    }

    let mut offset = 0;
    while offset < plaintext.len() {
        let remaining = plaintext.len() - offset;
        let is_final = remaining <= chunk_size;
        let end = if is_final {
            plaintext.len()
        } else {
            offset + chunk_size
        };
        let ct = encryptor.encrypt_chunk(&plaintext[offset..end], is_final)?;
        out.extend_from_slice(&ct);
        offset = end;
    }

    Ok(out)
}

/// One-shot convenience helper that encrypts an entire buffer using `RCSTR` v1 chunked framing
/// and the platform CSPRNG (`getrandom`).
pub fn encrypt_stream(
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    chunk_size: u32,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    let (mut encryptor, header) = RcstrEncryptor::new(ctx, chunk_size, recipients)?;
    encrypt_all_chunks(&mut encryptor, &header, plaintext)
}

/// One-shot convenience helper that encrypts an entire buffer using `RCSTR` v1 chunked framing
/// and a caller-supplied `CryptoRng`.
pub fn encrypt_stream_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    plaintext: &[u8],
    ctx: &EnvelopeContext,
    chunk_size: u32,
    recipients: &[RecipientSpec<'_>],
) -> Result<Vec<u8>, CryptoError> {
    let (mut encryptor, header) = RcstrEncryptor::new_with_rng(rng, ctx, chunk_size, recipients)?;
    encrypt_all_chunks(&mut encryptor, &header, plaintext)
}

/// One-shot convenience helper that authenticates and decrypts a complete `RCSTR` v1 stream.
pub fn decrypt_stream(
    stream_bytes: &[u8],
    expected_ctx: &EnvelopeContext,
    credential: &RecipientCredential<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (mut decryptor, header_len) = RcstrDecryptor::new(stream_bytes, expected_ctx, credential)?;
    let body = &stream_bytes[header_len..];
    if body.len() < AEAD_TAG_LEN {
        return Err(CryptoError::TruncatedInput);
    }

    let ct_chunk_len = decryptor.ciphertext_chunk_len();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(body.len()));
    let mut offset = 0;

    while offset < body.len() {
        let remaining = body.len() - offset;
        let is_final = remaining <= ct_chunk_len;
        let end = if is_final {
            body.len()
        } else {
            offset + ct_chunk_len
        };
        let chunk_pt = decryptor.decrypt_chunk(&body[offset..end], is_final)?;
        plaintext.extend_from_slice(&chunk_pt);
        offset = end;
    }

    if !decryptor.is_finished() {
        return Err(CryptoError::TruncatedInput);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_nonce_allows_max_chunk_index_and_rejects_overflow() {
        let prefix = [0x5A_u8; FILE_NONCE_PREFIX_LEN];
        let max_ok = build_chunk_nonce(&prefix, MAX_CHUNK_INDEX, false);
        assert!(max_ok.is_ok());
        if let Ok(nonce) = max_ok {
            assert_eq!(&nonce[0..16], &prefix);
            assert_eq!(&nonce[16..23], &[0xFF; 7]);
            assert_eq!(nonce[23], 0x00);
        }

        let max_final = build_chunk_nonce(&prefix, MAX_CHUNK_INDEX, true);
        assert!(max_final.is_ok());
        if let Ok(nonce) = max_final {
            assert_eq!(nonce[23], 0x01);
        }

        assert_eq!(
            build_chunk_nonce(&prefix, MAX_CHUNK_INDEX + 1, false),
            Err(CryptoError::ChunkIndexOverflow)
        );
        assert_eq!(
            build_chunk_nonce(&prefix, u64::MAX, true),
            Err(CryptoError::ChunkIndexOverflow)
        );
    }
}

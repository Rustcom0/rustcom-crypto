use core::fmt;

/// Cryptographic protocol, framing, and authentication errors.
///
/// Error variants intentionally omit secret key material and plaintext details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// OS or browser CSPRNG (`getrandom`) failed.
    RngFailure,
    /// Invalid or malformed X-Wing or Ed25519 public key encoding.
    InvalidPublicKey,
    /// Invalid secret key seed length.
    InvalidSecretKey,
    /// Invalid X-Wing ciphertext length or non-contributory X25519 shared secret.
    InvalidCiphertext,
    /// Envelope or stream header magic bytes did not match.
    InvalidMagic,
    /// Unsupported wire format version byte.
    UnsupportedFormatVersion(u8),
    /// Unsupported cipher suite identifier.
    UnsupportedCipherSuite(u8),
    /// Unknown or mismatched envelope kind.
    InvalidEnvelopeKind(u8),
    /// Unknown privacy tier byte (expected `1..=3`).
    InvalidPrivacyTier(u8),
    /// Reserved flag bits (bits 1..=7) were non-zero.
    UnsupportedFlags(u8),
    /// Recipient count outside `1..=8`.
    InvalidRecipientCount(usize),
    /// Duplicate `(recipient_type, key_id, key_version)` slot supplied on encryption.
    DuplicateRecipientSlot,
    /// Unknown or incompatible recipient type byte.
    InvalidRecipientType(u8),
    /// `kem_data_len` did not match the expected length for the recipient type.
    InvalidKemDataLength { expected: usize, actual: usize },
    /// Input buffer ended prematurely before the declared frame length.
    TruncatedInput,
    /// Unexpected trailing bytes followed a canonical frame.
    TrailingBytes,
    /// Payload length exceeded the safety bound or lacked space for the 16-byte AEAD tag.
    InvalidPayloadLength,
    /// No recipient slot in the envelope matched the caller's credential.
    RecipientNotFound,
    /// HKDF key derivation failed.
    KeyDerivationFailed,
    /// AEAD encryption failed.
    EncryptionFailed,
    /// AEAD decryption or authentication tag verification failed.
    DecryptionFailed,
    /// `RCSTR` chunk size outside `4096..=4_194_304`.
    InvalidChunkSize(u32),
    /// `RCSTR` chunk plaintext or ciphertext length violated framing rules.
    InvalidChunkLength,
    /// `RCSTR` stream already completed (`is_final = true`) and cannot process more chunks.
    StreamFinished,
    /// `RCSTR` chunk index overflowed the 7-byte nonce counter (`>= 2^56`).
    ChunkIndexOverflow,
    /// `RCSTR` header binding inside the wrapped `RCENC` payload did not match wire bytes.
    StreamHeaderMismatch,
    /// Ed25519 signature verification failed or signature bytes were malformed.
    InvalidSignature,
    /// Strict Account ID length, character set, or canonical pad bits were invalid.
    InvalidAccountIdFormat,
    /// Strict Account ID 2-character BLAKE3 checksum did not match.
    InvalidAccountIdChecksum,
    /// Private product password was empty or exceeded the maximum allowed length.
    InvalidPassword,
    /// Argon2id parameters or salt violated safe protocol bounds.
    InvalidArgon2Params,
    /// Multiple matching password recipient slots existed for the same resource.
    AmbiguousRecipientSlot,
    /// VIP `#k=...` URL fragment or token was malformed, duplicated, or failed checksum verification.
    InvalidInviteFragment,
    /// Decrypted `RCVIP` wrapped VIP group key payload failed structural or context checks.
    InvalidVipKeyPayload,
    /// Private product metadata attempted to use an internal reserved schema version.
    ReservedSchemaVersion(u16),
    /// Unknown vault role byte (expected `1=OrgMaster`, `2=Fulfillment`, `3=Accounting`).
    InvalidVaultRole(u8),
    /// Key version was zero or violated monotonic rotation rules.
    InvalidKeyVersion(u32),
    /// `StaffGrantV1` wire framing, version, context, or target key hash was invalid.
    InvalidStaffGrant,
    /// Decrypted `RCSKW` / `RCARC` staff or archive org key payload failed verification.
    InvalidStaffKeyPayload,
    /// Append-only Signed Key List (`SKL`) failed chain, monotonicity, signature, or checkpoint verification.
    InvalidSklChain,
    /// BIP-39 24-word recovery mnemonic failed length, word-count, character, or wordlist validation.
    InvalidMnemonicFormat,
    /// BIP-39 24-word recovery mnemonic 8-bit SHA-256 checksum did not match.
    InvalidMnemonicChecksum,
    /// Decrypted `RCREC` recovery backup payload failed structural or context verification.
    InvalidRecoveryPayload,
    /// Shamir threshold, total share count, split ID, or share index violated safe bounds.
    InvalidShamirParams,
    /// Shamir `RCSHR` share failed framing, commitment, metadata-match, uniqueness, or consistency checks.
    InvalidShamirShare,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RngFailure => f.write_str("cryptographic RNG failure"),
            Self::InvalidPublicKey => f.write_str("invalid public key"),
            Self::InvalidSecretKey => f.write_str("invalid secret key seed length"),
            Self::InvalidCiphertext => f.write_str("invalid or non-contributory X-Wing ciphertext"),
            Self::InvalidMagic => f.write_str("invalid envelope magic bytes"),
            Self::UnsupportedFormatVersion(v) => write!(f, "unsupported format version: 0x{v:02x}"),
            Self::UnsupportedCipherSuite(c) => write!(f, "unsupported cipher suite: 0x{c:02x}"),
            Self::InvalidEnvelopeKind(k) => {
                write!(f, "invalid or mismatched envelope kind: 0x{k:02x}")
            }
            Self::InvalidPrivacyTier(p) => write!(f, "invalid privacy tier: 0x{p:02x}"),
            Self::UnsupportedFlags(flags) => write!(f, "unsupported reserved flags: 0x{flags:02x}"),
            Self::InvalidRecipientCount(n) => {
                write!(f, "invalid recipient count: {n} (expected 1..=8)")
            }
            Self::DuplicateRecipientSlot => f.write_str("duplicate recipient slot in envelope"),
            Self::InvalidRecipientType(t) => write!(f, "invalid recipient type: 0x{t:02x}"),
            Self::InvalidKemDataLength { expected, actual } => {
                write!(
                    f,
                    "invalid kem_data length: expected {expected}, got {actual}"
                )
            }
            Self::TruncatedInput => f.write_str("truncated binary frame"),
            Self::TrailingBytes => f.write_str("unexpected trailing bytes after binary frame"),
            Self::InvalidPayloadLength => f.write_str("invalid payload length"),
            Self::RecipientNotFound => f.write_str("matching recipient slot not found"),
            Self::KeyDerivationFailed => f.write_str("key derivation failed"),
            Self::EncryptionFailed => f.write_str("AEAD encryption failed"),
            Self::DecryptionFailed => f.write_str("AEAD authentication/decryption failed"),
            Self::InvalidChunkSize(sz) => write!(f, "invalid stream chunk size: {sz}"),
            Self::InvalidChunkLength => f.write_str("invalid stream chunk length"),
            Self::StreamFinished => f.write_str("stream has already finalized"),
            Self::ChunkIndexOverflow => f.write_str("stream chunk counter overflow"),
            Self::StreamHeaderMismatch => f.write_str("stream header authentication mismatch"),
            Self::InvalidSignature => f.write_str("invalid Ed25519 signature"),
            Self::InvalidAccountIdFormat => f.write_str("invalid Strict Account ID format"),
            Self::InvalidAccountIdChecksum => f.write_str("invalid Strict Account ID checksum"),
            Self::InvalidPassword => f.write_str("invalid password length"),
            Self::InvalidArgon2Params => f.write_str("Argon2id parameters outside safe bounds"),
            Self::AmbiguousRecipientSlot => f.write_str("ambiguous matching recipient slot"),
            Self::InvalidInviteFragment => f.write_str("invalid VIP invite URL fragment"),
            Self::InvalidVipKeyPayload => f.write_str("invalid wrapped VIP group key payload"),
            Self::ReservedSchemaVersion(ver) => {
                write!(f, "reserved internal schema version: 0x{ver:04x}")
            }
            Self::InvalidVaultRole(role) => write!(f, "invalid vault role: 0x{role:02x}"),
            Self::InvalidKeyVersion(ver) => write!(f, "invalid key version: {ver}"),
            Self::InvalidStaffGrant => f.write_str("invalid StaffGrantV1 record"),
            Self::InvalidStaffKeyPayload => {
                f.write_str("invalid wrapped staff or archived org key payload")
            }
            Self::InvalidSklChain => f.write_str("invalid append-only Signed Key List chain"),
            Self::InvalidMnemonicFormat => f.write_str("invalid BIP-39 24-word mnemonic format"),
            Self::InvalidMnemonicChecksum => {
                f.write_str("invalid BIP-39 24-word mnemonic checksum")
            }
            Self::InvalidRecoveryPayload => f.write_str("invalid recovery backup payload"),
            Self::InvalidShamirParams => f.write_str("invalid Shamir secret sharing parameters"),
            Self::InvalidShamirShare => {
                f.write_str("invalid, mismatched, or inconsistent Shamir share")
            }
        }
    }
}

impl core::error::Error for CryptoError {}

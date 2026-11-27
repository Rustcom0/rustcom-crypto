use alloc::vec::Vec;

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::rcenc::{
    AEAD_TAG_LEN, RecipientCredential, RecipientSpec, decrypt_parsed, encrypt_with_entropy,
    parse_envelope,
};
use crate::xwing::{EntropySource, OsEntropy, RngEntropy, XWING_SECRET_SEED_LEN};
use crate::{
    CryptoError, ED25519_SIGNATURE_LEN, Ed25519SigningKey, Ed25519VerifyingKey, EnvelopeContext,
    EnvelopeFlags, EnvelopeKind, PrivacyTier, RecipientType, XWingPublicKey, XWingSecretKey,
};

/// Domain-separation prefix for `StaffGrantV1` Ed25519 signatures (`21 B`).
pub const STAFF_GRANT_DOMAIN: &[u8; 21] = b"sovret-v1-staff-grant";
/// Wire version byte for `StaffGrantV1` (`0x01`).
pub const STAFF_GRANT_VERSION_V1: u8 = 0x01;
/// Exact length of the canonical signed `StaffGrantV1` message (`114 B`):
/// `"sovret-v1-staff-grant"[21] || tenant_id[16] || vault_role[1] || store_key_ver[4 BE]
/// || target_staff_id[16] || BLAKE3(target_staff_xwing_pk)[32] || issued_at_unix[8 BE]
/// || grantor_staff_id[16]`.
pub const STAFF_GRANT_MSG_LEN: usize = 21 + 16 + 1 + 4 + 16 + 32 + 8 + 16;
/// Exact binary wire length of a serialized `StaffGrantV1` (`158 B`):
/// `version[1] || tenant_id[16] || vault_role[1] || store_key_ver[4 BE] || target_staff_id[16]
/// || target_staff_xwing_pk_hash[32] || issued_at_unix[8 BE] || grantor_staff_id[16]
/// || signature[64]`.
pub const STAFF_GRANT_WIRE_LEN: usize = 1 + 16 + 1 + 4 + 16 + 32 + 8 + 16 + ED25519_SIGNATURE_LEN;

/// `RCENC` `schema_version` (`1`) for wrapping a `StoreOrgKey` to a staff member (`RCSKW` v1).
pub const STAFF_KEY_WRAP_SCHEMA_VERSION: u16 = 1;
/// `RCENC` `schema_version` (`2`) for archiving a rotated `StoreOrgKey` under `v(N+1)` (`RCARC` v1).
pub const ORG_KEY_ARCHIVE_SCHEMA_VERSION: u16 = 2;

/// Inner payload magic for staff org key wraps (`"RCSKW"`).
pub const STAFF_KEY_WRAP_MAGIC: &[u8; 5] = b"RCSKW";
/// Inner payload version for `RCSKW` (`0x01`).
pub const STAFF_KEY_WRAP_VERSION_V1: u8 = 0x01;
/// Exact inner plaintext length of an `RCSKW` v1 staff key wrap (`75 B`):
/// `"RCSKW"[5] || ver[1] || tenant_id[16] || vault_role[1] || store_key_ver[4 BE]
/// || target_staff_id[16] || org_xwing_seed[32]`.
pub const STAFF_KEY_WRAP_PAYLOAD_LEN: usize = 5 + 1 + 16 + 1 + 4 + 16 + XWING_SECRET_SEED_LEN;

/// Inner payload magic for archived historical org keys (`"RCARC"`).
pub const ORG_KEY_ARCHIVE_MAGIC: &[u8; 5] = b"RCARC";
/// Inner payload version for `RCARC` (`0x01`).
pub const ORG_KEY_ARCHIVE_VERSION_V1: u8 = 0x01;
/// Exact inner plaintext length of an `RCARC` v1 archived org key (`63 B`):
/// `"RCARC"[5] || ver[1] || tenant_id[16] || vault_role[1] || archived_key_ver[4 BE]
/// || new_key_ver[4 BE] || archived_org_xwing_seed[32]`.
pub const ORG_KEY_ARCHIVE_PAYLOAD_LEN: usize = 5 + 1 + 16 + 1 + 4 + 4 + XWING_SECRET_SEED_LEN;

/// Store cryptographic vault role for Proton-style role-split organization keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VaultRole {
    /// Store master organization key (`0x01`).
    OrgMaster = 1,
    /// Fulfillment-scoped key decrypting shipping addresses and fulfillment instructions (`0x02`).
    Fulfillment = 2,
    /// Accounting-scoped key decrypting 6-10 year VAT / EN 16931 invoice records (`0x03`).
    Accounting = 3,
}

impl VaultRole {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(Self::OrgMaster),
            2 => Ok(Self::Fulfillment),
            3 => Ok(Self::Accounting),
            other => Err(CryptoError::InvalidVaultRole(other)),
        }
    }

    /// Zero-based dense index (`0..3`) for fixed-size per-role tracking arrays.
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::OrgMaster => 0,
            Self::Fulfillment => 1,
            Self::Accounting => 2,
        }
    }
}

/// Computes `BLAKE3(xwing_pk.to_bytes())` (`32 B`) for `StaffGrantV1` target key binding.
#[must_use]
pub fn hash_xwing_public_key(pk: &XWingPublicKey) -> [u8; 32] {
    let bytes = pk.to_bytes();
    *blake3::hash(&bytes).as_bytes()
}

/// Admin-signed Proton-style multi-staff organization key grant (`StaffGrantV1`).
///
/// Cryptographically binds `(tenant_id, vault_role, store_key_ver, target_staff_id,
/// BLAKE3(target_staff_xwing_pk), issued_at_unix, grantor_staff_id)` under the grantor's
/// Ed25519 signing key so a compromised backend cannot inject rogue staff keys or replay grants
/// across tenants, roles, or key versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaffGrantV1 {
    tenant_id: [u8; 16],
    vault_role: VaultRole,
    store_key_ver: u32,
    target_staff_id: [u8; 16],
    target_staff_xwing_pk_hash: [u8; 32],
    issued_at_unix: u64,
    grantor_staff_id: [u8; 16],
    signature: [u8; ED25519_SIGNATURE_LEN],
}

impl StaffGrantV1 {
    /// Creates and signs a canonical `StaffGrantV1` authorizing `target_staff_id` (owning
    /// `target_staff_xwing_pk`) to hold `(tenant_id, vault_role, store_key_ver)`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        tenant_id: [u8; 16],
        vault_role: VaultRole,
        store_key_ver: u32,
        target_staff_id: [u8; 16],
        target_staff_xwing_pk: &XWingPublicKey,
        issued_at_unix: u64,
        grantor_staff_id: [u8; 16],
        grantor_ed25519_sk: &Ed25519SigningKey,
    ) -> Result<Self, CryptoError> {
        if store_key_ver == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        if issued_at_unix == 0 {
            return Err(CryptoError::InvalidStaffGrant);
        }

        let target_staff_xwing_pk_hash = hash_xwing_public_key(target_staff_xwing_pk);
        let mut grant = Self {
            tenant_id,
            vault_role,
            store_key_ver,
            target_staff_id,
            target_staff_xwing_pk_hash,
            issued_at_unix,
            grantor_staff_id,
            signature: [0_u8; ED25519_SIGNATURE_LEN],
        };
        let msg = grant.signing_message();
        grant.signature = grantor_ed25519_sk.sign(&msg);
        Ok(grant)
    }

    /// Reconstructs a `StaffGrantV1` from pre-parsed fields (e.g. database columns) without
    /// assuming the signature is valid. Callers MUST call [`Self::verify`] before trusting.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        tenant_id: [u8; 16],
        vault_role: VaultRole,
        store_key_ver: u32,
        target_staff_id: [u8; 16],
        target_staff_xwing_pk_hash: [u8; 32],
        issued_at_unix: u64,
        grantor_staff_id: [u8; 16],
        signature: [u8; ED25519_SIGNATURE_LEN],
    ) -> Result<Self, CryptoError> {
        if store_key_ver == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        if issued_at_unix == 0 {
            return Err(CryptoError::InvalidStaffGrant);
        }
        Ok(Self {
            tenant_id,
            vault_role,
            store_key_ver,
            target_staff_id,
            target_staff_xwing_pk_hash,
            issued_at_unix,
            grantor_staff_id,
            signature,
        })
    }

    /// Builds the exact 114-byte canonical `grant_msg` signed by Ed25519.
    #[must_use]
    pub fn signing_message(&self) -> [u8; STAFF_GRANT_MSG_LEN] {
        let mut msg = [0_u8; STAFF_GRANT_MSG_LEN];
        msg[0..21].copy_from_slice(STAFF_GRANT_DOMAIN);
        msg[21..37].copy_from_slice(&self.tenant_id);
        msg[37] = self.vault_role.as_u8();
        msg[38..42].copy_from_slice(&self.store_key_ver.to_be_bytes());
        msg[42..58].copy_from_slice(&self.target_staff_id);
        msg[58..90].copy_from_slice(&self.target_staff_xwing_pk_hash);
        msg[90..98].copy_from_slice(&self.issued_at_unix.to_be_bytes());
        msg[98..114].copy_from_slice(&self.grantor_staff_id);
        msg
    }

    /// Serializes this grant into its fixed 158-byte canonical binary representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; STAFF_GRANT_WIRE_LEN] {
        let mut out = [0_u8; STAFF_GRANT_WIRE_LEN];
        out[0] = STAFF_GRANT_VERSION_V1;
        out[1..17].copy_from_slice(&self.tenant_id);
        out[17] = self.vault_role.as_u8();
        out[18..22].copy_from_slice(&self.store_key_ver.to_be_bytes());
        out[22..38].copy_from_slice(&self.target_staff_id);
        out[38..70].copy_from_slice(&self.target_staff_xwing_pk_hash);
        out[70..78].copy_from_slice(&self.issued_at_unix.to_be_bytes());
        out[78..94].copy_from_slice(&self.grantor_staff_id);
        out[94..158].copy_from_slice(&self.signature);
        out
    }

    /// Parses a fixed 158-byte canonical binary `StaffGrantV1`, rejecting invalid versions,
    /// trailing/truncated bytes, unknown roles, zero key versions, and zero timestamps.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < STAFF_GRANT_WIRE_LEN {
            return Err(CryptoError::TruncatedInput);
        }
        if bytes.len() > STAFF_GRANT_WIRE_LEN {
            return Err(CryptoError::TrailingBytes);
        }
        if bytes[0] != STAFF_GRANT_VERSION_V1 {
            return Err(CryptoError::UnsupportedFormatVersion(bytes[0]));
        }

        let mut tenant_id = [0_u8; 16];
        tenant_id.copy_from_slice(&bytes[1..17]);
        let vault_role = VaultRole::from_u8(bytes[17])?;
        let store_key_ver = u32::from_be_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        let mut target_staff_id = [0_u8; 16];
        target_staff_id.copy_from_slice(&bytes[22..38]);
        let mut target_staff_xwing_pk_hash = [0_u8; 32];
        target_staff_xwing_pk_hash.copy_from_slice(&bytes[38..70]);
        let issued_at_unix = u64::from_be_bytes([
            bytes[70], bytes[71], bytes[72], bytes[73], bytes[74], bytes[75], bytes[76], bytes[77],
        ]);
        let mut grantor_staff_id = [0_u8; 16];
        grantor_staff_id.copy_from_slice(&bytes[78..94]);
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[94..158]);

        Self::from_parts(
            tenant_id,
            vault_role,
            store_key_ver,
            target_staff_id,
            target_staff_xwing_pk_hash,
            issued_at_unix,
            grantor_staff_id,
            signature,
        )
    }

    /// Strictly verifies the `StaffGrantV1` context bindings and Ed25519 signature against the
    /// trusted grantor identity and target staff X-Wing public key.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        grantor_ed25519_vk: &Ed25519VerifyingKey,
        expected_grantor_staff_id: &[u8; 16],
        expected_tenant_id: &[u8; 16],
        expected_vault_role: VaultRole,
        expected_store_key_ver: u32,
        expected_target_staff_id: &[u8; 16],
        expected_target_xwing_pk: &XWingPublicKey,
    ) -> Result<(), CryptoError> {
        if self.store_key_ver == 0 || expected_store_key_ver == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        if self.issued_at_unix == 0
            || self.vault_role != expected_vault_role
            || self.store_key_ver != expected_store_key_ver
        {
            return Err(CryptoError::InvalidStaffGrant);
        }

        let expected_pk_hash = hash_xwing_public_key(expected_target_xwing_pk);
        let ctx_match = self.tenant_id.ct_eq(expected_tenant_id)
            & self.grantor_staff_id.ct_eq(expected_grantor_staff_id)
            & self.target_staff_id.ct_eq(expected_target_staff_id)
            & self.target_staff_xwing_pk_hash.ct_eq(&expected_pk_hash);
        if !bool::from(ctx_match) {
            return Err(CryptoError::InvalidStaffGrant);
        }

        let msg = self.signing_message();
        grantor_ed25519_vk.verify_strict(&msg, &self.signature)
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &[u8; 16] {
        &self.tenant_id
    }

    #[must_use]
    pub const fn vault_role(&self) -> VaultRole {
        self.vault_role
    }

    #[must_use]
    pub const fn store_key_ver(&self) -> u32 {
        self.store_key_ver
    }

    #[must_use]
    pub const fn target_staff_id(&self) -> &[u8; 16] {
        &self.target_staff_id
    }

    #[must_use]
    pub const fn target_staff_xwing_pk_hash(&self) -> &[u8; 32] {
        &self.target_staff_xwing_pk_hash
    }

    #[must_use]
    pub const fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    #[must_use]
    pub const fn grantor_staff_id(&self) -> &[u8; 16] {
        &self.grantor_staff_id
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.signature
    }
}

#[allow(clippy::too_many_arguments)]
fn wrap_staff_org_key_with_entropy<E: EntropySource>(
    entropy: &mut E,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    vault_role: VaultRole,
    store_key_ver: u32,
    org_xwing_sk: &XWingSecretKey,
    target_staff_id: [u8; 16],
    target_staff_key_version: u32,
    target_staff_xwing_pk: &XWingPublicKey,
    issued_at_unix: u64,
    grantor_staff_id: [u8; 16],
    grantor_ed25519_sk: &Ed25519SigningKey,
) -> Result<(StaffGrantV1, Vec<u8>), CryptoError> {
    if target_staff_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }

    let grant = StaffGrantV1::sign(
        tenant_id,
        vault_role,
        store_key_ver,
        target_staff_id,
        target_staff_xwing_pk,
        issued_at_unix,
        grantor_staff_id,
        grantor_ed25519_sk,
    )?;

    let seed = org_xwing_sk.to_seed_bytes();
    let mut payload = Zeroizing::new([0_u8; STAFF_KEY_WRAP_PAYLOAD_LEN]);
    payload[0..5].copy_from_slice(STAFF_KEY_WRAP_MAGIC);
    payload[5] = STAFF_KEY_WRAP_VERSION_V1;
    payload[6..22].copy_from_slice(&tenant_id);
    payload[22] = vault_role.as_u8();
    payload[23..27].copy_from_slice(&store_key_ver.to_be_bytes());
    payload[27..43].copy_from_slice(&target_staff_id);
    payload[43..75].copy_from_slice(seed.as_ref());

    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::StaffKeyWrap,
        tenant_id,
        resource_id: target_staff_id,
        privacy_tier,
        schema_version: STAFF_KEY_WRAP_SCHEMA_VERSION,
    };
    let recipient = RecipientSpec::XWing {
        recipient_type: RecipientType::XWingStaffKey,
        key_id: target_staff_xwing_pk.key_id(),
        key_version: target_staff_key_version,
        public_key: target_staff_xwing_pk,
    };

    let envelope = encrypt_with_entropy(
        entropy,
        payload.as_ref(),
        &ctx,
        EnvelopeFlags::default(),
        &[recipient],
    )?;

    Ok((grant, envelope))
}

/// Signs a [`StaffGrantV1`] and wraps `org_xwing_sk` into an `RCENC(kind = StaffKeyWrap)`
/// `RCSKW` v1 envelope addressed to `target_staff_xwing_pk`.
#[allow(clippy::too_many_arguments)]
pub fn wrap_staff_org_key(
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    vault_role: VaultRole,
    store_key_ver: u32,
    org_xwing_sk: &XWingSecretKey,
    target_staff_id: [u8; 16],
    target_staff_key_version: u32,
    target_staff_xwing_pk: &XWingPublicKey,
    issued_at_unix: u64,
    grantor_staff_id: [u8; 16],
    grantor_ed25519_sk: &Ed25519SigningKey,
) -> Result<(StaffGrantV1, Vec<u8>), CryptoError> {
    wrap_staff_org_key_with_entropy(
        &mut OsEntropy,
        tenant_id,
        privacy_tier,
        vault_role,
        store_key_ver,
        org_xwing_sk,
        target_staff_id,
        target_staff_key_version,
        target_staff_xwing_pk,
        issued_at_unix,
        grantor_staff_id,
        grantor_ed25519_sk,
    )
}

/// Deterministic `CryptoRng` variant of [`wrap_staff_org_key`] for KAT vectors and tests.
#[allow(clippy::too_many_arguments)]
pub fn wrap_staff_org_key_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    vault_role: VaultRole,
    store_key_ver: u32,
    org_xwing_sk: &XWingSecretKey,
    target_staff_id: [u8; 16],
    target_staff_key_version: u32,
    target_staff_xwing_pk: &XWingPublicKey,
    issued_at_unix: u64,
    grantor_staff_id: [u8; 16],
    grantor_ed25519_sk: &Ed25519SigningKey,
) -> Result<(StaffGrantV1, Vec<u8>), CryptoError> {
    wrap_staff_org_key_with_entropy(
        &mut RngEntropy(rng),
        tenant_id,
        privacy_tier,
        vault_role,
        store_key_ver,
        org_xwing_sk,
        target_staff_id,
        target_staff_key_version,
        target_staff_xwing_pk,
        issued_at_unix,
        grantor_staff_id,
        grantor_ed25519_sk,
    )
}

/// Verifies `grant` under `grantor_ed25519_vk`, decrypts the `RCSKW` v1 staff key wrap with
/// `target_staff_xwing_sk`, validates all inner bindings, and verifies the unwrapped key matches
/// `expected_org_pk` (anchored in the store's verified Signed Key List).
#[allow(clippy::too_many_arguments)]
pub fn unwrap_staff_org_key(
    grant: &StaffGrantV1,
    wrapped_envelope: &[u8],
    grantor_ed25519_vk: &Ed25519VerifyingKey,
    expected_grantor_staff_id: &[u8; 16],
    expected_tenant_id: &[u8; 16],
    privacy_tier: PrivacyTier,
    expected_vault_role: VaultRole,
    expected_store_key_ver: u32,
    expected_target_staff_id: &[u8; 16],
    target_staff_key_version: u32,
    target_staff_xwing_sk: &XWingSecretKey,
    expected_org_pk: &XWingPublicKey,
) -> Result<XWingSecretKey, CryptoError> {
    if target_staff_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }

    let target_staff_pk = target_staff_xwing_sk.public_key();
    grant.verify(
        grantor_ed25519_vk,
        expected_grantor_staff_id,
        expected_tenant_id,
        expected_vault_role,
        expected_store_key_ver,
        expected_target_staff_id,
        &target_staff_pk,
    )?;

    let parsed = parse_envelope(wrapped_envelope)?;
    if parsed.header.flags.to_byte() != 0 {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::StaffKeyWrap {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }
    if parsed.slots.len() != 1
        || parsed.ciphertext.len() != STAFF_KEY_WRAP_PAYLOAD_LEN + AEAD_TAG_LEN
    {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::StaffKeyWrap,
        tenant_id: *expected_tenant_id,
        resource_id: *expected_target_staff_id,
        privacy_tier,
        schema_version: STAFF_KEY_WRAP_SCHEMA_VERSION,
    };
    let cred = RecipientCredential::XWing {
        recipient_type: RecipientType::XWingStaffKey,
        key_id: target_staff_pk.key_id(),
        key_version: target_staff_key_version,
        secret_key: target_staff_xwing_sk,
    };
    let decrypted = decrypt_parsed(&parsed, &ctx, &cred)?;
    let pt = decrypted.plaintext.as_slice();
    if pt.len() != STAFF_KEY_WRAP_PAYLOAD_LEN {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }
    if pt[0..5] != *STAFF_KEY_WRAP_MAGIC || pt[5] != STAFF_KEY_WRAP_VERSION_V1 {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let role = VaultRole::from_u8(pt[22])?;
    let ver = u32::from_be_bytes([pt[23], pt[24], pt[25], pt[26]]);
    let body_match = pt[6..22].ct_eq(expected_tenant_id)
        & pt[27..43].ct_eq(expected_target_staff_id)
        & role.as_u8().ct_eq(&expected_vault_role.as_u8())
        & ver
            .to_be_bytes()
            .ct_eq(&expected_store_key_ver.to_be_bytes());
    if !bool::from(body_match) {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let (org_sk, derived_pk) = XWingSecretKey::from_seed_slice(&pt[43..75])?;
    if !bool::from(derived_pk.to_bytes().ct_eq(&expected_org_pk.to_bytes())) {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }
    Ok(org_sk)
}

#[allow(clippy::too_many_arguments)]
fn archive_org_key_with_entropy<E: EntropySource>(
    entropy: &mut E,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    vault_role: VaultRole,
    archived_key_version: u32,
    archived_org_sk: &XWingSecretKey,
    new_key_version: u32,
    new_org_pk: &XWingPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    if archived_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    if new_key_version <= archived_key_version {
        return Err(CryptoError::InvalidKeyVersion(new_key_version));
    }
    let archived_pk = archived_org_sk.public_key();
    if bool::from(archived_pk.to_bytes().ct_eq(&new_org_pk.to_bytes())) {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let seed = archived_org_sk.to_seed_bytes();
    let mut payload = Zeroizing::new([0_u8; ORG_KEY_ARCHIVE_PAYLOAD_LEN]);
    payload[0..5].copy_from_slice(ORG_KEY_ARCHIVE_MAGIC);
    payload[5] = ORG_KEY_ARCHIVE_VERSION_V1;
    payload[6..22].copy_from_slice(&tenant_id);
    payload[22] = vault_role.as_u8();
    payload[23..27].copy_from_slice(&archived_key_version.to_be_bytes());
    payload[27..31].copy_from_slice(&new_key_version.to_be_bytes());
    payload[31..63].copy_from_slice(seed.as_ref());

    let new_key_id = new_org_pk.key_id();
    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::StaffKeyWrap,
        tenant_id,
        resource_id: new_key_id,
        privacy_tier,
        schema_version: ORG_KEY_ARCHIVE_SCHEMA_VERSION,
    };
    let recipient = RecipientSpec::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: new_key_id,
        key_version: new_key_version,
        public_key: new_org_pk,
    };

    encrypt_with_entropy(
        entropy,
        payload.as_ref(),
        &ctx,
        EnvelopeFlags::default(),
        &[recipient],
    )
}

/// Archives a rotated historical `StoreOrgKey` (`v(N)`) encrypted under the successor key
/// `v(N+1)` inside `RCENC(kind = StaffKeyWrap, schema_version = 2)` (`RCARC` v1) to preserve
/// 6-10 year VAT / order archive readability after staff revocation.
#[allow(clippy::too_many_arguments)]
pub fn archive_org_key(
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    vault_role: VaultRole,
    archived_key_version: u32,
    archived_org_sk: &XWingSecretKey,
    new_key_version: u32,
    new_org_pk: &XWingPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    archive_org_key_with_entropy(
        &mut OsEntropy,
        tenant_id,
        privacy_tier,
        vault_role,
        archived_key_version,
        archived_org_sk,
        new_key_version,
        new_org_pk,
    )
}

/// Deterministic `CryptoRng` variant of [`archive_org_key`] for KAT vectors and tests.
#[allow(clippy::too_many_arguments)]
pub fn archive_org_key_with_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
    tenant_id: [u8; 16],
    privacy_tier: PrivacyTier,
    vault_role: VaultRole,
    archived_key_version: u32,
    archived_org_sk: &XWingSecretKey,
    new_key_version: u32,
    new_org_pk: &XWingPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    archive_org_key_with_entropy(
        &mut RngEntropy(rng),
        tenant_id,
        privacy_tier,
        vault_role,
        archived_key_version,
        archived_org_sk,
        new_key_version,
        new_org_pk,
    )
}

/// Unwraps an archived historical `StoreOrgKey` (`v(N)`) using the successor key `v(N+1)` and
/// verifies that the recovered secret key matches `expected_archived_org_pk` from the verified SKL.
#[allow(clippy::too_many_arguments)]
pub fn unwrap_archived_org_key(
    archived_envelope: &[u8],
    expected_tenant_id: &[u8; 16],
    privacy_tier: PrivacyTier,
    expected_vault_role: VaultRole,
    expected_archived_key_version: u32,
    new_key_version: u32,
    new_org_sk: &XWingSecretKey,
    expected_archived_org_pk: &XWingPublicKey,
) -> Result<XWingSecretKey, CryptoError> {
    if expected_archived_key_version == 0 {
        return Err(CryptoError::InvalidKeyVersion(0));
    }
    if new_key_version <= expected_archived_key_version {
        return Err(CryptoError::InvalidKeyVersion(new_key_version));
    }

    let wrapping_pk = new_org_sk.public_key();
    if bool::from(
        wrapping_pk
            .to_bytes()
            .ct_eq(&expected_archived_org_pk.to_bytes()),
    ) {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let parsed = parse_envelope(archived_envelope)?;
    if parsed.header.flags.to_byte() != 0 {
        return Err(CryptoError::UnsupportedFlags(parsed.header.flags.to_byte()));
    }
    if parsed.header.envelope_kind != EnvelopeKind::StaffKeyWrap {
        return Err(CryptoError::InvalidEnvelopeKind(
            parsed.header.envelope_kind.as_u8(),
        ));
    }
    if parsed.slots.len() != 1
        || parsed.ciphertext.len() != ORG_KEY_ARCHIVE_PAYLOAD_LEN + AEAD_TAG_LEN
    {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let new_key_id = wrapping_pk.key_id();
    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::StaffKeyWrap,
        tenant_id: *expected_tenant_id,
        resource_id: new_key_id,
        privacy_tier,
        schema_version: ORG_KEY_ARCHIVE_SCHEMA_VERSION,
    };
    let cred = RecipientCredential::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: new_key_id,
        key_version: new_key_version,
        secret_key: new_org_sk,
    };
    let decrypted = decrypt_parsed(&parsed, &ctx, &cred)?;
    let pt = decrypted.plaintext.as_slice();
    if pt.len() != ORG_KEY_ARCHIVE_PAYLOAD_LEN {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }
    if pt[0..5] != *ORG_KEY_ARCHIVE_MAGIC || pt[5] != ORG_KEY_ARCHIVE_VERSION_V1 {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let role = VaultRole::from_u8(pt[22])?;
    let archived_ver = u32::from_be_bytes([pt[23], pt[24], pt[25], pt[26]]);
    let wrapping_ver = u32::from_be_bytes([pt[27], pt[28], pt[29], pt[30]]);
    let body_match = pt[6..22].ct_eq(expected_tenant_id)
        & role.as_u8().ct_eq(&expected_vault_role.as_u8())
        & archived_ver
            .to_be_bytes()
            .ct_eq(&expected_archived_key_version.to_be_bytes())
        & wrapping_ver
            .to_be_bytes()
            .ct_eq(&new_key_version.to_be_bytes());
    if !bool::from(body_match) {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }

    let (archived_sk, derived_pk) = XWingSecretKey::from_seed_slice(&pt[31..63])?;
    if !bool::from(
        derived_pk
            .to_bytes()
            .ct_eq(&expected_archived_org_pk.to_bytes()),
    ) {
        return Err(CryptoError::InvalidStaffKeyPayload);
    }
    Ok(archived_sk)
}

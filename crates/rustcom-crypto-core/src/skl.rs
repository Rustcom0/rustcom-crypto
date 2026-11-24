use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use crate::staff_grant::hash_xwing_public_key;
use crate::{
    CryptoError, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey,
    Ed25519VerifyingKey, VaultRole, XWING_PUBLIC_KEY_LEN, XWingPublicKey,
};

/// Domain-separation prefix for canonical `SklEntryV1` unsigned bodies (`20 B`).
pub const SKL_ENTRY_DOMAIN: &[u8; 20] = b"rustcom-v1-skl-entry";
/// Domain-separation prefix for `StoreIdentity_Ed25519` rotation cross-signatures (`21 B`).
pub const SKL_ROTATE_DOMAIN: &[u8; 21] = b"rustcom-v1-skl-rotate";
/// Wire version byte for `SklEntryV1` (`0x01`).
pub const SKL_ENTRY_VERSION_V1: u8 = 0x01;
/// Exact length of the canonical unsigned `SklEntryV1` body (`1,338 B`):
/// `"rustcom-v1-skl-entry"[20] || ver[1] || tenant_id[16] || seq[8 BE] || vault_role[1]
/// || key_version[4 BE] || xwing_pk[1216] || identity_ed25519_pk[32] || issued_at_unix[8 BE]
/// || prev_entry_hash[32]`.
pub const SKL_BODY_LEN: usize =
    20 + 1 + 16 + 8 + 1 + 4 + XWING_PUBLIC_KEY_LEN + ED25519_PUBLIC_KEY_LEN + 8 + 32;
/// Exact length of the canonical identity-rotation cross-sign message (`117 B`):
/// `"rustcom-v1-skl-rotate"[21] || BLAKE3(canonical_body)[32] || prev_identity_pk[32]
/// || new_identity_pk[32]`.
pub const SKL_ROTATE_MSG_LEN: usize = 21 + 32 + ED25519_PUBLIC_KEY_LEN + ED25519_PUBLIC_KEY_LEN;
/// Canonical wire length of an `SklEntryV1` without an identity rotation cross-signature (`1,403 B`).
pub const SKL_ENTRY_BASE_WIRE_LEN: usize = SKL_BODY_LEN + ED25519_SIGNATURE_LEN + 1;
/// Canonical wire length of an `SklEntryV1` with an identity rotation cross-signature (`1,467 B`).
pub const SKL_ENTRY_ROTATE_WIRE_LEN: usize = SKL_ENTRY_BASE_WIRE_LEN + ED25519_SIGNATURE_LEN;
/// Upper bound on SKL entries verified in a single call to bound WASM verification work.
pub const MAX_SKL_ENTRIES: usize = 4_096;

/// Builds the 117-byte canonical cross-signature message authorizing an identity key rotation
/// from `prev_identity_pk` to `new_identity_pk` for an entry whose body is `canonical_body`.
fn build_rotation_message(
    canonical_body: &[u8],
    prev_identity_pk: &Ed25519VerifyingKey,
    new_identity_pk: &Ed25519VerifyingKey,
) -> [u8; SKL_ROTATE_MSG_LEN] {
    let body_hash = blake3::hash(canonical_body);
    let mut msg = [0_u8; SKL_ROTATE_MSG_LEN];
    msg[0..21].copy_from_slice(SKL_ROTATE_DOMAIN);
    msg[21..53].copy_from_slice(body_hash.as_bytes());
    msg[53..85].copy_from_slice(&prev_identity_pk.to_bytes());
    msg[85..117].copy_from_slice(&new_identity_pk.to_bytes());
    msg
}

/// Single entry in a store's append-only Ed25519 Signed Key List (`/.well-known/rustcom-skl.json`).
///
/// Chained via `prev_entry_hash = BLAKE3(canonical_bytes(entry[n - 1]))` and verified by
/// checkout WASM and admin clients before encrypting customer PII or unwrapping org keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SklEntryV1 {
    tenant_id: [u8; 16],
    seq: u64,
    vault_role: VaultRole,
    key_version: u32,
    xwing_pk: XWingPublicKey,
    identity_ed25519_pk: Ed25519VerifyingKey,
    issued_at_unix: u64,
    prev_entry_hash: [u8; 32],
    signature: [u8; ED25519_SIGNATURE_LEN],
    rotation_cross_signature: Option<[u8; ED25519_SIGNATURE_LEN]>,
}

impl SklEntryV1 {
    /// Creates and signs the genesis (`seq = 0`, `key_version = 1`) entry of a store's SKL.
    pub fn sign_genesis(
        tenant_id: [u8; 16],
        vault_role: VaultRole,
        xwing_pk: XWingPublicKey,
        identity_ed25519_sk: &Ed25519SigningKey,
        issued_at_unix: u64,
    ) -> Result<Self, CryptoError> {
        if issued_at_unix == 0 {
            return Err(CryptoError::InvalidSklChain);
        }
        let verifying_pk = identity_ed25519_sk.verifying_key();
        let mut entry = Self {
            tenant_id,
            seq: 0,
            vault_role,
            key_version: 1,
            xwing_pk,
            identity_ed25519_pk: verifying_pk,
            issued_at_unix,
            prev_entry_hash: [0_u8; 32],
            signature: [0_u8; ED25519_SIGNATURE_LEN],
            rotation_cross_signature: None,
        };
        let body = entry.canonical_body_bytes();
        entry.signature = identity_ed25519_sk.sign(&body);
        Ok(entry)
    }

    /// Appends and signs the next entry in the store's SKL using the active `StoreIdentity` key.
    pub fn sign_next(
        prev_entry: &Self,
        vault_role: VaultRole,
        key_version: u32,
        xwing_pk: XWingPublicKey,
        current_identity_sk: &Ed25519SigningKey,
        issued_at_unix: u64,
    ) -> Result<Self, CryptoError> {
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        if vault_role == prev_entry.vault_role
            && prev_entry.key_version.checked_add(1) != Some(key_version)
        {
            return Err(CryptoError::InvalidKeyVersion(key_version));
        }
        if xwing_pk == prev_entry.xwing_pk
            || issued_at_unix == 0
            || issued_at_unix < prev_entry.issued_at_unix
        {
            return Err(CryptoError::InvalidSklChain);
        }
        let identity_pk = current_identity_sk.verifying_key();
        if identity_pk != prev_entry.identity_ed25519_pk {
            return Err(CryptoError::InvalidSklChain);
        }
        let seq = prev_entry
            .seq
            .checked_add(1)
            .ok_or(CryptoError::InvalidSklChain)?;

        let mut entry = Self {
            tenant_id: prev_entry.tenant_id,
            seq,
            vault_role,
            key_version,
            xwing_pk,
            identity_ed25519_pk: identity_pk,
            issued_at_unix,
            prev_entry_hash: prev_entry.entry_hash(),
            signature: [0_u8; ED25519_SIGNATURE_LEN],
            rotation_cross_signature: None,
        };
        let body = entry.canonical_body_bytes();
        entry.signature = current_identity_sk.sign(&body);
        Ok(entry)
    }

    /// Appends an entry that rotates the store's `StoreIdentity_Ed25519` key from
    /// `prev_identity_sk` to `new_identity_sk`, signed by `new_identity_sk` and cross-signed by
    /// `prev_identity_sk`.
    pub fn sign_next_with_identity_rotation(
        prev_entry: &Self,
        vault_role: VaultRole,
        key_version: u32,
        xwing_pk: XWingPublicKey,
        prev_identity_sk: &Ed25519SigningKey,
        new_identity_sk: &Ed25519SigningKey,
        issued_at_unix: u64,
    ) -> Result<Self, CryptoError> {
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        if vault_role == prev_entry.vault_role
            && prev_entry.key_version.checked_add(1) != Some(key_version)
        {
            return Err(CryptoError::InvalidKeyVersion(key_version));
        }
        if xwing_pk == prev_entry.xwing_pk
            || issued_at_unix == 0
            || issued_at_unix < prev_entry.issued_at_unix
        {
            return Err(CryptoError::InvalidSklChain);
        }
        let old_verifying_pk = prev_identity_sk.verifying_key();
        let next_verifying_pk = new_identity_sk.verifying_key();
        if old_verifying_pk != prev_entry.identity_ed25519_pk
            || next_verifying_pk == old_verifying_pk
        {
            return Err(CryptoError::InvalidSklChain);
        }
        let seq = prev_entry
            .seq
            .checked_add(1)
            .ok_or(CryptoError::InvalidSklChain)?;

        let mut entry = Self {
            tenant_id: prev_entry.tenant_id,
            seq,
            vault_role,
            key_version,
            xwing_pk,
            identity_ed25519_pk: next_verifying_pk,
            issued_at_unix,
            prev_entry_hash: prev_entry.entry_hash(),
            signature: [0_u8; ED25519_SIGNATURE_LEN],
            rotation_cross_signature: None,
        };
        let body = entry.canonical_body_bytes();
        entry.signature = new_identity_sk.sign(&body);
        let rot_msg = build_rotation_message(&body, &old_verifying_pk, &next_verifying_pk);
        entry.rotation_cross_signature = Some(prev_identity_sk.sign(&rot_msg));
        Ok(entry)
    }

    /// Reconstructs an unverified `SklEntryV1` from deserialized fields (e.g.
    /// `/.well-known/rustcom-skl.json`). Callers MUST pass the full slice to [`verify_skl_chain`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        tenant_id: [u8; 16],
        seq: u64,
        vault_role: VaultRole,
        key_version: u32,
        xwing_pk: XWingPublicKey,
        identity_ed25519_pk: Ed25519VerifyingKey,
        issued_at_unix: u64,
        prev_entry_hash: [u8; 32],
        signature: [u8; ED25519_SIGNATURE_LEN],
        rotation_cross_signature: Option<[u8; ED25519_SIGNATURE_LEN]>,
    ) -> Result<Self, CryptoError> {
        if key_version == 0 {
            return Err(CryptoError::InvalidKeyVersion(0));
        }
        if issued_at_unix == 0 {
            return Err(CryptoError::InvalidSklChain);
        }
        Ok(Self {
            tenant_id,
            seq,
            vault_role,
            key_version,
            xwing_pk,
            identity_ed25519_pk,
            issued_at_unix,
            prev_entry_hash,
            signature,
            rotation_cross_signature,
        })
    }

    /// Encodes the exact 1,338-byte canonical unsigned body signed by `identity_ed25519_sk`.
    #[must_use]
    pub fn canonical_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SKL_BODY_LEN);
        out.extend_from_slice(SKL_ENTRY_DOMAIN);
        out.push(SKL_ENTRY_VERSION_V1);
        out.extend_from_slice(&self.tenant_id);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.vault_role.as_u8());
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(&self.xwing_pk.to_bytes());
        out.extend_from_slice(&self.identity_ed25519_pk.to_bytes());
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.prev_entry_hash);
        out
    }

    /// Encodes the full canonical signed entry (`1,403 B` or `1,467 B` with cross-signature).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let cap = if self.rotation_cross_signature.is_some() {
            SKL_ENTRY_ROTATE_WIRE_LEN
        } else {
            SKL_ENTRY_BASE_WIRE_LEN
        };
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&self.canonical_body_bytes());
        out.extend_from_slice(&self.signature);
        if let Some(cross_sig) = &self.rotation_cross_signature {
            out.push(1_u8);
            out.extend_from_slice(cross_sig);
        } else {
            out.push(0_u8);
        }
        out
    }

    /// Computes `BLAKE3(canonical_bytes(self))` (`32 B`) used as `prev_entry_hash` by entry `n + 1`.
    #[must_use]
    pub fn entry_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Parses a canonical binary `SklEntryV1`, strictly validating framing, version, `XWingPublicKey`,
    /// and `Ed25519VerifyingKey` (signatures and chaining are checked by [`verify_skl_chain`]).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SKL_ENTRY_BASE_WIRE_LEN {
            return Err(CryptoError::TruncatedInput);
        }
        if bytes[0..20] != *SKL_ENTRY_DOMAIN {
            return Err(CryptoError::InvalidMagic);
        }
        if bytes[20] != SKL_ENTRY_VERSION_V1 {
            return Err(CryptoError::UnsupportedFormatVersion(bytes[20]));
        }

        let mut tenant_id = [0_u8; 16];
        tenant_id.copy_from_slice(&bytes[21..37]);
        let seq = u64::from_be_bytes([
            bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43], bytes[44],
        ]);
        let vault_role = VaultRole::from_u8(bytes[45])?;
        let key_version = u32::from_be_bytes([bytes[46], bytes[47], bytes[48], bytes[49]]);

        let xwing_end = 50 + XWING_PUBLIC_KEY_LEN;
        let xwing_pk = XWingPublicKey::from_bytes(&bytes[50..xwing_end])?;

        let ed_end = xwing_end + ED25519_PUBLIC_KEY_LEN;
        let identity_ed25519_pk = Ed25519VerifyingKey::from_bytes(&bytes[xwing_end..ed_end])?;

        let ts_end = ed_end + 8;
        let issued_at_unix = u64::from_be_bytes([
            bytes[ed_end],
            bytes[ed_end + 1],
            bytes[ed_end + 2],
            bytes[ed_end + 3],
            bytes[ed_end + 4],
            bytes[ed_end + 5],
            bytes[ed_end + 6],
            bytes[ed_end + 7],
        ]);

        let prev_end = ts_end + 32;
        let mut prev_entry_hash = [0_u8; 32];
        prev_entry_hash.copy_from_slice(&bytes[ts_end..prev_end]);

        let sig_end = prev_end + ED25519_SIGNATURE_LEN;
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[prev_end..sig_end]);

        let has_cross_sig = bytes[sig_end];
        let rotation_cross_signature = match has_cross_sig {
            0 => {
                if bytes.len() != SKL_ENTRY_BASE_WIRE_LEN {
                    return Err(CryptoError::TrailingBytes);
                }
                None
            }
            1 => {
                if bytes.len() < SKL_ENTRY_ROTATE_WIRE_LEN {
                    return Err(CryptoError::TruncatedInput);
                }
                if bytes.len() > SKL_ENTRY_ROTATE_WIRE_LEN {
                    return Err(CryptoError::TrailingBytes);
                }
                let mut cross = [0_u8; ED25519_SIGNATURE_LEN];
                cross.copy_from_slice(&bytes[SKL_ENTRY_BASE_WIRE_LEN..SKL_ENTRY_ROTATE_WIRE_LEN]);
                Some(cross)
            }
            _ => return Err(CryptoError::InvalidSklChain),
        };

        Self::from_parts(
            tenant_id,
            seq,
            vault_role,
            key_version,
            xwing_pk,
            identity_ed25519_pk,
            issued_at_unix,
            prev_entry_hash,
            signature,
            rotation_cross_signature,
        )
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &[u8; 16] {
        &self.tenant_id
    }

    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub const fn vault_role(&self) -> VaultRole {
        self.vault_role
    }

    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    #[must_use]
    pub const fn xwing_pk(&self) -> &XWingPublicKey {
        &self.xwing_pk
    }

    #[must_use]
    pub const fn identity_ed25519_pk(&self) -> &Ed25519VerifyingKey {
        &self.identity_ed25519_pk
    }

    #[must_use]
    pub const fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    #[must_use]
    pub const fn prev_entry_hash(&self) -> &[u8; 32] {
        &self.prev_entry_hash
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.signature
    }

    #[must_use]
    pub const fn rotation_cross_signature(&self) -> Option<&[u8; ED25519_SIGNATURE_LEN]> {
        self.rotation_cross_signature.as_ref()
    }
}

/// Previously pinned SKL checkpoint anchored by TOFU, Rekor v2, or a store manifest to detect
/// server equivocation or chain truncation/rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SklCheckpoint {
    pub seq: u64,
    pub entry_hash: [u8; 32],
    pub identity_ed25519_pk: Ed25519VerifyingKey,
}

/// Verified summary of a store's append-only Signed Key List, exposing both currently active
/// per-role X-Wing public keys and historical keys for 6-10 year VAT / archive unwrapping.
#[derive(Debug, Clone)]
pub struct VerifiedSkl {
    tenant_id: [u8; 16],
    latest_seq: u64,
    latest_entry_hash: [u8; 32],
    current_identity_pk: Ed25519VerifyingKey,
    role_histories: [Vec<(u32, XWingPublicKey)>; 3],
}

impl VerifiedSkl {
    #[must_use]
    pub const fn tenant_id(&self) -> &[u8; 16] {
        &self.tenant_id
    }

    #[must_use]
    pub const fn latest_seq(&self) -> u64 {
        self.latest_seq
    }

    #[must_use]
    pub const fn latest_entry_hash(&self) -> &[u8; 32] {
        &self.latest_entry_hash
    }

    #[must_use]
    pub const fn current_identity_pk(&self) -> &Ed25519VerifyingKey {
        &self.current_identity_pk
    }

    /// Returns a checkpoint representing the verified chain tip for future anti-rollback pinning.
    #[must_use]
    pub const fn checkpoint(&self) -> SklCheckpoint {
        SklCheckpoint {
            seq: self.latest_seq,
            entry_hash: self.latest_entry_hash,
            identity_ed25519_pk: self.current_identity_pk,
        }
    }

    /// Returns the currently active `(key_version, &XWingPublicKey)` for `role`, if provisioned.
    #[must_use]
    pub fn active_key(&self, role: VaultRole) -> Option<(u32, &XWingPublicKey)> {
        self.role_histories[role.index()]
            .last()
            .map(|(ver, pk)| (*ver, pk))
    }

    /// Looks up a specific `(role, key_version)` X-Wing public key (active or historical).
    #[must_use]
    pub fn key_for_version(&self, role: VaultRole, key_version: u32) -> Option<&XWingPublicKey> {
        let idx = usize::try_from(key_version.checked_sub(1)?).ok()?;
        let (ver, pk) = self.role_histories[role.index()].get(idx)?;
        if *ver == key_version { Some(pk) } else { None }
    }
}

/// Verifies an entire append-only Signed Key List chain from genesis (`seq = 0`) through the tip.
///
/// Enforces:
/// 1. Non-empty chain bounded by [`MAX_SKL_ENTRIES`].
/// 2. Exact `tenant_id` binding on every entry.
/// 3. Strictly contiguous `seq = 0, 1, ..., n - 1` and non-decreasing `issued_at_unix > 0`.
/// 4. Strictly monotonic gap-free `key_version = 1, 2, ...` per [`VaultRole`].
/// 5. Distinct `xwing_pk` across the entire chain (preventing role collision & key resurrection).
/// 6. Exact hash chaining `prev_entry_hash == BLAKE3(canonical_bytes(entry[i - 1]))`
///    (and `[0; 32]` at genesis).
/// 7. Strict Ed25519 verification (`verify_strict`) on every entry signature, PLUS mandatory
///    cross-signature by `prev.identity_ed25519_pk` if and only if `identity_ed25519_pk` rotates.
/// 8. Optional anti-rollback / anti-equivocation verification against `pinned_checkpoint`.
pub fn verify_skl_chain(
    expected_tenant_id: &[u8; 16],
    entries: &[SklEntryV1],
    pinned_checkpoint: Option<&SklCheckpoint>,
) -> Result<VerifiedSkl, CryptoError> {
    if entries.is_empty() || entries.len() > MAX_SKL_ENTRIES {
        return Err(CryptoError::InvalidSklChain);
    }

    let entries_len_u64 = u64::try_from(entries.len()).map_err(|_| CryptoError::InvalidSklChain)?;
    if let Some(cp) = pinned_checkpoint
        && cp.seq >= entries_len_u64
    {
        return Err(CryptoError::InvalidSklChain);
    }

    let mut role_histories: [Vec<(u32, XWingPublicKey)>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut seen_xwing_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut retired_identity_pks: BTreeSet<[u8; ED25519_PUBLIC_KEY_LEN]> = BTreeSet::new();

    let mut prev_hash = [0_u8; 32];
    let mut prev_identity_pk: Option<Ed25519VerifyingKey> = None;
    let mut prev_issued_at = 0_u64;
    let mut checkpoint_verified = pinned_checkpoint.is_none();

    for (idx, entry) in entries.iter().enumerate() {
        let expected_seq = u64::try_from(idx).map_err(|_| CryptoError::InvalidSklChain)?;
        if entry.seq != expected_seq
            || !bool::from(entry.tenant_id.ct_eq(expected_tenant_id))
            || entry.issued_at_unix == 0
            || entry.issued_at_unix < prev_issued_at
        {
            return Err(CryptoError::InvalidSklChain);
        }

        let role_hist = &mut role_histories[entry.vault_role.index()];
        let expected_ver = u32::try_from(role_hist.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(CryptoError::InvalidKeyVersion(entry.key_version))?;
        if entry.key_version != expected_ver {
            return Err(CryptoError::InvalidKeyVersion(entry.key_version));
        }

        let pk_hash = hash_xwing_public_key(&entry.xwing_pk);
        if !seen_xwing_hashes.insert(pk_hash) {
            return Err(CryptoError::InvalidSklChain);
        }

        if !bool::from(entry.prev_entry_hash.ct_eq(&prev_hash)) {
            return Err(CryptoError::InvalidSklChain);
        }

        let body = entry.canonical_body_bytes();
        if let Some(prev_id) = prev_identity_pk {
            if entry.identity_ed25519_pk == prev_id {
                if entry.rotation_cross_signature.is_some() {
                    return Err(CryptoError::InvalidSklChain);
                }
            } else {
                let new_id_bytes = entry.identity_ed25519_pk.to_bytes();
                if retired_identity_pks.contains(&new_id_bytes) {
                    return Err(CryptoError::InvalidSklChain);
                }
                let cross_sig = entry
                    .rotation_cross_signature
                    .as_ref()
                    .ok_or(CryptoError::InvalidSklChain)?;
                let rot_msg = build_rotation_message(&body, &prev_id, &entry.identity_ed25519_pk);
                prev_id.verify_strict(&rot_msg, cross_sig)?;
                retired_identity_pks.insert(prev_id.to_bytes());
            }
        } else if entry.rotation_cross_signature.is_some() {
            return Err(CryptoError::InvalidSklChain);
        }

        entry
            .identity_ed25519_pk
            .verify_strict(&body, &entry.signature)?;

        let current_hash = entry.entry_hash();
        if let Some(cp) = pinned_checkpoint
            && cp.seq == entry.seq
        {
            if !bool::from(current_hash.ct_eq(&cp.entry_hash))
                || entry.identity_ed25519_pk != cp.identity_ed25519_pk
            {
                return Err(CryptoError::InvalidSklChain);
            }
            checkpoint_verified = true;
        }

        role_hist.push((entry.key_version, entry.xwing_pk.clone()));
        prev_hash = current_hash;
        prev_identity_pk = Some(entry.identity_ed25519_pk);
        prev_issued_at = entry.issued_at_unix;
    }

    let current_identity_pk = prev_identity_pk.ok_or(CryptoError::InvalidSklChain)?;
    if !checkpoint_verified {
        return Err(CryptoError::InvalidSklChain);
    }

    Ok(VerifiedSkl {
        tenant_id: *expected_tenant_id,
        latest_seq: entries_len_u64 - 1,
        latest_entry_hash: prev_hash,
        current_identity_pk,
        role_histories,
    })
}

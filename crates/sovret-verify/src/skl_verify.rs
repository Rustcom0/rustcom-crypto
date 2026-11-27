use serde::{Deserialize, Serialize};
use sovret_crypto_core::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519VerifyingKey, MAX_SKL_ENTRIES,
    SklCheckpoint, SklEntryV1, VaultRole, VerifiedSkl, XWING_PUBLIC_KEY_LEN, XWingPublicKey,
    verify_skl_chain,
};

use crate::VerifyError;

/// Upper bound on `/.well-known/sovret-skl.json` size (`16 MiB`).
pub const MAX_SKL_JSON_LEN: usize = 16 * 1024 * 1024;
/// Upper bound on checkpoint JSON size (`16 KiB`).
pub const MAX_CHECKPOINT_JSON_LEN: usize = 16 * 1024;

/// JSON wire format served at `/.well-known/sovret-skl.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SklDocumentJson {
    pub entries: Vec<SklEntryJson>,
}

/// Single JSON-encoded entry in `/.well-known/sovret-skl.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SklEntryJson {
    pub tenant_id_hex: String,
    pub seq: u64,
    pub vault_role: u8,
    pub key_version: u32,
    pub xwing_pk_hex: String,
    pub identity_ed25519_pk_hex: String,
    pub issued_at_unix: u64,
    pub prev_entry_hash_hex: String,
    pub signature_hex: String,
    #[serde(default)]
    pub rotation_cross_signature_hex: Option<String>,
}

/// JSON format for an anti-rollback pinned SKL checkpoint (`--pinned-checkpoint`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SklCheckpointJson {
    pub seq: u64,
    pub entry_hash_hex: String,
    pub identity_ed25519_pk_hex: String,
}

fn decode_hex_exact<const N: usize>(input: &str, field: &str) -> Result<[u8; N], VerifyError> {
    if input.len() != N * 2 {
        return Err(VerifyError::SklVerificationFailed(format!(
            "field '{field}' expected {} hex chars, got {}",
            N * 2,
            input.len()
        )));
    }
    let mut out = [0_u8; N];
    hex::decode_to_slice(input, &mut out).map_err(|_| {
        VerifyError::SklVerificationFailed(format!("field '{field}' contains invalid hex"))
    })?;
    Ok(out)
}

fn decode_hex_vec(input: &str, expected_bytes: usize, field: &str) -> Result<Vec<u8>, VerifyError> {
    if input.len() != expected_bytes * 2 {
        return Err(VerifyError::SklVerificationFailed(format!(
            "field '{field}' expected {} hex chars, got {}",
            expected_bytes * 2,
            input.len()
        )));
    }
    hex::decode(input).map_err(|_| {
        VerifyError::SklVerificationFailed(format!("field '{field}' contains invalid hex"))
    })
}

/// Parses a JSON-encoded [`SklCheckpoint`], rejecting duplicate keys and unknown fields.
pub fn parse_checkpoint_json(raw: &[u8]) -> Result<SklCheckpoint, VerifyError> {
    if raw.len() > MAX_CHECKPOINT_JSON_LEN {
        return Err(VerifyError::InputTooLarge("SKL checkpoint JSON"));
    }
    crate::reject_duplicate_json_keys(raw)?;
    let parsed: SklCheckpointJson =
        serde_json::from_slice(raw).map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
    let entry_hash = decode_hex_exact::<32>(&parsed.entry_hash_hex, "entry_hash_hex")?;
    let id_bytes = decode_hex_exact::<ED25519_PUBLIC_KEY_LEN>(
        &parsed.identity_ed25519_pk_hex,
        "identity_ed25519_pk_hex",
    )?;
    let identity_ed25519_pk = Ed25519VerifyingKey::from_bytes(&id_bytes)
        .map_err(|e| VerifyError::SklVerificationFailed(e.to_string()))?;
    Ok(SklCheckpoint {
        seq: parsed.seq,
        entry_hash,
        identity_ed25519_pk,
    })
}

/// Parses and cryptographically verifies a `/.well-known/sovret-skl.json` document against
/// `expected_tenant_id_hex` and an optional pinned anti-rollback [`SklCheckpoint`].
pub fn verify_skl_document(
    expected_tenant_id_hex: &str,
    skl_json_bytes: &[u8],
    pinned_checkpoint: Option<&SklCheckpoint>,
) -> Result<VerifiedSkl, VerifyError> {
    if skl_json_bytes.len() > MAX_SKL_JSON_LEN {
        return Err(VerifyError::InputTooLarge("sovret-skl.json"));
    }
    crate::reject_duplicate_json_keys(skl_json_bytes)?;
    let expected_tenant_id = decode_hex_exact::<16>(expected_tenant_id_hex, "tenant_id_hex")?;
    let doc: SklDocumentJson = serde_json::from_slice(skl_json_bytes)
        .map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
    if doc.entries.is_empty() || doc.entries.len() > MAX_SKL_ENTRIES {
        return Err(VerifyError::SklVerificationFailed(format!(
            "SKL entry count {} outside 1..={MAX_SKL_ENTRIES}",
            doc.entries.len()
        )));
    }

    let mut entries = Vec::with_capacity(doc.entries.len());
    for raw in doc.entries {
        let tenant_id = decode_hex_exact::<16>(&raw.tenant_id_hex, "entry.tenant_id_hex")?;
        let vault_role = VaultRole::from_u8(raw.vault_role)
            .map_err(|e| VerifyError::SklVerificationFailed(e.to_string()))?;
        let xwing_bytes = decode_hex_vec(&raw.xwing_pk_hex, XWING_PUBLIC_KEY_LEN, "xwing_pk_hex")?;
        let xwing_pk = XWingPublicKey::from_bytes(&xwing_bytes)
            .map_err(|e| VerifyError::SklVerificationFailed(e.to_string()))?;
        let id_bytes = decode_hex_exact::<ED25519_PUBLIC_KEY_LEN>(
            &raw.identity_ed25519_pk_hex,
            "identity_ed25519_pk_hex",
        )?;
        let identity_ed25519_pk = Ed25519VerifyingKey::from_bytes(&id_bytes)
            .map_err(|e| VerifyError::SklVerificationFailed(e.to_string()))?;
        let prev_entry_hash =
            decode_hex_exact::<32>(&raw.prev_entry_hash_hex, "prev_entry_hash_hex")?;
        let signature =
            decode_hex_exact::<ED25519_SIGNATURE_LEN>(&raw.signature_hex, "signature_hex")?;
        let rotation_cross_signature = match raw.rotation_cross_signature_hex {
            Some(ref s) => Some(decode_hex_exact::<ED25519_SIGNATURE_LEN>(
                s,
                "rotation_cross_signature_hex",
            )?),
            None => None,
        };
        let entry = SklEntryV1::from_parts(
            tenant_id,
            raw.seq,
            vault_role,
            raw.key_version,
            xwing_pk,
            identity_ed25519_pk,
            raw.issued_at_unix,
            prev_entry_hash,
            signature,
            rotation_cross_signature,
        )
        .map_err(|e| VerifyError::SklVerificationFailed(e.to_string()))?;
        entries.push(entry);
    }

    verify_skl_chain(&expected_tenant_id, &entries, pinned_checkpoint)
        .map_err(|e| VerifyError::SklVerificationFailed(e.to_string()))
}

/// Converts a verified [`SklEntryV1`] into its canonical JSON wire entry for fixtures & tooling.
#[must_use]
pub fn skl_entry_to_json(entry: &SklEntryV1) -> SklEntryJson {
    SklEntryJson {
        tenant_id_hex: hex::encode(entry.tenant_id()),
        seq: entry.seq(),
        vault_role: entry.vault_role().as_u8(),
        key_version: entry.key_version(),
        xwing_pk_hex: hex::encode(entry.xwing_pk().to_bytes()),
        identity_ed25519_pk_hex: hex::encode(entry.identity_ed25519_pk().to_bytes()),
        issued_at_unix: entry.issued_at_unix(),
        prev_entry_hash_hex: hex::encode(entry.prev_entry_hash()),
        signature_hex: hex::encode(entry.signature()),
        rotation_cross_signature_hex: entry.rotation_cross_signature().map(hex::encode),
    }
}

#![forbid(unsafe_code)]

//! Browser WASM cryptographic bridge for `rustcom-crypto-core`.
//!
//! # WASM/JS Memory Boundary Contract
//! All secret material inside Rust/WASM is held in `ZeroizeOnDrop` / `Zeroizing` storage and
//! wiped before deallocation. Once a return value crosses the `wasm-bindgen` FFI boundary into
//! JavaScript, Rust can no longer control its lifetime:
//! - Prefer binary `Uint8Array`-returning functions (`derive_strict_auth_secret`,
//!   `generate_strict_account_id_bytes`, `generate_recovery_mnemonic_bytes`,
//!   `combine_shamir_shares_to_mnemonic_bytes`, and all `decrypt_*` functions) over immutable
//!   JS strings whenever possible.
//! - JavaScript callers **MUST** wipe every returned secret `Uint8Array` as soon as it is no
//!   longer needed by calling [`wipe_bytes`] (or `buf.fill(0)`).

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

fn unwrap_zeroizing_string(mut z: zeroize::Zeroizing<String>) -> String {
    core::mem::take(&mut *z)
}

fn unwrap_zeroizing_vec(mut z: zeroize::Zeroizing<Vec<u8>>) -> Vec<u8> {
    core::mem::take(&mut *z)
}

pub mod api {
    use std::collections::BTreeSet;

    use rustcom_crypto_core::{
        Argon2idBudget, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519VerifyingKey,
        EnvelopeContext, EnvelopeFlags, EnvelopeKind, MAX_RECIPIENTS, MAX_SHAMIR_SHARES,
        MAX_SKL_ENTRIES, PrivacyTier, RCENC_FORMAT_VERSION_V1, RCSTR_FORMAT_VERSION_V1,
        RecipientSpec, RecipientType, RecoveryMasterSecret, SHAMIR_SHARE_VERSION_V1,
        SKL_ENTRY_VERSION_V1, STAFF_GRANT_VERSION_V1, ShamirShare, SklCheckpoint, SklEntryV1,
        StrictAccountId, VaultRole, VipInviteFragment, XWING_PUBLIC_KEY_LEN, XWingPublicKey,
        combine_recovery_shares, decrypt_private_product_password_with_budget,
        decrypt_private_product_vip_fragment, encrypt, split_recovery_secret, verify_skl_chain,
    };
    use serde::de::DeserializeSeed;
    use serde::{Deserialize, Serialize};
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    /// Upper bound on small JSON control payloads (recipients, checkpoints, Shamir share arrays).
    const MAX_CONTROL_JSON_LEN: usize = 64 * 1024;
    /// Upper bound on `/.well-known/rustcom-skl.json` payloads (`16 MiB` covers `4,096` entries).
    const MAX_SKL_JSON_LEN: usize = 16 * 1024 * 1024;
    /// Maximum JSON nesting depth accepted by the duplicate-key validator.
    const MAX_JSON_DEPTH: usize = 64;

    /// Rejects duplicate keys anywhere inside a JSON document (including Unicode-escaped duplicates
    /// such as `"\u0073eq"` vs `"seq"`) and trailing non-whitespace bytes.
    fn reject_duplicate_json_keys(raw: &str) -> Result<(), String> {
        struct NoDupValue {
            depth: usize,
        }

        impl<'de> DeserializeSeed<'de> for NoDupValue {
            type Value = ();

            fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(NoDupVisitor { depth: self.depth })
            }
        }

        struct NoDupVisitor {
            depth: usize,
        }

        impl<'de> serde::de::Visitor<'de> for NoDupVisitor {
            type Value = ();

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a valid JSON value with unique object keys")
            }

            fn visit_bool<E>(self, _: bool) -> Result<(), E> {
                Ok(())
            }
            fn visit_i64<E>(self, _: i64) -> Result<(), E> {
                Ok(())
            }
            fn visit_u64<E>(self, _: u64) -> Result<(), E> {
                Ok(())
            }
            fn visit_f64<E>(self, _: f64) -> Result<(), E> {
                Ok(())
            }
            fn visit_str<E>(self, _: &str) -> Result<(), E> {
                Ok(())
            }
            fn visit_unit<E>(self) -> Result<(), E> {
                Ok(())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                if self.depth >= MAX_JSON_DEPTH {
                    return Err(serde::de::Error::custom("JSON nesting depth exceeded"));
                }
                while seq
                    .next_element_seed(NoDupValue {
                        depth: self.depth + 1,
                    })?
                    .is_some()
                {}
                Ok(())
            }

            fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                if self.depth >= MAX_JSON_DEPTH {
                    return Err(serde::de::Error::custom("JSON nesting depth exceeded"));
                }
                let mut seen = BTreeSet::<String>::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    map.next_value_seed(NoDupValue {
                        depth: self.depth + 1,
                    })?;
                }
                Ok(())
            }
        }

        let mut de = serde_json::Deserializer::from_str(raw);
        NoDupValue { depth: 0 }
            .deserialize(&mut de)
            .map_err(|e| format!("invalid JSON: {e}"))?;
        de.end().map_err(|e| format!("invalid JSON: {e}"))?;
        Ok(())
    }

    #[derive(Serialize)]
    #[allow(clippy::struct_field_names)]
    struct ProtocolInfo {
        rcenc_version: u8,
        rcstr_version: u8,
        skl_version: u8,
        staff_grant_version: u8,
        shamir_version: u8,
    }

    /// Public Strict session metadata (deliberately excludes OPAQUE `auth_secret`; callers must
    /// obtain the 32-byte secret separately via [`derive_strict_auth_secret`] as a wipeable buffer).
    #[derive(Serialize)]
    #[allow(clippy::struct_field_names)]
    struct StrictSessionInfo {
        auth_lookup_id_hex: String,
        xwing_public_key_hex: String,
        xwing_key_id_hex: String,
        ed25519_public_key_hex: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct XWingRecipientJson {
        recipient_type: u8,
        key_id_hex: String,
        key_version: u32,
        xwing_public_key_hex: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SklDocumentJson {
        entries: Vec<SklEntryJson>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SklEntryJson {
        tenant_id_hex: String,
        seq: u64,
        vault_role: u8,
        key_version: u32,
        xwing_pk_hex: String,
        identity_ed25519_pk_hex: String,
        issued_at_unix: u64,
        prev_entry_hash_hex: String,
        signature_hex: String,
        #[serde(default)]
        rotation_cross_signature_hex: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SklCheckpointJson {
        seq: u64,
        entry_hash_hex: String,
        identity_ed25519_pk_hex: String,
    }

    #[derive(Serialize)]
    struct ActiveRoleKeyJson {
        key_version: u32,
        key_id_hex: String,
        xwing_pk_hex: String,
    }

    #[derive(Serialize)]
    struct VerifiedSklSummaryJson {
        tenant_id_hex: String,
        latest_seq: u64,
        latest_entry_hash_hex: String,
        current_identity_pk_hex: String,
        org_master: Option<ActiveRoleKeyJson>,
        fulfillment: Option<ActiveRoleKeyJson>,
        accounting: Option<ActiveRoleKeyJson>,
    }

    #[derive(Serialize)]
    struct VipFragmentInfoJson {
        key_version: u32,
        key_id_hex: String,
        xwing_public_key_hex: String,
    }

    #[derive(Serialize, Zeroize, ZeroizeOnDrop)]
    struct ShamirShareOutputJson {
        share_index: u8,
        split_id_hex: String,
        commitment_sha256_hex: String,
        share_wire_hex: String,
    }

    struct ZeroizingStringVec(Vec<String>);

    impl Drop for ZeroizingStringVec {
        fn drop(&mut self) {
            for s in &mut self.0 {
                s.zeroize();
            }
        }
    }

    fn decode_hex_exact<const N: usize>(input: &str, label: &str) -> Result<[u8; N], String> {
        if input.len() != N * 2 {
            return Err(format!("invalid {label} hex length"));
        }
        let mut out = [0_u8; N];
        hex::decode_to_slice(input, &mut out).map_err(|_| format!("invalid {label} hex"))?;
        Ok(out)
    }

    fn decode_hex_vec(input: &str, expected_len: usize, label: &str) -> Result<Vec<u8>, String> {
        if input.len() != expected_len * 2 {
            return Err(format!("invalid {label} hex length"));
        }
        hex::decode(input).map_err(|_| format!("invalid {label} hex"))
    }

    /// Returns static protocol version metadata as JSON.
    #[must_use]
    pub fn protocol_info_json() -> String {
        let info = ProtocolInfo {
            rcenc_version: RCENC_FORMAT_VERSION_V1,
            rcstr_version: RCSTR_FORMAT_VERSION_V1,
            skl_version: SKL_ENTRY_VERSION_V1,
            staff_grant_version: STAFF_GRANT_VERSION_V1,
            shamir_version: SHAMIR_SHARE_VERSION_V1,
        };
        serde_json::to_string(&info).unwrap_or_else(|_| String::from("{}"))
    }

    /// Generates a new 128-bit Mullvad-style Strict Account ID (`XXXX-XXXX-...`).
    pub fn generate_strict_account_id() -> Result<Zeroizing<String>, String> {
        let id = StrictAccountId::generate().map_err(|e| e.to_string())?;
        Ok(id.to_formatted_string())
    }

    /// Generates a new 128-bit Strict Account ID as UTF-8 bytes so JS callers can hold and wipe
    /// it inside a mutable `Uint8Array`.
    pub fn generate_strict_account_id_bytes() -> Result<Zeroizing<Vec<u8>>, String> {
        let mut formatted = generate_strict_account_id()?;
        Ok(Zeroizing::new(
            core::mem::take(&mut *formatted).into_bytes(),
        ))
    }

    /// Validates, normalizes, and returns the canonical hyphenated Strict Account ID.
    pub fn validate_strict_account_id(input: &str) -> Result<Zeroizing<String>, String> {
        let id = StrictAccountId::parse(input).map_err(|e| e.to_string())?;
        Ok(id.to_formatted_string())
    }

    /// Derives tenant-scoped Strict **public** session metadata (`auth_lookup_id_hex`, public
    /// X-Wing/Ed25519 keys) without serializing `auth_secret` or vault seeds into JSON.
    pub fn derive_strict_session_json(
        account_id: &str,
        tenant_id_hex: &str,
    ) -> Result<String, String> {
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let id = StrictAccountId::parse(account_id).map_err(|e| e.to_string())?;
        let keys = id.derive_keys(&tenant_id).map_err(|e| e.to_string())?;
        let vault = keys.derive_vault().map_err(|e| e.to_string())?;

        let info = StrictSessionInfo {
            auth_lookup_id_hex: hex::encode(keys.auth_lookup_id()),
            xwing_public_key_hex: hex::encode(vault.xwing_public().to_bytes()),
            xwing_key_id_hex: hex::encode(vault.xwing_public().key_id()),
            ed25519_public_key_hex: hex::encode(vault.ed25519_verifying().to_bytes()),
        };
        serde_json::to_string(&info).map_err(|_| String::from("failed to encode session json"))
    }

    /// Derives the raw 32-byte tenant-scoped OPAQUE client secret (`auth_secret`) as binary bytes
    /// (JS `Uint8Array`), avoiding immutable JSON/hex secret strings. JS callers MUST wipe the
    /// returned buffer via `wipe_bytes(buf)` or `buf.fill(0)` immediately after OPAQUE use.
    pub fn derive_strict_auth_secret(
        account_id: &str,
        tenant_id_hex: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let id = StrictAccountId::parse(account_id).map_err(|e| e.to_string())?;
        let keys = id.derive_keys(&tenant_id).map_err(|e| e.to_string())?;
        Ok(Zeroizing::new(keys.auth_secret().as_bytes().to_vec()))
    }

    /// Verifies a store's `/.well-known/rustcom-skl.json` chain and optional pinned checkpoint.
    pub fn verify_skl_json(
        tenant_id_hex: &str,
        skl_json: &str,
        pinned_checkpoint_json: Option<&str>,
    ) -> Result<String, String> {
        if skl_json.len() > MAX_SKL_JSON_LEN {
            return Err(String::from("SKL JSON exceeds size limit"));
        }
        reject_duplicate_json_keys(skl_json)?;
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let doc: SklDocumentJson =
            serde_json::from_str(skl_json).map_err(|_| String::from("invalid SKL JSON"))?;
        if doc.entries.is_empty() || doc.entries.len() > MAX_SKL_ENTRIES {
            return Err(String::from("invalid SKL entry count"));
        }

        let mut entries = Vec::with_capacity(doc.entries.len());
        for raw in doc.entries {
            let entry_tenant = decode_hex_exact::<16>(&raw.tenant_id_hex, "entry.tenant_id")?;
            let role = VaultRole::from_u8(raw.vault_role).map_err(|e| e.to_string())?;
            let xwing_bytes = decode_hex_vec(&raw.xwing_pk_hex, XWING_PUBLIC_KEY_LEN, "xwing_pk")?;
            let xwing_pk = XWingPublicKey::from_bytes(&xwing_bytes).map_err(|e| e.to_string())?;
            let ed_bytes =
                decode_hex_exact::<ED25519_PUBLIC_KEY_LEN>(&raw.identity_ed25519_pk_hex, "id_pk")?;
            let id_pk = Ed25519VerifyingKey::from_bytes(&ed_bytes).map_err(|e| e.to_string())?;
            let prev_hash = decode_hex_exact::<32>(&raw.prev_entry_hash_hex, "prev_entry_hash")?;
            let sig = decode_hex_exact::<ED25519_SIGNATURE_LEN>(&raw.signature_hex, "signature")?;
            let cross_sig = match raw.rotation_cross_signature_hex {
                Some(ref s) => Some(decode_hex_exact::<ED25519_SIGNATURE_LEN>(
                    s,
                    "rotation_cross_signature",
                )?),
                None => None,
            };
            let entry = SklEntryV1::from_parts(
                entry_tenant,
                raw.seq,
                role,
                raw.key_version,
                xwing_pk,
                id_pk,
                raw.issued_at_unix,
                prev_hash,
                sig,
                cross_sig,
            )
            .map_err(|e| e.to_string())?;
            entries.push(entry);
        }

        let checkpoint = match pinned_checkpoint_json {
            Some(raw_cp) => {
                if raw_cp.len() > MAX_CONTROL_JSON_LEN {
                    return Err(String::from("checkpoint JSON exceeds size limit"));
                }
                reject_duplicate_json_keys(raw_cp)?;
                let cp: SklCheckpointJson = serde_json::from_str(raw_cp)
                    .map_err(|_| String::from("invalid checkpoint JSON"))?;
                let entry_hash = decode_hex_exact::<32>(&cp.entry_hash_hex, "entry_hash")?;
                let id_bytes = decode_hex_exact::<ED25519_PUBLIC_KEY_LEN>(
                    &cp.identity_ed25519_pk_hex,
                    "identity_ed25519_pk",
                )?;
                let identity_ed25519_pk =
                    Ed25519VerifyingKey::from_bytes(&id_bytes).map_err(|e| e.to_string())?;
                Some(SklCheckpoint {
                    seq: cp.seq,
                    entry_hash,
                    identity_ed25519_pk,
                })
            }
            None => None,
        };

        let verified = verify_skl_chain(&tenant_id, &entries, checkpoint.as_ref())
            .map_err(|e| e.to_string())?;

        let map_role = |role: VaultRole| -> Option<ActiveRoleKeyJson> {
            verified
                .active_key(role)
                .map(|(ver, pk)| ActiveRoleKeyJson {
                    key_version: ver,
                    key_id_hex: hex::encode(pk.key_id()),
                    xwing_pk_hex: hex::encode(pk.to_bytes()),
                })
        };

        let summary = VerifiedSklSummaryJson {
            tenant_id_hex: hex::encode(verified.tenant_id()),
            latest_seq: verified.latest_seq(),
            latest_entry_hash_hex: hex::encode(verified.latest_entry_hash()),
            current_identity_pk_hex: hex::encode(verified.current_identity_pk().to_bytes()),
            org_master: map_role(VaultRole::OrgMaster),
            fulfillment: map_role(VaultRole::Fulfillment),
            accounting: map_role(VaultRole::Accounting),
        };
        serde_json::to_string(&summary).map_err(|_| String::from("failed to encode SKL summary"))
    }

    /// Encrypts plaintext into an `RCENC` v1 envelope for `1..=8` X-Wing recipients (checkout /
    /// dual-wrapped Strict orders / portal messages).
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_rcenc_xwing(
        plaintext: &[u8],
        tenant_id_hex: &str,
        resource_id_hex: &str,
        envelope_kind: u8,
        privacy_tier: u8,
        schema_version: u16,
        recipients_json: &str,
    ) -> Result<Vec<u8>, String> {
        if recipients_json.len() > MAX_CONTROL_JSON_LEN {
            return Err(String::from("recipients JSON exceeds size limit"));
        }
        reject_duplicate_json_keys(recipients_json)?;
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let resource_id = decode_hex_exact::<16>(resource_id_hex, "resource_id")?;
        let kind = EnvelopeKind::from_u8(envelope_kind).map_err(|e| e.to_string())?;
        let tier = PrivacyTier::from_u8(privacy_tier).map_err(|e| e.to_string())?;

        let raw_recipients: Vec<XWingRecipientJson> = serde_json::from_str(recipients_json)
            .map_err(|_| String::from("invalid recipients JSON"))?;
        if raw_recipients.is_empty() || raw_recipients.len() > MAX_RECIPIENTS {
            return Err(String::from("recipient count must be 1..=8"));
        }

        let mut parsed_keys: Vec<(RecipientType, [u8; 16], u32, XWingPublicKey)> =
            Vec::with_capacity(raw_recipients.len());
        for item in raw_recipients {
            let rtype = RecipientType::from_u8(item.recipient_type).map_err(|e| e.to_string())?;
            if !rtype.is_xwing() {
                return Err(String::from(
                    "recipient_type must be an X-Wing type (1..=4)",
                ));
            }
            let key_id = decode_hex_exact::<16>(&item.key_id_hex, "key_id")?;
            let pk_bytes = decode_hex_vec(
                &item.xwing_public_key_hex,
                XWING_PUBLIC_KEY_LEN,
                "xwing_public_key",
            )?;
            let pk = XWingPublicKey::from_bytes(&pk_bytes).map_err(|e| e.to_string())?;
            parsed_keys.push((rtype, key_id, item.key_version, pk));
        }

        let specs: Vec<RecipientSpec<'_>> = parsed_keys
            .iter()
            .map(|(rtype, key_id, ver, pk)| RecipientSpec::XWing {
                recipient_type: *rtype,
                key_id: *key_id,
                key_version: *ver,
                public_key: pk,
            })
            .collect();

        let ctx = EnvelopeContext {
            envelope_kind: kind,
            tenant_id,
            resource_id,
            privacy_tier: tier,
            schema_version,
        };
        encrypt(plaintext, &ctx, EnvelopeFlags::default(), &specs).map_err(|e| e.to_string())
    }

    /// Decrypts a dual-wrapped Strict customer `RCENC` v1 envelope strictly inside WASM memory.
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_rcenc_strict_customer(
        envelope: &[u8],
        account_id: &str,
        tenant_id_hex: &str,
        resource_id_hex: &str,
        envelope_kind: u8,
        privacy_tier: u8,
        schema_version: u16,
        customer_key_version: u32,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let resource_id = decode_hex_exact::<16>(resource_id_hex, "resource_id")?;
        let kind = EnvelopeKind::from_u8(envelope_kind).map_err(|e| e.to_string())?;
        let tier = PrivacyTier::from_u8(privacy_tier).map_err(|e| e.to_string())?;

        let id = StrictAccountId::parse(account_id).map_err(|e| e.to_string())?;
        let vault = id.derive_vault(&tenant_id).map_err(|e| e.to_string())?;
        let ctx = EnvelopeContext {
            envelope_kind: kind,
            tenant_id,
            resource_id,
            privacy_tier: tier,
            schema_version,
        };
        let cred = vault.recipient_credential(customer_key_version);
        let decrypted =
            rustcom_crypto_core::decrypt(envelope, &ctx, &cred).map_err(|e| e.to_string())?;
        Ok(decrypted.plaintext)
    }

    /// Decrypts a password-protected Private Product `RCENC` envelope enforcing the stricter
    /// single-threaded browser WASM Argon2id budget ([`Argon2idBudget::WASM_CLIENT`]: `m <= 64 MiB`,
    /// `t <= 4`, `p <= 2`, `m * t <= 262,144 KiB-iters`) before executing KDF.
    pub fn decrypt_private_product_password_bytes(
        envelope: &[u8],
        tenant_id_hex: &str,
        product_id_hex: &str,
        privacy_tier: u8,
        schema_version: u16,
        password: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let product_id = decode_hex_exact::<16>(product_id_hex, "product_id")?;
        let tier = PrivacyTier::from_u8(privacy_tier).map_err(|e| e.to_string())?;
        let ctx = EnvelopeContext {
            envelope_kind: EnvelopeKind::PrivateProduct,
            tenant_id,
            resource_id: product_id,
            privacy_tier: tier,
            schema_version,
        };
        let decrypted = decrypt_private_product_password_with_budget(
            envelope,
            &ctx,
            password.as_bytes(),
            Argon2idBudget::WASM_CLIENT,
        )
        .map_err(|e| e.to_string())?;
        Ok(decrypted.plaintext)
    }

    /// Decrypts a VIP Group Private Product `RCENC` envelope using a client-only `#k=...` fragment.
    pub fn decrypt_private_product_vip_fragment_bytes(
        envelope: &[u8],
        tenant_id_hex: &str,
        product_id_hex: &str,
        privacy_tier: u8,
        schema_version: u16,
        vip_group_id_hex: &str,
        url_fragment: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let product_id = decode_hex_exact::<16>(product_id_hex, "product_id")?;
        let vip_group_id = decode_hex_exact::<16>(vip_group_id_hex, "vip_group_id")?;
        let tier = PrivacyTier::from_u8(privacy_tier).map_err(|e| e.to_string())?;
        let ctx = EnvelopeContext {
            envelope_kind: EnvelopeKind::PrivateProduct,
            tenant_id,
            resource_id: product_id,
            privacy_tier: tier,
            schema_version,
        };
        let fragment =
            VipInviteFragment::parse_url_fragment(url_fragment).map_err(|e| e.to_string())?;
        let decrypted =
            decrypt_private_product_vip_fragment(envelope, &ctx, vip_group_id, &fragment)
                .map_err(|e| e.to_string())?;
        Ok(decrypted.plaintext)
    }

    /// Parses a `#k=...` VIP URL fragment and returns only its public metadata (never the seed).
    pub fn inspect_vip_fragment_json(url_fragment: &str) -> Result<String, String> {
        let fragment =
            VipInviteFragment::parse_url_fragment(url_fragment).map_err(|e| e.to_string())?;
        let (_sk, pk) = fragment.to_xwing_keypair();
        let info = VipFragmentInfoJson {
            key_version: fragment.key_version(),
            key_id_hex: hex::encode(pk.key_id()),
            xwing_public_key_hex: hex::encode(pk.to_bytes()),
        };
        serde_json::to_string(&info).map_err(|_| String::from("failed to encode fragment info"))
    }

    /// Generates a fresh 256-bit BIP-39 24-word English Recovery Kit phrase.
    pub fn generate_recovery_mnemonic() -> Result<Zeroizing<String>, String> {
        let secret = RecoveryMasterSecret::generate().map_err(|e| e.to_string())?;
        Ok(secret.to_mnemonic())
    }

    /// Generates a fresh 256-bit BIP-39 24-word Recovery Kit phrase as UTF-8 bytes so JS callers
    /// can hold and wipe it inside a mutable `Uint8Array`.
    pub fn generate_recovery_mnemonic_bytes() -> Result<Zeroizing<Vec<u8>>, String> {
        let mut phrase = generate_recovery_mnemonic()?;
        Ok(Zeroizing::new(core::mem::take(&mut *phrase).into_bytes()))
    }

    /// Validates a 24-word BIP-39 Recovery Kit phrase and its 8-bit SHA-256 checksum.
    pub fn validate_recovery_mnemonic(phrase: &str) -> Result<bool, String> {
        let _secret = RecoveryMasterSecret::from_mnemonic(phrase).map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Splits a BIP-39 24-word recovery phrase into `N` `GF(256)` Shamir shares (`M`-of-`N`).
    pub fn split_recovery_mnemonic_shamir_json(
        phrase: &str,
        tenant_id_hex: &str,
        threshold: u8,
        total_shares: u8,
    ) -> Result<Zeroizing<String>, String> {
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let secret = RecoveryMasterSecret::from_mnemonic(phrase).map_err(|e| e.to_string())?;
        let shares = split_recovery_secret(&secret, tenant_id, threshold, total_shares)
            .map_err(|e| e.to_string())?;

        let mut out = Vec::with_capacity(shares.len());
        for share in &shares {
            let wire = share.to_bytes();
            let mut wire_hex = Zeroizing::new(hex::encode(wire.as_slice()));
            out.push(ShamirShareOutputJson {
                share_index: share.share_index(),
                split_id_hex: hex::encode(share.split_id()),
                commitment_sha256_hex: hex::encode(share.commitment_sha256()),
                share_wire_hex: core::mem::take(&mut *wire_hex),
            });
        }
        serde_json::to_string(&out)
            .map(Zeroizing::new)
            .map_err(|_| String::from("failed to encode Shamir shares"))
    }

    /// Reconstructs a 24-word BIP-39 recovery phrase from a JSON array of hex `RCSHR` v1 shares.
    pub fn combine_shamir_shares_to_mnemonic(
        tenant_id_hex: &str,
        share_wires_json: &str,
    ) -> Result<Zeroizing<String>, String> {
        if share_wires_json.len() > MAX_CONTROL_JSON_LEN {
            return Err(String::from("shares JSON exceeds size limit"));
        }
        reject_duplicate_json_keys(share_wires_json)?;
        let tenant_id = decode_hex_exact::<16>(tenant_id_hex, "tenant_id")?;
        let raw_hex_list = ZeroizingStringVec(
            serde_json::from_str(share_wires_json)
                .map_err(|_| String::from("invalid shares JSON array"))?,
        );
        if raw_hex_list.0.is_empty() || raw_hex_list.0.len() > usize::from(MAX_SHAMIR_SHARES) {
            return Err(String::from("invalid Shamir share count"));
        }

        let mut shares = Vec::with_capacity(raw_hex_list.0.len());
        for raw_hex in &raw_hex_list.0 {
            let bytes = Zeroizing::new(
                hex::decode(raw_hex).map_err(|_| String::from("invalid share wire hex"))?,
            );
            let share = ShamirShare::from_bytes(bytes.as_slice()).map_err(|e| e.to_string())?;
            shares.push(share);
        }
        let secret = combine_recovery_shares(&tenant_id, &shares).map_err(|e| e.to_string())?;
        Ok(secret.to_mnemonic())
    }

    /// Reconstructs a 24-word BIP-39 recovery phrase as UTF-8 bytes so JS callers can wipe it
    /// inside a mutable `Uint8Array`.
    pub fn combine_shamir_shares_to_mnemonic_bytes(
        tenant_id_hex: &str,
        share_wires_json: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut phrase = combine_shamir_shares_to_mnemonic(tenant_id_hex, share_wires_json)?;
        Ok(Zeroizing::new(core::mem::take(&mut *phrase).into_bytes()))
    }
}

/// Overwrites `buf` with zeroes in place via `zeroize`.
///
/// JavaScript callers MUST call `wipe_bytes(buf)` (or `buf.fill(0)`) on every secret `Uint8Array`
/// returned across the WASM boundary once processing finishes.
#[wasm_bindgen]
pub fn wipe_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

#[wasm_bindgen]
#[must_use]
pub fn protocol_info() -> String {
    api::protocol_info_json()
}

/// Generates a Strict Account ID string.
///
/// **JS boundary note:** JavaScript strings are immutable and GC-managed; prefer
/// [`generate_strict_account_id_bytes`] when holding the secret in JS memory before display.
#[wasm_bindgen]
pub fn generate_strict_account_id() -> Result<String, JsValue> {
    api::generate_strict_account_id()
        .map(unwrap_zeroizing_string)
        .map_err(|e| JsValue::from_str(&e))
}

/// Generates a Strict Account ID as a wipeable UTF-8 `Uint8Array`.
/// Callers MUST wipe the returned buffer via [`wipe_bytes`] / `buf.fill(0)`.
#[wasm_bindgen]
pub fn generate_strict_account_id_bytes() -> Result<Vec<u8>, JsValue> {
    api::generate_strict_account_id_bytes()
        .map(unwrap_zeroizing_vec)
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn validate_strict_account_id(input: &str) -> Result<String, JsValue> {
    api::validate_strict_account_id(input)
        .map(unwrap_zeroizing_string)
        .map_err(|e| JsValue::from_str(&e))
}

/// Derives public Strict session metadata JSON (`auth_lookup_id_hex` + public keys, zero secrets).
#[wasm_bindgen]
pub fn derive_strict_session_json(
    account_id: &str,
    tenant_id_hex: &str,
) -> Result<String, JsValue> {
    api::derive_strict_session_json(account_id, tenant_id_hex).map_err(|e| JsValue::from_str(&e))
}

/// Derives the raw 32-byte OPAQUE `auth_secret` as a wipeable `Uint8Array`.
/// Callers MUST wipe the returned buffer via [`wipe_bytes`] / `buf.fill(0)` after OPAQUE login.
#[wasm_bindgen]
pub fn derive_strict_auth_secret(
    account_id: &str,
    tenant_id_hex: &str,
) -> Result<Vec<u8>, JsValue> {
    api::derive_strict_auth_secret(account_id, tenant_id_hex)
        .map(unwrap_zeroizing_vec)
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value)]
pub fn verify_skl_json(
    tenant_id_hex: &str,
    skl_json: &str,
    pinned_checkpoint_json: Option<String>,
) -> Result<String, JsValue> {
    api::verify_skl_json(tenant_id_hex, skl_json, pinned_checkpoint_json.as_deref())
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_rcenc_xwing(
    plaintext: &[u8],
    tenant_id_hex: &str,
    resource_id_hex: &str,
    envelope_kind: u8,
    privacy_tier: u8,
    schema_version: u16,
    recipients_json: &str,
) -> Result<Vec<u8>, JsValue> {
    api::encrypt_rcenc_xwing(
        plaintext,
        tenant_id_hex,
        resource_id_hex,
        envelope_kind,
        privacy_tier,
        schema_version,
        recipients_json,
    )
    .map_err(|e| JsValue::from_str(&e))
}

/// Decrypts a Strict customer `RCENC` envelope and returns plaintext as a wipeable `Uint8Array`.
/// Callers MUST wipe the returned buffer via [`wipe_bytes`] / `buf.fill(0)` once rendered.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn decrypt_rcenc_strict_customer(
    envelope: &[u8],
    account_id: &str,
    tenant_id_hex: &str,
    resource_id_hex: &str,
    envelope_kind: u8,
    privacy_tier: u8,
    schema_version: u16,
    customer_key_version: u32,
) -> Result<Vec<u8>, JsValue> {
    api::decrypt_rcenc_strict_customer(
        envelope,
        account_id,
        tenant_id_hex,
        resource_id_hex,
        envelope_kind,
        privacy_tier,
        schema_version,
        customer_key_version,
    )
    .map(unwrap_zeroizing_vec)
    .map_err(|e| JsValue::from_str(&e))
}

/// Decrypts a password-protected Private Product `RCENC` envelope under `Argon2idBudget::WASM_CLIENT`.
/// Callers MUST wipe the returned plaintext `Uint8Array` via [`wipe_bytes`] / `buf.fill(0)`.
#[wasm_bindgen]
pub fn decrypt_private_product_password(
    envelope: &[u8],
    tenant_id_hex: &str,
    product_id_hex: &str,
    privacy_tier: u8,
    schema_version: u16,
    password: &str,
) -> Result<Vec<u8>, JsValue> {
    api::decrypt_private_product_password_bytes(
        envelope,
        tenant_id_hex,
        product_id_hex,
        privacy_tier,
        schema_version,
        password,
    )
    .map(unwrap_zeroizing_vec)
    .map_err(|e| JsValue::from_str(&e))
}

/// Decrypts a VIP Group Private Product `RCENC` envelope via `#k=...` fragment.
/// Callers MUST wipe the returned plaintext `Uint8Array` via [`wipe_bytes`] / `buf.fill(0)`.
#[wasm_bindgen]
pub fn decrypt_private_product_vip_fragment(
    envelope: &[u8],
    tenant_id_hex: &str,
    product_id_hex: &str,
    privacy_tier: u8,
    schema_version: u16,
    vip_group_id_hex: &str,
    url_fragment: &str,
) -> Result<Vec<u8>, JsValue> {
    api::decrypt_private_product_vip_fragment_bytes(
        envelope,
        tenant_id_hex,
        product_id_hex,
        privacy_tier,
        schema_version,
        vip_group_id_hex,
        url_fragment,
    )
    .map(unwrap_zeroizing_vec)
    .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn inspect_vip_fragment_json(url_fragment: &str) -> Result<String, JsValue> {
    api::inspect_vip_fragment_json(url_fragment).map_err(|e| JsValue::from_str(&e))
}

/// Generates a 24-word BIP-39 recovery phrase string.
/// Prefer [`generate_recovery_mnemonic_bytes`] for wipeable JS `Uint8Array` storage.
#[wasm_bindgen]
pub fn generate_recovery_mnemonic() -> Result<String, JsValue> {
    api::generate_recovery_mnemonic()
        .map(unwrap_zeroizing_string)
        .map_err(|e| JsValue::from_str(&e))
}

/// Generates a 24-word BIP-39 recovery phrase as a wipeable UTF-8 `Uint8Array`.
/// Callers MUST wipe the returned buffer via [`wipe_bytes`] / `buf.fill(0)`.
#[wasm_bindgen]
pub fn generate_recovery_mnemonic_bytes() -> Result<Vec<u8>, JsValue> {
    api::generate_recovery_mnemonic_bytes()
        .map(unwrap_zeroizing_vec)
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn validate_recovery_mnemonic(phrase: &str) -> Result<bool, JsValue> {
    api::validate_recovery_mnemonic(phrase).map_err(|e| JsValue::from_str(&e))
}

/// Splits a recovery mnemonic into Shamir shares JSON.
/// **JS boundary note:** Contains share secrets in JSON; discard immediately after export/print.
#[wasm_bindgen]
pub fn split_recovery_mnemonic_shamir_json(
    phrase: &str,
    tenant_id_hex: &str,
    threshold: u8,
    total_shares: u8,
) -> Result<String, JsValue> {
    api::split_recovery_mnemonic_shamir_json(phrase, tenant_id_hex, threshold, total_shares)
        .map(unwrap_zeroizing_string)
        .map_err(|e| JsValue::from_str(&e))
}

/// Reconstructs a 24-word BIP-39 recovery phrase string.
/// Prefer [`combine_shamir_shares_to_mnemonic_bytes`] for wipeable JS `Uint8Array` storage.
#[wasm_bindgen]
pub fn combine_shamir_shares_to_mnemonic(
    tenant_id_hex: &str,
    share_wires_json: &str,
) -> Result<String, JsValue> {
    api::combine_shamir_shares_to_mnemonic(tenant_id_hex, share_wires_json)
        .map(unwrap_zeroizing_string)
        .map_err(|e| JsValue::from_str(&e))
}

/// Reconstructs a 24-word BIP-39 recovery phrase as a wipeable UTF-8 `Uint8Array`.
/// Callers MUST wipe the returned buffer via [`wipe_bytes`] / `buf.fill(0)`.
#[wasm_bindgen]
pub fn combine_shamir_shares_to_mnemonic_bytes(
    tenant_id_hex: &str,
    share_wires_json: &str,
) -> Result<Vec<u8>, JsValue> {
    api::combine_shamir_shares_to_mnemonic_bytes(tenant_id_hex, share_wires_json)
        .map(unwrap_zeroizing_vec)
        .map_err(|e| JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
    use super::api;
    use rustcom_crypto_core::{
        Argon2idParams, Ed25519SigningKey, EnvelopeContext, EnvelopeFlags, EnvelopeKind,
        MIN_ARGON2_M_COST_KIB, MIN_ARGON2_P_COST, MIN_ARGON2_T_COST, PrivacyTier, SklEntryV1,
        VaultRole, VipInviteFragment, XWingSecretKey, encrypt_private_product_password,
        encrypt_private_product_vip,
    };

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wasm_api_end_to_end_checkout_skl_private_product_and_shamir() -> Result<(), String> {
        let info: serde_json::Value =
            serde_json::from_str(&api::protocol_info_json()).map_err(|e| e.to_string())?;
        assert_eq!(info["rcenc_version"], 1);
        assert_eq!(info["rcstr_version"], 1);

        let tenant_id = [0x11_u8; 16];
        let tenant_hex = hex::encode(tenant_id);
        let order_id = [0x22_u8; 16];
        let order_hex = hex::encode(order_id);

        // 1. Strict Account ID + public session JSON (zero secrets) + binary auth_secret.
        let account_id = api::generate_strict_account_id()?;
        let normalized = api::validate_strict_account_id(&account_id.to_lowercase())?;
        assert_eq!(normalized.as_str(), account_id.as_str());
        let id_bytes = api::generate_strict_account_id_bytes()?;
        assert_eq!(id_bytes.len(), 34);
        let session_str = api::derive_strict_session_json(&account_id, &tenant_hex)?;
        let session: serde_json::Value =
            serde_json::from_str(&session_str).map_err(|e| e.to_string())?;
        assert!(session.get("auth_secret_hex").is_none());
        let mut auth_secret = api::derive_strict_auth_secret(&account_id, &tenant_hex)?;
        assert_eq!(auth_secret.len(), 32);
        super::wipe_bytes(&mut auth_secret);
        assert!(auth_secret.iter().all(|&b| b == 0));
        let cust_pk_hex = session["xwing_public_key_hex"]
            .as_str()
            .ok_or_else(|| String::from("missing cust pk"))?;
        let cust_key_id_hex = session["xwing_key_id_hex"]
            .as_str()
            .ok_or_else(|| String::from("missing cust key id"))?;

        // 2. SKL JSON verification.
        let (store_id_sk, _store_id_vk) =
            Ed25519SigningKey::generate().map_err(|e| e.to_string())?;
        let (_org_sk, org_pk) = XWingSecretKey::generate().map_err(|e| e.to_string())?;
        let e0 = SklEntryV1::sign_genesis(
            tenant_id,
            VaultRole::OrgMaster,
            org_pk.clone(),
            &store_id_sk,
            1_795_400_000,
        )
        .map_err(|e| e.to_string())?;
        let skl_json = serde_json::json!({
            "entries": [{
                "tenant_id_hex": tenant_hex,
                "seq": e0.seq(),
                "vault_role": e0.vault_role().as_u8(),
                "key_version": e0.key_version(),
                "xwing_pk_hex": hex::encode(e0.xwing_pk().to_bytes()),
                "identity_ed25519_pk_hex": hex::encode(e0.identity_ed25519_pk().to_bytes()),
                "issued_at_unix": e0.issued_at_unix(),
                "prev_entry_hash_hex": hex::encode(e0.prev_entry_hash()),
                "signature_hex": hex::encode(e0.signature()),
                "rotation_cross_signature_hex": null
            }]
        })
        .to_string();
        let verified_str = api::verify_skl_json(&tenant_hex, &skl_json, None)?;
        // Duplicate JSON keys (including Unicode-escaped duplicates) rejected.
        let dup_skl = format!(
            r#"{{"entries":[],"\u0065ntries":{}}}"#,
            &skl_json[11..skl_json.len() - 1]
        );
        assert!(api::verify_skl_json(&tenant_hex, &dup_skl, None).is_err());
        let verified: serde_json::Value =
            serde_json::from_str(&verified_str).map_err(|e| e.to_string())?;
        let verified_org_pk_hex = verified["org_master"]["xwing_pk_hex"]
            .as_str()
            .ok_or_else(|| String::from("missing org pk"))?;
        let verified_org_key_id_hex = verified["org_master"]["key_id_hex"]
            .as_str()
            .ok_or_else(|| String::from("missing org key id"))?;

        // 3. Dual-wrapped Strict order encrypt -> customer decrypt inside WASM.
        let recipients_json = serde_json::json!([
            {
                "recipient_type": 1,
                "key_id_hex": verified_org_key_id_hex,
                "key_version": 1,
                "xwing_public_key_hex": verified_org_pk_hex
            },
            {
                "recipient_type": 2,
                "key_id_hex": cust_key_id_hex,
                "key_version": 1,
                "xwing_public_key_hex": cust_pk_hex
            }
        ])
        .to_string();
        let order_pt = b"{\"ship_to\":\"Strict Vault Buyer\"}";
        let envelope = api::encrypt_rcenc_xwing(
            order_pt,
            &tenant_hex,
            &order_hex,
            EnvelopeKind::OrderFulfillment.as_u8(),
            PrivacyTier::Strict.as_u8(),
            1,
            &recipients_json,
        )?;
        let decrypted = api::decrypt_rcenc_strict_customer(
            &envelope,
            &account_id,
            &tenant_hex,
            &order_hex,
            EnvelopeKind::OrderFulfillment.as_u8(),
            PrivacyTier::Strict.as_u8(),
            1,
            1,
        )?;
        assert_eq!(decrypted.as_slice(), order_pt);

        // 4. Private Product password & VIP `#k=` decrypt (plus WASM Argon2id DoS cap check).
        let prod_id = [0x33_u8; 16];
        let prod_hex = hex::encode(prod_id);
        let prod_ctx = EnvelopeContext {
            envelope_kind: EnvelopeKind::PrivateProduct,
            tenant_id,
            resource_id: prod_id,
            privacy_tier: PrivacyTier::Strict,
            schema_version: 1,
        };
        let params =
            Argon2idParams::new(MIN_ARGON2_M_COST_KIB, MIN_ARGON2_T_COST, MIN_ARGON2_P_COST)
                .map_err(|e| e.to_string())?;
        let pw_ct = encrypt_private_product_password(
            b"secret-drop",
            &prod_ctx,
            EnvelopeFlags::default(),
            b"drop-pass-2026",
            1,
            params,
            &[],
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(
            api::decrypt_private_product_password_bytes(
                &pw_ct,
                &tenant_hex,
                &prod_hex,
                PrivacyTier::Strict.as_u8(),
                1,
                "drop-pass-2026"
            )?
            .as_slice(),
            b"secret-drop"
        );
        // Hostile 128 MiB / t=8 envelope rejected by WASM_CLIENT Argon2id budget before KDF.
        let mut hostile_pw_ct = pw_ct.clone();
        let kem_offset = rustcom_crypto_core::RCENC_HEADER_LEN + 1 + 16 + 4 + 2;
        hostile_pw_ct[kem_offset + 32..kem_offset + 36]
            .copy_from_slice(&rustcom_crypto_core::MAX_ARGON2_M_COST_KIB.to_be_bytes());
        hostile_pw_ct[kem_offset + 36..kem_offset + 40]
            .copy_from_slice(&rustcom_crypto_core::MAX_ARGON2_T_COST.to_be_bytes());
        assert!(
            api::decrypt_private_product_password_bytes(
                &hostile_pw_ct,
                &tenant_hex,
                &prod_hex,
                PrivacyTier::Strict.as_u8(),
                1,
                "drop-pass-2026"
            )
            .is_err()
        );

        let vip_group_id = [0x44_u8; 16];
        let vip_hex = hex::encode(vip_group_id);
        let (vip_secret, vip_public) = XWingSecretKey::generate().map_err(|e| e.to_string())?;
        let frag = VipInviteFragment::from_secret_key(1, &vip_secret).map_err(|e| e.to_string())?;
        let frag_str = frag.to_url_fragment();
        let frag_info: serde_json::Value =
            serde_json::from_str(&api::inspect_vip_fragment_json(&frag_str)?)
                .map_err(|e| e.to_string())?;
        assert_eq!(frag_info["key_version"], 1);
        let vip_ct = encrypt_private_product_vip(
            b"vip-secret",
            &prod_ctx,
            EnvelopeFlags::default(),
            vip_group_id,
            1,
            &vip_public,
            &[],
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(
            api::decrypt_private_product_vip_fragment_bytes(
                &vip_ct,
                &tenant_hex,
                &prod_hex,
                PrivacyTier::Strict.as_u8(),
                1,
                &vip_hex,
                &frag_str
            )?
            .as_slice(),
            b"vip-secret"
        );

        // 5. BIP-39 Recovery + Shamir 2-of-3 split & combine (including wipeable byte APIs).
        let phrase = api::generate_recovery_mnemonic()?;
        assert!(api::validate_recovery_mnemonic(&phrase)?);
        let phrase_bytes = api::generate_recovery_mnemonic_bytes()?;
        assert!(!phrase_bytes.is_empty());
        let shares_str = api::split_recovery_mnemonic_shamir_json(&phrase, &tenant_hex, 2, 3)?;
        let shares: Vec<serde_json::Value> =
            serde_json::from_str(&shares_str).map_err(|e| e.to_string())?;
        assert_eq!(shares.len(), 3);
        let subset_json =
            serde_json::json!([shares[0]["share_wire_hex"], shares[2]["share_wire_hex"]])
                .to_string();
        let recovered_phrase = api::combine_shamir_shares_to_mnemonic(&tenant_hex, &subset_json)?;
        assert_eq!(recovered_phrase.as_str(), phrase.as_str());
        let recovered_bytes =
            api::combine_shamir_shares_to_mnemonic_bytes(&tenant_hex, &subset_json)?;
        assert_eq!(recovered_bytes.as_slice(), phrase.as_bytes());

        Ok(())
    }
}

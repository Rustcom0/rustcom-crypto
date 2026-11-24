#![forbid(unsafe_code)]
#![allow(
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use proptest::prelude::*;
use rand_core::{TryCryptoRng, TryRng};
use rustcom_crypto_core::RecoveryMasterSecret;
use rustcom_crypto_core::{
    BIP39_MAX_INPUT_LEN, CryptoError, ED25519_SIGNATURE_LEN, Ed25519SigningKey, EnvelopeContext,
    EnvelopeFlags, EnvelopeKind, MAX_SHAMIR_SHARES, ORG_KEY_ARCHIVE_PAYLOAD_LEN,
    ORG_KEY_ARCHIVE_SCHEMA_VERSION, OrgKeyBackupEntry, PrivacyTier, RECOVERY_BACKUP_SCHEMA_VERSION,
    RECOVERY_SECRET_LEN, RecipientCredential, RecipientSpec, RecipientType, SHAMIR_SHARE_WIRE_LEN,
    SKL_BODY_LEN, SKL_ENTRY_BASE_WIRE_LEN, SKL_ENTRY_ROTATE_WIRE_LEN, STAFF_GRANT_MSG_LEN,
    STAFF_GRANT_WIRE_LEN, STAFF_KEY_WRAP_SCHEMA_VERSION, ShamirShare, SklCheckpoint, SklEntryV1,
    StaffGrantV1, VaultRole, XWingSecretKey, archive_org_key, archive_org_key_with_rng,
    combine_recovery_shares, decrypt, encrypt, hash_xwing_public_key, split_recovery_secret,
    split_recovery_secret_with_rng, unwrap_archived_org_key, unwrap_recovery_backup,
    unwrap_staff_org_key, verify_skl_chain, wrap_recovery_backup, wrap_recovery_backup_with_rng,
    wrap_staff_org_key, wrap_staff_org_key_with_rng,
};
use serde::Deserialize;

/// Deterministic XOF-backed RNG strictly for reproducible KAT vectors and property tests.
/// NEVER used in production code.
struct DeterministicTestRng {
    reader: blake3::OutputReader,
}

impl DeterministicTestRng {
    fn from_label(label: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"rustcom-test-rng-v1:");
        hasher.update(label);
        Self {
            reader: hasher.finalize_xof(),
        }
    }
}

impl TryRng for DeterministicTestRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0_u8; 4];
        self.reader.fill(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0_u8; 8];
        self.reader.fill(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.reader.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for DeterministicTestRng {}

fn decode_hex_array<const N: usize>(s: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    let arr: [u8; N] = bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes from hex"))?;
    Ok(arr)
}

#[test]
fn staff_grant_wrap_rotation_archive_and_tamper_defenses() -> Result<(), Box<dyn std::error::Error>>
{
    let tenant_id = [0x11_u8; 16];
    let other_tenant = [0x22_u8; 16];
    let owner_id = [0xA1_u8; 16];
    let staff_id = [0xB2_u8; 16];
    let other_staff_id = [0xC3_u8; 16];

    let (owner_ed_sk, owner_ed_vk) = Ed25519SigningKey::generate()?;
    let (rogue_ed_sk, rogue_ed_vk) = Ed25519SigningKey::generate()?;
    let (staff_xwing_sk, staff_xwing_pk) = XWingSecretKey::generate()?;
    let (rogue_staff_sk, rogue_staff_pk) = XWingSecretKey::generate()?;

    let (org_v1_sk, org_v1_pk) = XWingSecretKey::generate()?;
    let (org_v2_sk, org_v2_pk) = XWingSecretKey::generate()?;
    let (org_v3_sk, org_v3_pk) = XWingSecretKey::generate()?;

    // Owner grants Fulfillment v1 to staff member.
    let (grant, wrapped) = wrap_staff_org_key(
        tenant_id,
        PrivacyTier::Strict,
        VaultRole::Fulfillment,
        1,
        &org_v1_sk,
        staff_id,
        1,
        &staff_xwing_pk,
        1_795_400_000,
        owner_id,
        &owner_ed_sk,
    )?;
    assert_eq!(grant.signing_message().len(), STAFF_GRANT_MSG_LEN);

    // Canonical 158-byte binary roundtrip + framing error checks.
    let grant_wire = grant.to_bytes();
    assert_eq!(grant_wire.len(), STAFF_GRANT_WIRE_LEN);
    let parsed_grant = StaffGrantV1::from_bytes(&grant_wire)?;
    assert_eq!(parsed_grant, grant);
    assert_eq!(
        StaffGrantV1::from_bytes(&grant_wire[..STAFF_GRANT_WIRE_LEN - 1]),
        Err(CryptoError::TruncatedInput)
    );
    let mut with_trailing = grant_wire.to_vec();
    with_trailing.push(0x00);
    assert_eq!(
        StaffGrantV1::from_bytes(&with_trailing),
        Err(CryptoError::TrailingBytes)
    );
    let mut bad_ver = grant_wire;
    bad_ver[0] = 0x02;
    assert_eq!(
        StaffGrantV1::from_bytes(&bad_ver),
        Err(CryptoError::UnsupportedFormatVersion(0x02))
    );
    let mut bad_role = grant_wire;
    bad_role[17] = 0x99;
    assert_eq!(
        StaffGrantV1::from_bytes(&bad_role),
        Err(CryptoError::InvalidVaultRole(0x99))
    );
    let mut zero_ver = grant_wire;
    zero_ver[18..22].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        StaffGrantV1::from_bytes(&zero_ver),
        Err(CryptoError::InvalidKeyVersion(0))
    );
    let mut zero_ts = grant_wire;
    zero_ts[70..78].copy_from_slice(&0_u64.to_be_bytes());
    assert_eq!(
        StaffGrantV1::from_bytes(&zero_ts),
        Err(CryptoError::InvalidStaffGrant)
    );

    // Authorized staff member verifies grant & unwraps org v1 key anchored against SKL org_v1_pk.
    let unwrapped_v1 = unwrap_staff_org_key(
        &parsed_grant,
        &wrapped,
        &owner_ed_vk,
        &owner_id,
        &tenant_id,
        PrivacyTier::Strict,
        VaultRole::Fulfillment,
        1,
        &staff_id,
        1,
        &staff_xwing_sk,
        &org_v1_pk,
    )?;
    assert_eq!(unwrapped_v1.public_key(), org_v1_pk);

    // Owner self-grant (grantor == target) succeeds for initial store bootstrap.
    let (owner_xwing_sk, owner_xwing_pk) = XWingSecretKey::generate()?;
    let (self_grant, self_wrapped) = wrap_staff_org_key(
        tenant_id,
        PrivacyTier::Flexible,
        VaultRole::OrgMaster,
        1,
        &org_v1_sk,
        owner_id,
        1,
        &owner_xwing_pk,
        1_795_400_001,
        owner_id,
        &owner_ed_sk,
    )?;
    let self_unwrapped = unwrap_staff_org_key(
        &self_grant,
        &self_wrapped,
        &owner_ed_vk,
        &owner_id,
        &tenant_id,
        PrivacyTier::Flexible,
        VaultRole::OrgMaster,
        1,
        &owner_id,
        1,
        &owner_xwing_sk,
        &org_v1_pk,
    )?;
    assert_eq!(self_unwrapped.public_key(), org_v1_pk);

    // Attack 1: Wrong grantor Ed25519 verifying key or grantor staff ID.
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &rogue_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidSignature)
    );
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &owner_ed_vk,
            &other_staff_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffGrant)
    );

    // Attack 2: Cross-tenant, cross-role, wrong store_key_ver, or wrong target staff / rogue key.
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &owner_ed_vk,
            &owner_id,
            &other_tenant,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffGrant)
    );
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &owner_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Accounting,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffGrant)
    );
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &owner_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            2,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffGrant)
    );
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &owner_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &rogue_staff_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffGrant)
    );

    // Attack 3: Compromised grantor/server wraps a key that does NOT match SKL's expected_org_pk.
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &wrapped,
            &owner_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v2_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffKeyPayload)
    );

    // Attack 4: Multi-recipient StaffKeyWrap envelope rejected before decapsulation.
    let forged_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::StaffKeyWrap,
        tenant_id,
        resource_id: staff_id,
        privacy_tier: PrivacyTier::Strict,
        schema_version: STAFF_KEY_WRAP_SCHEMA_VERSION,
    };
    let multi_wrap = encrypt(
        &[0_u8; 75],
        &forged_ctx,
        EnvelopeFlags::default(),
        &[
            RecipientSpec::XWing {
                recipient_type: RecipientType::XWingStaffKey,
                key_id: staff_xwing_pk.key_id(),
                key_version: 1,
                public_key: &staff_xwing_pk,
            },
            RecipientSpec::XWing {
                recipient_type: RecipientType::XWingStaffKey,
                key_id: rogue_staff_pk.key_id(),
                key_version: 1,
                public_key: &rogue_staff_pk,
            },
        ],
    )?;
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &multi_wrap,
            &owner_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffKeyPayload)
    );

    // Revocation + rotation chain: archive v1 under v2, archive v2 under v3, then unwrap v3 -> v2 -> v1
    // and decrypt a historical VAT order encrypted under v1.
    let order_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::OrderAccounting,
        tenant_id,
        resource_id: [0x99_u8; 16],
        privacy_tier: PrivacyTier::Strict,
        schema_version: 1,
    };
    let historical_order_pt = b"{\"invoice\":\"INV-2026-0001\",\"vat_minor\":1900}";
    let historical_order_ct = encrypt(
        historical_order_pt,
        &order_ctx,
        EnvelopeFlags::default(),
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_v1_pk.key_id(),
            key_version: 1,
            public_key: &org_v1_pk,
        }],
    )?;

    let arch_v1_under_v2 = archive_org_key(
        tenant_id,
        PrivacyTier::Strict,
        VaultRole::Accounting,
        1,
        &org_v1_sk,
        2,
        &org_v2_pk,
    )?;
    let arch_v2_under_v3 = archive_org_key(
        tenant_id,
        PrivacyTier::Strict,
        VaultRole::Accounting,
        2,
        &org_v2_sk,
        3,
        &org_v3_pk,
    )?;

    let recovered_v2 = unwrap_archived_org_key(
        &arch_v2_under_v3,
        &tenant_id,
        PrivacyTier::Strict,
        VaultRole::Accounting,
        2,
        3,
        &org_v3_sk,
        &org_v2_pk,
    )?;
    let recovered_v1 = unwrap_archived_org_key(
        &arch_v1_under_v2,
        &tenant_id,
        PrivacyTier::Strict,
        VaultRole::Accounting,
        1,
        2,
        &recovered_v2,
        &org_v1_pk,
    )?;

    let dec_order = decrypt(
        &historical_order_ct,
        &order_ctx,
        &RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_v1_pk.key_id(),
            key_version: 1,
            secret_key: &recovered_v1,
        },
    )?;
    assert_eq!(dec_order.plaintext.as_slice(), historical_order_pt);

    // Archive safety checks: cannot archive under same/older version, same key, or cross-schema replay.
    assert_eq!(
        archive_org_key(
            tenant_id,
            PrivacyTier::Strict,
            VaultRole::Accounting,
            2,
            &org_v2_sk,
            2,
            &org_v3_pk,
        )
        .err(),
        Some(CryptoError::InvalidKeyVersion(2))
    );
    assert_eq!(
        archive_org_key(
            tenant_id,
            PrivacyTier::Strict,
            VaultRole::Accounting,
            1,
            &org_v1_sk,
            2,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffKeyPayload)
    );
    // Cross-schema replay: RCSKW cannot be unwrapped by unwrap_archived_org_key.
    assert_eq!(
        unwrap_archived_org_key(
            &wrapped,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            2,
            &org_v2_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffKeyPayload)
    );
    // Tampered RCARC payload length rejected before decapsulation.
    let bad_arch_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::StaffKeyWrap,
        tenant_id,
        resource_id: org_v2_pk.key_id(),
        privacy_tier: PrivacyTier::Strict,
        schema_version: ORG_KEY_ARCHIVE_SCHEMA_VERSION,
    };
    let wrong_len_arch = encrypt(
        &[0_u8; ORG_KEY_ARCHIVE_PAYLOAD_LEN + 1],
        &bad_arch_ctx,
        EnvelopeFlags::default(),
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_v2_pk.key_id(),
            key_version: 2,
            public_key: &org_v2_pk,
        }],
    )?;
    assert_eq!(
        unwrap_archived_org_key(
            &wrong_len_arch,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Accounting,
            1,
            2,
            &org_v2_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffKeyPayload)
    );
    // Self-archive symmetry check rejected before decapsulation in unwrap_archived_org_key.
    assert_eq!(
        unwrap_archived_org_key(
            &arch_v1_under_v2,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Accounting,
            1,
            2,
            &org_v2_sk,
            &org_v2_pk,
        )
        .err(),
        Some(CryptoError::InvalidStaffKeyPayload)
    );
    // Non-zero flags (e.g. compressed_zstd = 0x01) rejected on both RCSKW and RCARC before decapsulation.
    let compressed_staff_wrap = encrypt(
        &[0_u8; 75],
        &forged_ctx,
        EnvelopeFlags::new(true),
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingStaffKey,
            key_id: staff_xwing_pk.key_id(),
            key_version: 1,
            public_key: &staff_xwing_pk,
        }],
    )?;
    assert_eq!(
        unwrap_staff_org_key(
            &grant,
            &compressed_staff_wrap,
            &owner_ed_vk,
            &owner_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &staff_id,
            1,
            &staff_xwing_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::UnsupportedFlags(0x01))
    );
    let compressed_arch = encrypt(
        &[0_u8; ORG_KEY_ARCHIVE_PAYLOAD_LEN],
        &bad_arch_ctx,
        EnvelopeFlags::new(true),
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_v2_pk.key_id(),
            key_version: 2,
            public_key: &org_v2_pk,
        }],
    )?;
    assert_eq!(
        unwrap_archived_org_key(
            &compressed_arch,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Accounting,
            1,
            2,
            &org_v2_sk,
            &org_v1_pk,
        )
        .err(),
        Some(CryptoError::UnsupportedFlags(0x01))
    );
    let _ = rogue_ed_sk;
    Ok(())
}

#[test]
fn skl_append_only_chain_identity_rotation_checkpoints_and_attacks()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = [0x33_u8; 16];
    let other_tenant = [0x44_u8; 16];

    let (id1_sk, id1_vk) = Ed25519SigningKey::generate()?;
    let (id2_sk, id2_vk) = Ed25519SigningKey::generate()?;
    let (rogue_id_sk, _rogue_id_vk) = Ed25519SigningKey::generate()?;

    let (_, org_m1) = XWingSecretKey::generate()?;
    let (_, ful_1) = XWingSecretKey::generate()?;
    let (_, acc_1) = XWingSecretKey::generate()?;
    let (_, org_m2) = XWingSecretKey::generate()?;
    let (_, org_m3) = XWingSecretKey::generate()?;
    let (_, ful_2) = XWingSecretKey::generate()?;

    let e0 = SklEntryV1::sign_genesis(
        tenant_id,
        VaultRole::OrgMaster,
        org_m1.clone(),
        &id1_sk,
        1_795_400_000,
    )?;
    let e1 = SklEntryV1::sign_next(
        &e0,
        VaultRole::Fulfillment,
        1,
        ful_1.clone(),
        &id1_sk,
        1_795_400_000, // Equal timestamp allowed (store bootstrap).
    )?;
    let e2 = SklEntryV1::sign_next(
        &e1,
        VaultRole::Accounting,
        1,
        acc_1.clone(),
        &id1_sk,
        1_795_400_005,
    )?;
    let e3 = SklEntryV1::sign_next(
        &e2,
        VaultRole::OrgMaster,
        2,
        org_m2.clone(),
        &id1_sk,
        1_795_400_100,
    )?;
    // Identity key rotation from id1 -> id2, cross-signed by id1.
    let e4 = SklEntryV1::sign_next_with_identity_rotation(
        &e3,
        VaultRole::OrgMaster,
        3,
        org_m3.clone(),
        &id1_sk,
        &id2_sk,
        1_795_400_200,
    )?;
    // Subsequent entry signed under id2.
    let e5 = SklEntryV1::sign_next(
        &e4,
        VaultRole::Fulfillment,
        2,
        ful_2.clone(),
        &id2_sk,
        1_795_400_300,
    )?;

    // Canonical wire roundtrip checks.
    assert_eq!(e0.canonical_body_bytes().len(), SKL_BODY_LEN);
    assert_eq!(e0.canonical_bytes().len(), SKL_ENTRY_BASE_WIRE_LEN);
    assert_eq!(e4.canonical_bytes().len(), SKL_ENTRY_ROTATE_WIRE_LEN);
    assert_eq!(SklEntryV1::from_canonical_bytes(&e0.canonical_bytes())?, e0);
    assert_eq!(SklEntryV1::from_canonical_bytes(&e4.canonical_bytes())?, e4);
    assert_eq!(
        e4.entry_hash(),
        *blake3::hash(&e4.canonical_bytes()).as_bytes()
    );

    let chain = vec![
        e0.clone(),
        e1.clone(),
        e2.clone(),
        e3.clone(),
        e4.clone(),
        e5.clone(),
    ];
    let verified = verify_skl_chain(&tenant_id, &chain, None)?;
    assert_eq!(verified.latest_seq(), 5);
    assert_eq!(verified.current_identity_pk(), &id2_vk);
    assert_eq!(
        verified.active_key(VaultRole::OrgMaster),
        Some((3, &org_m3))
    );
    assert_eq!(
        verified.active_key(VaultRole::Fulfillment),
        Some((2, &ful_2))
    );
    assert_eq!(
        verified.active_key(VaultRole::Accounting),
        Some((1, &acc_1))
    );
    assert_eq!(
        verified.key_for_version(VaultRole::OrgMaster, 1),
        Some(&org_m1)
    );
    assert_eq!(
        verified.key_for_version(VaultRole::OrgMaster, 2),
        Some(&org_m2)
    );
    assert_eq!(
        verified.key_for_version(VaultRole::OrgMaster, 3),
        Some(&org_m3)
    );
    assert_eq!(verified.key_for_version(VaultRole::OrgMaster, 4), None);

    // Pinned checkpoint at seq 3 passes on the extended chain.
    let cp_at_3 = SklCheckpoint {
        seq: 3,
        entry_hash: e3.entry_hash(),
        identity_ed25519_pk: id1_vk,
    };
    let verified_cp = verify_skl_chain(&tenant_id, &chain, Some(&cp_at_3))?;
    assert_eq!(verified_cp.checkpoint().seq, 5);

    // Attack 1: Truncation / rollback past pinned checkpoint fails.
    assert_eq!(
        verify_skl_chain(&tenant_id, &chain[..3], Some(&cp_at_3)).err(),
        Some(CryptoError::InvalidSklChain)
    );
    // Attack 2: Forked checkpoint hash fails.
    let mut bad_cp = cp_at_3;
    bad_cp.entry_hash[0] ^= 0x01;
    assert_eq!(
        verify_skl_chain(&tenant_id, &chain, Some(&bad_cp)).err(),
        Some(CryptoError::InvalidSklChain)
    );
    // Attack 3: Empty chain & wrong tenant fail.
    assert_eq!(
        verify_skl_chain(&tenant_id, &[], None).err(),
        Some(CryptoError::InvalidSklChain)
    );
    assert_eq!(
        verify_skl_chain(&other_tenant, &chain, None).err(),
        Some(CryptoError::InvalidSklChain)
    );

    // Attack 4: Missing cross-signature on identity rotation fails.
    let mut missing_cross = chain.clone();
    missing_cross[4] = SklEntryV1::from_parts(
        *e4.tenant_id(),
        e4.seq(),
        e4.vault_role(),
        e4.key_version(),
        e4.xwing_pk().clone(),
        *e4.identity_ed25519_pk(),
        e4.issued_at_unix(),
        *e4.prev_entry_hash(),
        *e4.signature(),
        None,
    )?;
    assert_eq!(
        verify_skl_chain(&tenant_id, &missing_cross[..5], None).err(),
        Some(CryptoError::InvalidSklChain)
    );

    // Attack 5: Forged cross-signature (signed by rogue key) fails.
    let mut rogue_cross = chain.clone();
    rogue_cross[4] = SklEntryV1::from_parts(
        *e4.tenant_id(),
        e4.seq(),
        e4.vault_role(),
        e4.key_version(),
        e4.xwing_pk().clone(),
        *e4.identity_ed25519_pk(),
        e4.issued_at_unix(),
        *e4.prev_entry_hash(),
        *e4.signature(),
        Some(rogue_id_sk.sign(&e4.canonical_body_bytes())),
    )?;
    assert_eq!(
        verify_skl_chain(&tenant_id, &rogue_cross[..5], None).err(),
        Some(CryptoError::InvalidSignature)
    );

    // Attack 6: Extraneous cross-signature on non-rotation entry or genesis fails.
    let mut extra_cross = chain.clone();
    extra_cross[0] = SklEntryV1::from_parts(
        *e0.tenant_id(),
        e0.seq(),
        e0.vault_role(),
        e0.key_version(),
        e0.xwing_pk().clone(),
        *e0.identity_ed25519_pk(),
        e0.issued_at_unix(),
        *e0.prev_entry_hash(),
        *e0.signature(),
        Some([0xAA_u8; ED25519_SIGNATURE_LEN]),
    )?;
    assert_eq!(
        verify_skl_chain(&tenant_id, &extra_cross[..1], None).err(),
        Some(CryptoError::InvalidSklChain)
    );

    // Attack 7: Revoked / previously used X-Wing public key resurrected across roles or versions.
    let resurrected = SklEntryV1::sign_next(
        &e5,
        VaultRole::Accounting,
        2,
        org_m1.clone(), // Already used at seq 0!
        &id2_sk,
        1_795_400_400,
    )?;
    let mut with_resurrected = chain.clone();
    with_resurrected.push(resurrected);
    assert_eq!(
        verify_skl_chain(&tenant_id, &with_resurrected, None).err(),
        Some(CryptoError::InvalidSklChain)
    );

    // Attack 8: Skipped key_version for a role fails.
    let (_, acc_skip) = XWingSecretKey::generate()?;
    let skipped = SklEntryV1::sign_next(
        &e5,
        VaultRole::Accounting,
        3, // Expected 2!
        acc_skip,
        &id2_sk,
        1_795_400_400,
    )?;
    let mut with_skipped = chain.clone();
    with_skipped.push(skipped);
    assert_eq!(
        verify_skl_chain(&tenant_id, &with_skipped, None).err(),
        Some(CryptoError::InvalidKeyVersion(3))
    );

    // Attack 9: Backdated timestamp fails both signing & chain verification.
    let (_, ful_3) = XWingSecretKey::generate()?;
    assert_eq!(
        SklEntryV1::sign_next(
            &e5,
            VaultRole::Fulfillment,
            3,
            ful_3,
            &id2_sk,
            1_795_400_299
        )
        .err(),
        Some(CryptoError::InvalidSklChain)
    );

    // Attack 10: Tampered prev_entry_hash breaks chain.
    let mut bad_prev = e1.canonical_bytes();
    bad_prev[SKL_BODY_LEN - 1] ^= 0x01;
    let parsed_bad_prev = SklEntryV1::from_canonical_bytes(&bad_prev)?;
    assert_eq!(
        verify_skl_chain(&tenant_id, &[e0, parsed_bad_prev], None).err(),
        Some(CryptoError::InvalidSklChain)
    );

    // Attack 11: Resurrecting a retired StoreIdentity_Ed25519 key (id1 -> id2 -> id1) fails.
    let (_, org_m4) = XWingSecretKey::generate()?;
    let resurrected_id = SklEntryV1::sign_next_with_identity_rotation(
        &e5,
        VaultRole::OrgMaster,
        4,
        org_m4,
        &id2_sk,
        &id1_sk,
        1_795_400_500,
    )?;
    let mut with_resurrected_id = chain;
    with_resurrected_id.push(resurrected_id);
    assert_eq!(
        verify_skl_chain(&tenant_id, &with_resurrected_id, None).err(),
        Some(CryptoError::InvalidSklChain)
    );

    Ok(())
}

#[test]
fn bip39_official_trezor_256bit_vectors_validation_and_recovery_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    // All 8 official upstream Trezor BIP-39 256-bit English test vectors.
    const TREZOR_256_VECTORS: [(&str, &str); 8] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        ),
    ];

    for (entropy_hex, expected_phrase) in TREZOR_256_VECTORS {
        let raw = decode_hex_array::<RECOVERY_SECRET_LEN>(entropy_hex)?;
        let secret = RecoveryMasterSecret::from_slice(&raw)?;
        let mnemonic = secret.to_mnemonic();
        assert_eq!(mnemonic.as_str(), expected_phrase);

        let parsed = RecoveryMasterSecret::from_mnemonic(expected_phrase)?;
        assert_eq!(parsed, secret);
    }

    // Normalization (uppercase, tabs, newlines, multiple spaces) works cleanly.
    let messy = "  \tABANDON   Abandon\r\nabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ART\n ";
    assert_eq!(
        RecoveryMasterSecret::from_mnemonic(messy)?,
        RecoveryMasterSecret::from_bytes([0_u8; 32])
    );

    // Format & checksum rejections.
    assert_eq!(
        RecoveryMasterSecret::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
        )
        .err(),
        Some(CryptoError::InvalidMnemonicChecksum)
    );
    assert_eq!(
        RecoveryMasterSecret::from_mnemonic("abandon abandon art").err(),
        Some(CryptoError::InvalidMnemonicFormat)
    );
    assert_eq!(
        RecoveryMasterSecret::from_mnemonic(
            "abandon\0 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        )
        .err(),
        Some(CryptoError::InvalidMnemonicFormat)
    );
    assert_eq!(
        RecoveryMasterSecret::from_mnemonic(&"a".repeat(BIP39_MAX_INPUT_LEN + 1)).err(),
        Some(CryptoError::InvalidMnemonicFormat)
    );

    // Tenant isolation of RecoveryKEK & Debug redaction.
    let secret = RecoveryMasterSecret::generate()?;
    let tenant_a = [0x55_u8; 16];
    let tenant_b = [0x66_u8; 16];
    assert_ne!(
        secret.derive_recovery_kek(&tenant_a)?,
        secret.derive_recovery_kek(&tenant_b)?
    );
    let dbg_str = format!("{secret:?}");
    assert!(dbg_str.contains("REDACTED"));
    assert!(!dbg_str.contains(&hex::encode(secret.as_bytes())));

    // Full RCREC v1 recovery bundle roundtrip with 3 role-split org keys + StoreIdentity Ed25519.
    let (id_sk, id_vk) = Ed25519SigningKey::generate()?;
    let (org_sk, org_pk) = XWingSecretKey::generate()?;
    let (ful_sk, ful_pk) = XWingSecretKey::generate()?;
    let (acc_sk, acc_pk) = XWingSecretKey::generate()?;

    let backup_ct = wrap_recovery_backup(
        &secret,
        tenant_a,
        PrivacyTier::Strict,
        1,
        &id_sk,
        &[
            OrgKeyBackupEntry {
                vault_role: VaultRole::OrgMaster,
                key_version: 3,
                xwing_secret: &org_sk,
            },
            OrgKeyBackupEntry {
                vault_role: VaultRole::Fulfillment,
                key_version: 2,
                xwing_secret: &ful_sk,
            },
            OrgKeyBackupEntry {
                vault_role: VaultRole::Accounting,
                key_version: 1,
                xwing_secret: &acc_sk,
            },
        ],
    )?;

    let phrase = secret.to_mnemonic();
    let recovered_secret = RecoveryMasterSecret::from_mnemonic(&phrase)?;
    let bundle = unwrap_recovery_backup(
        &backup_ct,
        &recovered_secret,
        &tenant_a,
        PrivacyTier::Strict,
        1,
    )?;
    assert_eq!(bundle.tenant_id(), &tenant_a);
    assert_eq!(bundle.recovery_version(), 1);
    assert_eq!(bundle.store_identity_sk().verifying_key(), id_vk);
    assert_eq!(bundle.org_keys().len(), 3);
    assert_eq!(
        bundle
            .org_key_for_role(VaultRole::OrgMaster)
            .map(|k| (k.key_version(), k.xwing_secret().public_key())),
        Some((3, org_pk))
    );
    assert_eq!(
        bundle
            .org_key_for_role(VaultRole::Fulfillment)
            .map(|k| (k.key_version(), k.xwing_secret().public_key())),
        Some((2, ful_pk))
    );
    assert_eq!(
        bundle
            .org_key_for_role(VaultRole::Accounting)
            .map(|k| (k.key_version(), k.xwing_secret().public_key())),
        Some((1, acc_pk))
    );
    let bundle_dbg = format!("{bundle:?}");
    assert!(bundle_dbg.contains("REDACTED"));

    // Wrong tenant, wrong mnemonic, wrong version, duplicate roles, empty keys rejected.
    assert_eq!(
        unwrap_recovery_backup(
            &backup_ct,
            &recovered_secret,
            &tenant_b,
            PrivacyTier::Strict,
            1
        )
        .err(),
        Some(CryptoError::RecipientNotFound)
    );
    let wrong_secret = RecoveryMasterSecret::generate()?;
    assert_eq!(
        unwrap_recovery_backup(&backup_ct, &wrong_secret, &tenant_a, PrivacyTier::Strict, 1).err(),
        Some(CryptoError::DecryptionFailed)
    );
    assert_eq!(
        wrap_recovery_backup(&secret, tenant_a, PrivacyTier::Strict, 1, &id_sk, &[]).err(),
        Some(CryptoError::InvalidRecoveryPayload)
    );
    assert_eq!(
        wrap_recovery_backup(
            &secret,
            tenant_a,
            PrivacyTier::Strict,
            1,
            &id_sk,
            &[
                OrgKeyBackupEntry {
                    vault_role: VaultRole::OrgMaster,
                    key_version: 1,
                    xwing_secret: &org_sk,
                },
                OrgKeyBackupEntry {
                    vault_role: VaultRole::OrgMaster,
                    key_version: 2,
                    xwing_secret: &ful_sk,
                },
            ],
        )
        .err(),
        Some(CryptoError::InvalidRecoveryPayload)
    );

    // Multi-recipient RecoveryBackup rejected before decrypt.
    let recovery_kek = secret.derive_recovery_kek(&tenant_a)?;
    let bad_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::RecoveryBackup,
        tenant_id: tenant_a,
        resource_id: tenant_a,
        privacy_tier: PrivacyTier::Strict,
        schema_version: RECOVERY_BACKUP_SCHEMA_VERSION,
    };
    let multi_rec = encrypt(
        &[0_u8; 96],
        &bad_ctx,
        EnvelopeFlags::default(),
        &[
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::RecoveryBip39,
                key_id: tenant_a,
                key_version: 1,
                kem_data: &[],
                kek: &recovery_kek,
            },
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::RecoveryBip39,
                key_id: tenant_a,
                key_version: 2,
                kem_data: &[],
                kek: &recovery_kek,
            },
        ],
    )?;
    assert_eq!(
        unwrap_recovery_backup(&multi_rec, &secret, &tenant_a, PrivacyTier::Strict, 1).err(),
        Some(CryptoError::InvalidRecoveryPayload)
    );
    // Reusing the same X-Wing key across distinct VaultRoles rejected in wrap_recovery_backup.
    assert_eq!(
        wrap_recovery_backup(
            &secret,
            tenant_a,
            PrivacyTier::Strict,
            1,
            &id_sk,
            &[
                OrgKeyBackupEntry {
                    vault_role: VaultRole::OrgMaster,
                    key_version: 1,
                    xwing_secret: &org_sk,
                },
                OrgKeyBackupEntry {
                    vault_role: VaultRole::Fulfillment,
                    key_version: 1,
                    xwing_secret: &org_sk,
                },
            ],
        )
        .err(),
        Some(CryptoError::InvalidRecoveryPayload)
    );
    // Non-zero flags (compressed_zstd = 0x01) rejected on RCREC before HKDF/decrypt.
    let compressed_rec = encrypt(
        &[0_u8; 96],
        &bad_ctx,
        EnvelopeFlags::new(true),
        &[RecipientSpec::SymmetricKek {
            recipient_type: RecipientType::RecoveryBip39,
            key_id: tenant_a,
            key_version: 1,
            kem_data: &[],
            kek: &recovery_kek,
        }],
    )?;
    assert_eq!(
        unwrap_recovery_backup(&compressed_rec, &secret, &tenant_a, PrivacyTier::Strict, 1).err(),
        Some(CryptoError::UnsupportedFlags(0x01))
    );

    Ok(())
}

#[test]
fn shamir_gf256_subsets_commitments_wire_format_and_forged_share_defenses()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = [0x77_u8; 16];
    let other_tenant = [0x88_u8; 16];
    let secret = RecoveryMasterSecret::generate()?;

    // Parameter bounds checks.
    assert_eq!(
        split_recovery_secret(&secret, tenant_id, 1, 3).err(),
        Some(CryptoError::InvalidShamirParams)
    );
    assert_eq!(
        split_recovery_secret(&secret, tenant_id, 4, 3).err(),
        Some(CryptoError::InvalidShamirParams)
    );
    assert_eq!(
        split_recovery_secret(&secret, tenant_id, 2, MAX_SHAMIR_SHARES + 1).err(),
        Some(CryptoError::InvalidShamirParams)
    );
    let mut rng = DeterministicTestRng::from_label(b"shamir-zero-split-id");
    assert_eq!(
        split_recovery_secret_with_rng(&mut rng, &secret, tenant_id, [0_u8; 16], 2, 3).err(),
        Some(CryptoError::InvalidShamirParams)
    );

    // 3-of-5 split: EVERY C(5,3) = 10 subset MUST reconstruct exact secret, plus 4-of-5 and 5-of-5.
    let shares = split_recovery_secret(&secret, tenant_id, 3, 5)?;
    assert_eq!(shares.len(), 5);
    for (idx, share) in shares.iter().enumerate() {
        assert_eq!(usize::from(share.share_index()), idx + 1);
        share.verify_commitment(share.commitment_sha256())?;

        // Canonical 105B wire roundtrip + Debug redaction.
        let wire = share.to_bytes();
        assert_eq!(wire.len(), SHAMIR_SHARE_WIRE_LEN);
        let parsed = ShamirShare::from_bytes(wire.as_slice())?;
        assert_eq!(parsed, *share);
        let dbg_str = format!("{share:?}");
        assert!(dbg_str.contains("REDACTED"));
    }

    let mut combo_count = 0_usize;
    for i in 0..5 {
        for j in (i + 1)..5 {
            for k in (j + 1)..5 {
                let subset = [shares[i].clone(), shares[j].clone(), shares[k].clone()];
                let recovered = combine_recovery_shares(&tenant_id, &subset)?;
                assert_eq!(recovered, secret);
                combo_count += 1;
            }
        }
    }
    assert_eq!(combo_count, 10);

    // 4-of-5 and 5-of-5 (extra consistent shares) succeed.
    assert_eq!(combine_recovery_shares(&tenant_id, &shares[..4])?, secret);
    assert_eq!(combine_recovery_shares(&tenant_id, &shares)?, secret);

    // Boundary 2-of-64 max share count works.
    let max_shares = split_recovery_secret(&secret, tenant_id, 2, MAX_SHAMIR_SHARES)?;
    assert_eq!(max_shares.len(), usize::from(MAX_SHAMIR_SHARES));
    let pair = [max_shares[0].clone(), max_shares[63].clone()];
    assert_eq!(combine_recovery_shares(&tenant_id, &pair)?, secret);

    // Failure cases:
    // 1. Fewer than M shares fails.
    assert_eq!(
        combine_recovery_shares(&tenant_id, &shares[..2]).err(),
        Some(CryptoError::InvalidShamirShare)
    );
    // 2. Duplicate share index fails.
    assert_eq!(
        combine_recovery_shares(
            &tenant_id,
            &[shares[0].clone(), shares[0].clone(), shares[1].clone()]
        )
        .err(),
        Some(CryptoError::InvalidShamirShare)
    );
    // 3. Wrong tenant fails.
    assert_eq!(
        combine_recovery_shares(&other_tenant, &shares[..3]).err(),
        Some(CryptoError::InvalidShamirShare)
    );
    // 4. Mixing shares from two different splits fails.
    let other_shares = split_recovery_secret(&secret, tenant_id, 3, 5)?;
    assert_eq!(
        combine_recovery_shares(
            &tenant_id,
            &[
                shares[0].clone(),
                shares[1].clone(),
                other_shares[2].clone()
            ]
        )
        .err(),
        Some(CryptoError::InvalidShamirShare)
    );
    // 5. Tampered share_value or commitment fails from_bytes & verify_commitment.
    let mut bad_wire = shares[0].to_bytes();
    bad_wire[45] ^= 0x01;
    assert_eq!(
        ShamirShare::from_bytes(bad_wire.as_slice()).err(),
        Some(CryptoError::InvalidShamirShare)
    );
    let mut wrong_db_commit = *shares[0].commitment_sha256();
    wrong_db_commit[0] ^= 0x80;
    assert_eq!(
        shares[0].verify_commitment(&wrong_db_commit).err(),
        Some(CryptoError::InvalidShamirShare)
    );
    // 6. Forged extra share (validly self-committed under the SAME split_id, but wrong polynomial)
    //    is caught by polynomial consistency check when passed alongside M valid shares.
    let mut rng_a = DeterministicTestRng::from_label(b"shamir-poly-a");
    let mut rng_b = DeterministicTestRng::from_label(b"shamir-poly-b");
    let shared_split_id = [0xAB_u8; 16];
    let set_a =
        split_recovery_secret_with_rng(&mut rng_a, &secret, tenant_id, shared_split_id, 3, 5)?;
    let set_b =
        split_recovery_secret_with_rng(&mut rng_b, &secret, tenant_id, shared_split_id, 3, 5)?;
    assert_eq!(
        combine_recovery_shares(
            &tenant_id,
            &[
                set_a[0].clone(),
                set_a[1].clone(),
                set_a[2].clone(),
                set_b[3].clone()
            ]
        )
        .err(),
        Some(CryptoError::InvalidShamirShare)
    );

    Ok(())
}

#[derive(Deserialize)]
struct KatBundle {
    staff_grant_and_archive_v1: StaffGrantKat,
    skl_chain_v1: SklKat,
    bip39_recovery_and_shamir_v1: RecoveryShamirKat,
}

#[derive(Deserialize)]
struct StaffGrantKat {
    rng_label_wrap: String,
    rng_label_archive: String,
    tenant_id_hex: String,
    grantor_staff_id_hex: String,
    target_staff_id_hex: String,
    grantor_ed25519_seed_hex: String,
    target_staff_xwing_seed_hex: String,
    org_v1_xwing_seed_hex: String,
    org_v2_xwing_seed_hex: String,
    issued_at_unix: u64,
    expected_target_pk_hash_hex: String,
    expected_grant_wire_blake3_hex: String,
    expected_staff_wrap_blake3_hex: String,
    expected_staff_wrap_len: usize,
    expected_archive_blake3_hex: String,
    expected_archive_len: usize,
}

#[derive(Deserialize)]
struct SklKat {
    tenant_id_hex: String,
    id1_seed_hex: String,
    id2_seed_hex: String,
    org_v1_seed_hex: String,
    ful_v1_seed_hex: String,
    org_v2_seed_hex: String,
    expected_e0_hash_hex: String,
    expected_e1_hash_hex: String,
    expected_e2_hash_hex: String,
}

#[derive(Deserialize)]
struct RecoveryShamirKat {
    rng_label_backup: String,
    rng_label_shamir: String,
    tenant_id_hex: String,
    split_id_hex: String,
    recovery_entropy_hex: String,
    store_id_seed_hex: String,
    org_v1_seed_hex: String,
    ful_v1_seed_hex: String,
    expected_mnemonic: String,
    expected_recovery_kek_hex: String,
    expected_backup_blake3_hex: String,
    expected_backup_len: usize,
    expected_share_commitments_hex: Vec<String>,
    expected_share_wires_blake3_hex: Vec<String>,
}

#[test]
fn golden_kat_vectors_staff_skl_recovery_v1() -> Result<(), Box<dyn std::error::Error>> {
    let raw = include_str!("../../../vectors/staff_skl_recovery_v1.json");
    let kat: KatBundle = serde_json::from_str(raw)?;

    // 1. StaffGrantV1 + RCSKW + RCARC KAT.
    {
        let k = &kat.staff_grant_and_archive_v1;
        let tenant_id = decode_hex_array::<16>(&k.tenant_id_hex)?;
        let grantor_id = decode_hex_array::<16>(&k.grantor_staff_id_hex)?;
        let target_id = decode_hex_array::<16>(&k.target_staff_id_hex)?;
        let (grantor_sk, grantor_vk) = Ed25519SigningKey::from_seed_slice(
            &decode_hex_array::<32>(&k.grantor_ed25519_seed_hex)?,
        )?;
        let (target_sk, target_pk) = XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(
            &k.target_staff_xwing_seed_hex,
        )?)?;
        let (org_v1_sk, org_v1_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.org_v1_xwing_seed_hex)?)?;
        let (org_v2_sk, org_v2_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.org_v2_xwing_seed_hex)?)?;

        assert_eq!(
            hex::encode(hash_xwing_public_key(&target_pk)),
            k.expected_target_pk_hash_hex
        );

        let mut rng_wrap = DeterministicTestRng::from_label(k.rng_label_wrap.as_bytes());
        let (grant, wrapped) = wrap_staff_org_key_with_rng(
            &mut rng_wrap,
            tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &org_v1_sk,
            target_id,
            1,
            &target_pk,
            k.issued_at_unix,
            grantor_id,
            &grantor_sk,
        )?;
        assert_eq!(
            hex::encode(blake3::hash(&grant.to_bytes()).as_bytes()),
            k.expected_grant_wire_blake3_hex
        );
        assert_eq!(wrapped.len(), k.expected_staff_wrap_len);
        assert_eq!(
            hex::encode(blake3::hash(&wrapped).as_bytes()),
            k.expected_staff_wrap_blake3_hex
        );

        let unwrapped = unwrap_staff_org_key(
            &grant,
            &wrapped,
            &grantor_vk,
            &grantor_id,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &target_id,
            1,
            &target_sk,
            &org_v1_pk,
        )?;
        assert_eq!(unwrapped.public_key(), org_v1_pk);

        let mut rng_arch = DeterministicTestRng::from_label(k.rng_label_archive.as_bytes());
        let archived = archive_org_key_with_rng(
            &mut rng_arch,
            tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            &org_v1_sk,
            2,
            &org_v2_pk,
        )?;
        assert_eq!(archived.len(), k.expected_archive_len);
        assert_eq!(
            hex::encode(blake3::hash(&archived).as_bytes()),
            k.expected_archive_blake3_hex
        );
        let unwrapped_arch = unwrap_archived_org_key(
            &archived,
            &tenant_id,
            PrivacyTier::Strict,
            VaultRole::Fulfillment,
            1,
            2,
            &org_v2_sk,
            &org_v1_pk,
        )?;
        assert_eq!(unwrapped_arch.public_key(), org_v1_pk);
    }

    // 2. Append-only SKL + identity rotation cross-signature KAT.
    {
        let k = &kat.skl_chain_v1;
        let tenant_id = decode_hex_array::<16>(&k.tenant_id_hex)?;
        let (id1_sk, _id1_vk) =
            Ed25519SigningKey::from_seed_slice(&decode_hex_array::<32>(&k.id1_seed_hex)?)?;
        let (id2_sk, id2_vk) =
            Ed25519SigningKey::from_seed_slice(&decode_hex_array::<32>(&k.id2_seed_hex)?)?;
        let (_, org_v1_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.org_v1_seed_hex)?)?;
        let (_, ful_v1_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.ful_v1_seed_hex)?)?;
        let (_, org_v2_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.org_v2_seed_hex)?)?;

        let e0 = SklEntryV1::sign_genesis(
            tenant_id,
            VaultRole::OrgMaster,
            org_v1_pk,
            &id1_sk,
            1_795_400_000,
        )?;
        let e1 = SklEntryV1::sign_next(
            &e0,
            VaultRole::Fulfillment,
            1,
            ful_v1_pk,
            &id1_sk,
            1_795_400_010,
        )?;
        let e2 = SklEntryV1::sign_next_with_identity_rotation(
            &e1,
            VaultRole::OrgMaster,
            2,
            org_v2_pk.clone(),
            &id1_sk,
            &id2_sk,
            1_795_400_020,
        )?;

        assert_eq!(hex::encode(e0.entry_hash()), k.expected_e0_hash_hex);
        assert_eq!(hex::encode(e1.entry_hash()), k.expected_e1_hash_hex);
        assert_eq!(hex::encode(e2.entry_hash()), k.expected_e2_hash_hex);

        let verified = verify_skl_chain(&tenant_id, &[e0, e1, e2], None)?;
        assert_eq!(verified.current_identity_pk(), &id2_vk);
        assert_eq!(
            verified.active_key(VaultRole::OrgMaster),
            Some((2, &org_v2_pk))
        );
    }

    // 3. BIP-39 Recovery Kit + RCREC backup + (3, 5) GF(256) Shamir KAT.
    {
        let k = &kat.bip39_recovery_and_shamir_v1;
        let tenant_id = decode_hex_array::<16>(&k.tenant_id_hex)?;
        let split_id = decode_hex_array::<16>(&k.split_id_hex)?;
        let secret =
            RecoveryMasterSecret::from_slice(&decode_hex_array::<32>(&k.recovery_entropy_hex)?)?;
        let (store_id_sk, store_id_vk) =
            Ed25519SigningKey::from_seed_slice(&decode_hex_array::<32>(&k.store_id_seed_hex)?)?;
        let (org_v1_sk, org_v1_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.org_v1_seed_hex)?)?;
        let (ful_v1_sk, ful_v1_pk) =
            XWingSecretKey::from_seed_slice(&decode_hex_array::<32>(&k.ful_v1_seed_hex)?)?;

        assert_eq!(secret.to_mnemonic().as_str(), k.expected_mnemonic);
        assert_eq!(
            hex::encode(secret.derive_recovery_kek(&tenant_id)?.as_bytes()),
            k.expected_recovery_kek_hex
        );

        let mut rng_backup = DeterministicTestRng::from_label(k.rng_label_backup.as_bytes());
        let backup = wrap_recovery_backup_with_rng(
            &mut rng_backup,
            &secret,
            tenant_id,
            PrivacyTier::Strict,
            1,
            &store_id_sk,
            &[
                OrgKeyBackupEntry {
                    vault_role: VaultRole::OrgMaster,
                    key_version: 1,
                    xwing_secret: &org_v1_sk,
                },
                OrgKeyBackupEntry {
                    vault_role: VaultRole::Fulfillment,
                    key_version: 1,
                    xwing_secret: &ful_v1_sk,
                },
            ],
        )?;
        assert_eq!(backup.len(), k.expected_backup_len);
        assert_eq!(
            hex::encode(blake3::hash(&backup).as_bytes()),
            k.expected_backup_blake3_hex
        );

        let mut rng_shamir = DeterministicTestRng::from_label(k.rng_label_shamir.as_bytes());
        let shares =
            split_recovery_secret_with_rng(&mut rng_shamir, &secret, tenant_id, split_id, 3, 5)?;
        assert_eq!(shares.len(), 5);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(
                hex::encode(share.commitment_sha256()),
                k.expected_share_commitments_hex[i]
            );
            assert_eq!(
                hex::encode(blake3::hash(share.to_bytes().as_slice()).as_bytes()),
                k.expected_share_wires_blake3_hex[i]
            );
        }

        let reconstructed = combine_recovery_shares(
            &tenant_id,
            &[shares[1].clone(), shares[3].clone(), shares[4].clone()],
        )?;
        assert_eq!(reconstructed, secret);
        let bundle =
            unwrap_recovery_backup(&backup, &reconstructed, &tenant_id, PrivacyTier::Strict, 1)?;
        assert_eq!(bundle.store_identity_sk().verifying_key(), store_id_vk);
        assert_eq!(
            bundle
                .org_key_for_role(VaultRole::OrgMaster)
                .map(|e| e.xwing_secret().public_key()),
            Some(org_v1_pk)
        );
        assert_eq!(
            bundle
                .org_key_for_role(VaultRole::Fulfillment)
                .map(|e| e.xwing_secret().public_key()),
            Some(ful_v1_pk)
        );
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn proptest_bip39_roundtrip_normalization_and_single_word_tamper(
        raw in any::<[u8; 32]>(),
        tamper_idx in 0_usize..24,
        upper_mask in any::<u32>(),
    ) {
        let secret = RecoveryMasterSecret::from_bytes(raw);
        let mnemonic = secret.to_mnemonic();
        let parsed = RecoveryMasterSecret::from_mnemonic(&mnemonic);
        prop_assert_eq!(parsed, Ok(secret.clone()));

        // Random mixed-case + whitespace normalization preserves exact secret.
        let mut mixed = String::new();
        for (i, word) in mnemonic.split(' ').enumerate() {
            if i > 0 {
                mixed.push_str(if i % 3 == 0 { "  \t" } else { " " });
            }
            if (upper_mask >> i) & 1 == 1 {
                mixed.push_str(&word.to_ascii_uppercase());
            } else {
                mixed.push_str(word);
            }
        }
        prop_assert_eq!(RecoveryMasterSecret::from_mnemonic(&mixed), Ok(secret.clone()));

        // Replacing one word with a different valid BIP-39 word changes entropy or checksum;
        // if it changes the 256-bit entropy it can only pass if the new SHA-256 checksum collides
        // (1/256), and in that case the decoded secret MUST differ from the original secret.
        let mut words: Vec<&str> = mnemonic.split(' ').collect();
        words[tamper_idx] = if words[tamper_idx] == "abandon" { "ability" } else { "abandon" };
        let tampered = words.join(" ");
        if let Ok(decoded) = RecoveryMasterSecret::from_mnemonic(&tampered) {
            prop_assert_ne!(decoded, secret);
        }
    }

    #[test]
    fn proptest_shamir_any_subset_reconstructs_and_single_bit_wire_flip_fails(
        raw in any::<[u8; 32]>(),
        tenant_id in any::<[u8; 16]>(),
        split_id_seed in any::<[u8; 16]>(),
        threshold in 2_u8..=5,
        extra_n in 0_u8..=3,
        rng_seed in any::<[u8; 16]>(),
        flip_byte in 0_usize..SHAMIR_SHARE_WIRE_LEN,
        flip_bit in 0_u8..8,
    ) {
        let mut split_id = split_id_seed;
        if split_id == [0_u8; 16] {
            split_id[0] = 1;
        }
        let total = threshold + extra_n;
        let secret = RecoveryMasterSecret::from_bytes(raw);
        let mut rng = DeterministicTestRng::from_label(&rng_seed);
        let shares = split_recovery_secret_with_rng(&mut rng, &secret, tenant_id, split_id, threshold, total)
            .map_err(|e| TestCaseError::fail(format!("split failed: {e}")))?;

        // Reconstruct from last `threshold` shares (reversed order) after binary roundtrip.
        let mut subset = Vec::with_capacity(usize::from(threshold));
        for share in shares.iter().rev().take(usize::from(threshold)) {
            let wire = share.to_bytes();
            let parsed = ShamirShare::from_bytes(wire.as_slice())
                .map_err(|e| TestCaseError::fail(format!("wire roundtrip failed: {e}")))?;
            subset.push(parsed);
        }
        let recovered = combine_recovery_shares(&tenant_id, &subset)
            .map_err(|e| TestCaseError::fail(format!("combine failed: {e}")))?;
        prop_assert_eq!(recovered, secret);

        // Any single bit flip in a serialized RCSHR share MUST be rejected.
        let mut bad_wire = shares[0].to_bytes();
        bad_wire[flip_byte] ^= 1_u8 << flip_bit;
        prop_assert!(ShamirShare::from_bytes(bad_wire.as_slice()).is_err());
    }

    #[test]
    fn proptest_arbitrary_inputs_never_panic_s1_3_parsers(
        bytes in proptest::collection::vec(any::<u8>(), 0..2048),
        text in ".*",
    ) {
        let _ = StaffGrantV1::from_bytes(&bytes);
        let _ = SklEntryV1::from_canonical_bytes(&bytes);
        let _ = ShamirShare::from_bytes(&bytes);
        let _ = RecoveryMasterSecret::from_mnemonic(&text);
    }
}

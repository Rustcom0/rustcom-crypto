#![forbid(unsafe_code)]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use proptest::prelude::*;
use rand_core::{TryCryptoRng, TryRng};
use rustcom_crypto_core::{
    ARGON2_KEM_DATA_LEN, Argon2idKemData, Argon2idParams, CryptoError, DEFAULT_ARGON2_M_COST_KIB,
    DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
    Ed25519SigningKey, Ed25519VerifyingKey, EnvelopeContext, EnvelopeFlags, EnvelopeKind,
    MAX_ARGON2_M_COST_KIB, MAX_ARGON2_P_COST, MAX_ARGON2_T_COST, MAX_PASSWORD_LEN,
    MIN_ARGON2_M_COST_KIB, MIN_ARGON2_P_COST, MIN_ARGON2_T_COST, MIN_CHUNK_SIZE, PrivacyTier,
    RCENC_HEADER_LEN, RCSTR_FIXED_HEADER_LEN, RecipientCredential, RecipientSpec, RecipientType,
    STRICT_ACCOUNT_ID_BYTES_LEN, STRICT_ACCOUNT_ID_FORMATTED_LEN, STRICT_ACCOUNT_ID_MAX_INPUT_LEN,
    STRICT_ACCOUNT_ID_TOTAL_CHARS, StrictAccountId, SymmetricKey, VIP_FRAGMENT_CHK_CONTEXT,
    VIP_FRAGMENT_MAX_INPUT_LEN, VIP_FRAGMENT_TOKEN_LEN, VIP_GROUP_KEY_WRAP_SCHEMA_VERSION,
    VIP_KEY_WRAP_MAGIC, VIP_KEY_WRAP_PAYLOAD_LEN, VipInviteFragment, XWingSecretKey,
    compute_strict_lookup_index, decrypt, decrypt_private_product_password,
    decrypt_private_product_password_version, decrypt_private_product_vip,
    decrypt_private_product_vip_fragment, decrypt_stream, derive_password_kek, encrypt,
    encrypt_private_product_password, encrypt_private_product_password_with_rng,
    encrypt_private_product_vip, encrypt_private_product_vip_with_rng, encrypt_stream,
    extract_password_slot, unwrap_vip_group_key, wrap_vip_group_key, wrap_vip_group_key_with_rng,
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

const CROCKFORD_CHARS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Known small-order / weak Ed25519 public keys (orders 1, 2, 4, 8).
const WEAK_ED25519_KEYS: [[u8; 32]; 5] = [
    // Order 1 (identity point)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // Order 2
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Order 4
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // Order 8
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // Order 8 (sign bit flipped)
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
];

fn product_ctx(tenant_id: [u8; 16], product_id: [u8; 16], tier: PrivacyTier) -> EnvelopeContext {
    EnvelopeContext {
        envelope_kind: EnvelopeKind::PrivateProduct,
        tenant_id,
        resource_id: product_id,
        privacy_tier: tier,
        schema_version: 1,
    }
}

fn fast_valid_argon2_params() -> Result<Argon2idParams, CryptoError> {
    Argon2idParams::new(MIN_ARGON2_M_COST_KIB, MIN_ARGON2_T_COST, MIN_ARGON2_P_COST)
}

#[test]
fn ed25519_strict_verification_weak_key_rejection_and_redaction()
-> Result<(), Box<dyn std::error::Error>> {
    let (sk, vk) = Ed25519SigningKey::generate()?;
    let vk_bytes = vk.to_bytes();
    assert_eq!(vk_bytes.len(), ED25519_PUBLIC_KEY_LEN);

    let parsed_vk = Ed25519VerifyingKey::from_bytes(&vk_bytes)?;
    assert_eq!(parsed_vk, vk);
    assert_eq!(parsed_vk.key_id(), vk.key_id());

    let seed = sk.to_seed_bytes();
    let (sk_rebuilt, vk_rebuilt) = Ed25519SigningKey::from_seed_slice(seed.as_slice())?;
    assert_eq!(vk_rebuilt, vk);
    assert_eq!(sk_rebuilt.verifying_key(), vk);

    let msg = b"rustcom-v1-ed25519-strict-test";
    let sig = sk_rebuilt.sign(msg);
    assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
    vk.verify_strict(msg, &sig)?;

    // Wrong message and flipped signature bit fail strictly.
    assert_eq!(
        vk.verify_strict(b"wrong-message", &sig),
        Err(CryptoError::InvalidSignature)
    );
    let mut bad_sig = sig;
    bad_sig[63] ^= 0x01;
    assert_eq!(
        vk.verify_strict(msg, &bad_sig),
        Err(CryptoError::InvalidSignature)
    );
    assert_eq!(
        vk.verify_strict(msg, &sig[..63]),
        Err(CryptoError::InvalidSignature)
    );

    // Weak / small-order Ed25519 public keys MUST be rejected.
    for weak in WEAK_ED25519_KEYS {
        assert_eq!(
            Ed25519VerifyingKey::from_bytes(&weak),
            Err(CryptoError::InvalidPublicKey)
        );
    }
    // Non-canonical y >= 2^255 - 19 public keys (all 19 values x both sign bits) MUST be rejected.
    for low_byte in 0xED_u8..=0xFF {
        for top_byte in [0x7F_u8, 0xFF_u8] {
            let mut non_canonical = [0xFF_u8; 32];
            non_canonical[0] = low_byte;
            non_canonical[31] = top_byte;
            assert_eq!(
                Ed25519VerifyingKey::from_bytes(&non_canonical),
                Err(CryptoError::InvalidPublicKey)
            );
        }
    }
    assert_eq!(
        Ed25519VerifyingKey::from_bytes(&vk_bytes[..16]),
        Err(CryptoError::InvalidPublicKey)
    );
    assert_eq!(
        Ed25519SigningKey::from_seed_slice(&[0_u8; 16]).err(),
        Some(CryptoError::InvalidSecretKey)
    );

    // Signature malleability (S' = S + L >= L) and small-order R point rejected by verify_strict.
    let ed_order_l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut malleable_sig = sig;
    let mut carry = 0_u16;
    for (dst, &l_byte) in malleable_sig[32..64].iter_mut().zip(ed_order_l.iter()) {
        let sum = u16::from(*dst) + u16::from(l_byte) + carry;
        *dst = u8::try_from(sum & 0xFF)?;
        carry = sum >> 8;
    }
    assert_eq!(
        vk.verify_strict(msg, &malleable_sig),
        Err(CryptoError::InvalidSignature)
    );
    for weak_r in WEAK_ED25519_KEYS {
        let mut weak_r_sig = sig;
        weak_r_sig[0..32].copy_from_slice(&weak_r);
        assert_eq!(
            vk.verify_strict(msg, &weak_r_sig),
            Err(CryptoError::InvalidSignature)
        );
    }

    // Official RFC 8032 §7.1 Test Vectors 1 & 2.
    let rfc_seed_1: [u8; 32] =
        decode_fixed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?;
    let (rfc_sk_1, rfc_vk_1) = Ed25519SigningKey::from_seed_bytes(rfc_seed_1);
    assert_eq!(
        hex::encode(rfc_vk_1.to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let rfc_sig_1 = rfc_sk_1.sign(b"");
    assert_eq!(
        hex::encode(rfc_sig_1),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    rfc_vk_1.verify_strict(b"", &rfc_sig_1)?;

    let rfc_seed_2: [u8; 32] =
        decode_fixed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")?;
    let (rfc_sk_2, rfc_vk_2) = Ed25519SigningKey::from_seed_bytes(rfc_seed_2);
    assert_eq!(
        hex::encode(rfc_vk_2.to_bytes()),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let rfc_sig_2 = rfc_sk_2.sign(&[0x72]);
    assert_eq!(
        hex::encode(rfc_sig_2),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    rfc_vk_2.verify_strict(&[0x72], &rfc_sig_2)?;

    // Debug redaction.
    assert_eq!(format!("{sk:?}"), "Ed25519SigningKey([REDACTED])");
    Ok(())
}

#[test]
fn strict_account_id_crockford_normalization_checksum_and_canonical_pad_bits()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary_inputs = [
        [0x00; STRICT_ACCOUNT_ID_BYTES_LEN],
        [0xFF; STRICT_ACCOUNT_ID_BYTES_LEN],
        [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ],
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ],
    ];

    for raw in boundary_inputs {
        let id = StrictAccountId::from_bytes(raw);
        let formatted = id.to_formatted_string();
        let compact = id.to_compact_string();

        assert_eq!(formatted.len(), STRICT_ACCOUNT_ID_FORMATTED_LEN);
        assert_eq!(compact.len(), STRICT_ACCOUNT_ID_TOTAL_CHARS);

        // Hyphens at exact 4-char intervals (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX).
        for (i, ch) in formatted.bytes().enumerate() {
            if i % 5 == 4 {
                assert_eq!(ch, b'-');
            } else {
                assert!(CROCKFORD_CHARS.contains(&ch));
                assert!(!matches!(ch, b'I' | b'L' | b'O' | b'U'));
            }
        }

        // Top 2 pad bits must be 00, so first symbol is strictly in '0'..='7'.
        let first_char = compact.as_bytes()[0];
        assert!((b'0'..=b'7').contains(&first_char));

        // Roundtrip formatted & compact.
        assert_eq!(StrictAccountId::parse(&formatted)?, id);
        assert_eq!(StrictAccountId::parse(&compact)?, id);
    }

    // Forgiving normalization: lowercase, i/I/l/L -> 1, o/O -> 0, arbitrary whitespace/hyphens.
    let id = StrictAccountId::from_bytes([
        0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    let formatted = id.to_formatted_string();
    let noisy: String = format!(
        "  \t {} \r\n ",
        formatted
            .to_lowercase()
            .replace('0', "o")
            .replace('1', "l")
            .replace('-', " - ")
    );
    assert_eq!(StrictAccountId::parse(&noisy)?, id);
    let aliased_upper = formatted.replace('0', "O").replace('1', "I");
    assert_eq!(StrictAccountId::parse(&aliased_upper)?, id);

    // Every single-character mutation across all 28 positions fails checksum or pad-bit check.
    let compact = id.to_compact_string();
    for pos in 0..STRICT_ACCOUNT_ID_TOTAL_CHARS {
        let mut bytes = compact.as_bytes().to_vec();
        let orig = bytes[pos];
        // Pick a different valid symbol keeping symbol[0] in '0'..='7' so we test checksum detection.
        let replacement = if pos == 0 {
            if orig == b'0' { b'1' } else { b'0' }
        } else if orig == b'Z' {
            b'Y'
        } else {
            b'Z'
        };
        bytes[pos] = replacement;
        let mutated = String::from_utf8(bytes)?;
        assert_eq!(
            StrictAccountId::parse(&mutated),
            Err(CryptoError::InvalidAccountIdChecksum),
            "mutation at pos={pos} was not detected"
        );
    }

    // Non-canonical top 2 pad bits (symbol 0 in '8'..'Z') MUST fail with InvalidAccountIdFormat.
    for bad_first in *b"89AGZ" {
        let mut bytes = compact.as_bytes().to_vec();
        bytes[0] = bad_first;
        let bad = String::from_utf8(bytes)?;
        assert_eq!(
            StrictAccountId::parse(&bad),
            Err(CryptoError::InvalidAccountIdFormat)
        );
    }

    // Excluded letter 'U' / 'u', bad lengths, punctuation, and >128B input rejected.
    let mut with_u = compact.as_bytes().to_vec();
    with_u[5] = b'U';
    assert_eq!(
        StrictAccountId::parse(&String::from_utf8(with_u)?),
        Err(CryptoError::InvalidAccountIdFormat)
    );
    let mut with_lower_u = compact.as_bytes().to_vec();
    with_lower_u[5] = b'u';
    assert_eq!(
        StrictAccountId::parse(&String::from_utf8(with_lower_u)?),
        Err(CryptoError::InvalidAccountIdFormat)
    );
    assert_eq!(
        StrictAccountId::parse(&compact[..27]),
        Err(CryptoError::InvalidAccountIdFormat)
    );
    assert_eq!(
        StrictAccountId::parse(&format!("{}0", compact.as_str())),
        Err(CryptoError::InvalidAccountIdFormat)
    );
    assert_eq!(
        StrictAccountId::parse(&" ".repeat(STRICT_ACCOUNT_ID_MAX_INPUT_LEN + 1)),
        Err(CryptoError::InvalidAccountIdFormat)
    );
    assert_eq!(
        StrictAccountId::parse(&format!("{}!", &compact[..27])),
        Err(CryptoError::InvalidAccountIdFormat)
    );

    // CSPRNG generation + Debug redaction.
    let generated = StrictAccountId::generate()?;
    assert_eq!(
        StrictAccountId::parse(&generated.to_formatted_string())?,
        generated
    );
    assert_eq!(format!("{generated:?}"), "StrictAccountId([REDACTED])");
    Ok(())
}

#[test]
fn strict_account_id_three_hkdf_keys_tenant_isolation_and_vault_roundtrip()
-> Result<(), Box<dyn std::error::Error>> {
    let account = StrictAccountId::generate()?;
    let tenant_a = [0x11_u8; 16];
    let tenant_b = [0x22_u8; 16];
    let pepper_1 = SymmetricKey::from_bytes([0xAA; 32]);
    let pepper_2 = SymmetricKey::from_bytes([0xBB; 32]);

    let keys_a = account.derive_keys(&tenant_a)?;
    let keys_b = account.derive_keys(&tenant_b)?;

    // All 3 domain-separated keys are distinct and tenant-isolated.
    assert_ne!(keys_a.auth_lookup_id(), keys_b.auth_lookup_id());
    assert_ne!(keys_a.auth_secret(), keys_b.auth_secret());
    assert_ne!(keys_a.customer_vault_seed(), keys_b.customer_vault_seed());
    assert_ne!(keys_a.auth_secret(), keys_a.customer_vault_seed());
    assert_ne!(
        keys_a.auth_lookup_id(),
        &keys_a.auth_secret().as_bytes()[..16]
    );

    // Server lookup index changes with pepper, tenant, and lookup_id.
    let idx_a_p1 = compute_strict_lookup_index(&pepper_1, &tenant_a, keys_a.auth_lookup_id());
    let idx_a_p2 = compute_strict_lookup_index(&pepper_2, &tenant_a, keys_a.auth_lookup_id());
    let idx_b_p1 = compute_strict_lookup_index(&pepper_1, &tenant_b, keys_b.auth_lookup_id());
    assert_ne!(idx_a_p1, idx_a_p2);
    assert_ne!(idx_a_p1, idx_b_p1);

    // Deterministic vault keypairs per tenant; distinct across tenants.
    let vault_a = keys_a.derive_vault()?;
    let vault_a_again = account.derive_vault(&tenant_a)?;
    let vault_b = keys_b.derive_vault()?;
    assert_eq!(vault_a.xwing_public(), vault_a_again.xwing_public());
    assert_eq!(
        vault_a.ed25519_verifying(),
        vault_a_again.ed25519_verifying()
    );
    assert_ne!(vault_a.xwing_public(), vault_b.xwing_public());
    assert_ne!(vault_a.ed25519_verifying(), vault_b.ed25519_verifying());

    // Debug redaction on keys and vault.
    let keys_dbg = format!("{keys_a:?}");
    assert!(keys_dbg.contains("[REDACTED]"));
    assert!(!keys_dbg.contains(&hex::encode(keys_a.auth_lookup_id())));
    let vault_dbg = format!("{vault_a:?}");
    assert!(vault_dbg.contains("XWingSecretKey([REDACTED])"));
    assert!(vault_dbg.contains("Ed25519SigningKey([REDACTED])"));

    // End-to-end Strict dual-wrapped order + buyer Ed25519 portal signature.
    let (org_sk, org_pk) = XWingSecretKey::generate()?;
    let order_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::OrderFulfillment,
        tenant_id: tenant_a,
        resource_id: [0x99; 16],
        privacy_tier: PrivacyTier::Strict,
        schema_version: 1,
    };
    let order_pii = br#"{"recipient":"Strict Buyer","parcel_locker":"DHL-10115"}"#;
    let envelope = encrypt(
        order_pii,
        &order_ctx,
        EnvelopeFlags::default(),
        &[
            RecipientSpec::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: org_pk.key_id(),
                key_version: 1,
                public_key: &org_pk,
            },
            vault_a.recipient_spec(1),
        ],
    )?;

    let dec_buyer = decrypt(&envelope, &order_ctx, &vault_a.recipient_credential(1))?;
    assert_eq!(dec_buyer.plaintext.as_slice(), order_pii);
    let dec_org = decrypt(
        &envelope,
        &order_ctx,
        &RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_pk.key_id(),
            key_version: 1,
            secret_key: &org_sk,
        },
    )?;
    assert_eq!(dec_org.plaintext.as_slice(), order_pii);
    assert!(decrypt(&envelope, &order_ctx, &vault_b.recipient_credential(1)).is_err());

    let portal_msg = b"Where is my shipment?";
    let sig = vault_a.ed25519_signing().sign(portal_msg);
    vault_a
        .ed25519_verifying()
        .verify_strict(portal_msg, &sig)?;
    assert!(
        vault_b
            .ed25519_verifying()
            .verify_strict(portal_msg, &sig)
            .is_err()
    );
    Ok(())
}

#[test]
fn private_product_password_mode_bounds_roundtrip_and_asset_reuse()
-> Result<(), Box<dyn std::error::Error>> {
    let (org_sk, org_pk) = XWingSecretKey::generate()?;
    let tenant_id = [0x31_u8; 16];
    let product_id = [0x42_u8; 16];
    let ctx = product_ctx(tenant_id, product_id, PrivacyTier::Strict);
    let metadata = br#"{"title":"Secret Collector Vinyl","sku":"PRIV-001"}"#;
    let password = b"aurora-quartz-99!";

    // 1. Full protocol default (m=65536 KiB, t=3, p=1) roundtrip with StoreOrgKey + password.
    let org_spec = RecipientSpec::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: org_pk.key_id(),
        key_version: 2,
        public_key: &org_pk,
    };
    let wire = encrypt_private_product_password(
        metadata,
        &ctx,
        EnvelopeFlags::default(),
        password,
        1,
        Argon2idParams::DEFAULT,
        &[org_spec],
    )?;

    // Buyer decrypts with password; merchant decrypts with StoreOrgKey.
    let buyer_dec = decrypt_private_product_password(&wire, &ctx, password)?;
    assert_eq!(buyer_dec.plaintext.as_slice(), metadata);

    let merchant_dec = decrypt(
        &wire,
        &ctx,
        &RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_pk.key_id(),
            key_version: 2,
            secret_key: &org_sk,
        },
    )?;
    assert_eq!(merchant_dec.plaintext.as_slice(), metadata);

    // Wrong password fails AEAD unwrap.
    assert!(matches!(
        decrypt_private_product_password(&wire, &ctx, b"wrong-password"),
        Err(CryptoError::DecryptionFailed)
    ));

    // 2. Single Argon2id derivation reused for metadata + RCSTR encrypted private product image.
    let (pw_ver, kem_data) = extract_password_slot(&wire, &product_id)?;
    assert_eq!(pw_ver, 1);
    assert_eq!(kem_data.params().m_cost_kib(), DEFAULT_ARGON2_M_COST_KIB);
    assert_eq!(kem_data.params().t_cost(), DEFAULT_ARGON2_T_COST);
    assert_eq!(kem_data.params().p_cost(), DEFAULT_ARGON2_P_COST);

    let derived_kek = derive_password_kek(password, &kem_data)?;
    let kem_wire = kem_data.to_bytes();
    let image_ctx = product_ctx(tenant_id, [0x77; 16], PrivacyTier::Strict);
    let fake_image = vec![0xD5_u8; MIN_CHUNK_SIZE as usize + 512];
    let image_stream = encrypt_stream(
        &fake_image,
        &image_ctx,
        MIN_CHUNK_SIZE,
        &[
            org_spec,
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: product_id,
                key_version: pw_ver,
                kem_data: &kem_wire,
                kek: &derived_kek,
            },
        ],
    )?;
    let dec_image = decrypt_stream(
        &image_stream,
        &image_ctx,
        &RecipientCredential::SymmetricKek {
            recipient_type: RecipientType::Argon2idPassword,
            key_id: product_id,
            key_version: pw_ver,
            kek: &derived_kek,
        },
    )?;
    assert_eq!(dec_image.as_slice(), fake_image.as_slice());

    // 3. Password validation & Argon2id DoS / downgrade bounds enforcement.
    let fast_params = fast_valid_argon2_params()?;
    assert_eq!(
        encrypt_private_product_password(
            metadata,
            &ctx,
            EnvelopeFlags::default(),
            b"",
            1,
            fast_params,
            &[],
        ),
        Err(CryptoError::InvalidPassword)
    );
    assert_eq!(
        encrypt_private_product_password(
            metadata,
            &ctx,
            EnvelopeFlags::default(),
            &vec![b'a'; MAX_PASSWORD_LEN + 1],
            1,
            fast_params,
            &[],
        ),
        Err(CryptoError::InvalidPassword)
    );
    assert!(matches!(
        decrypt_private_product_password(&wire, &ctx, b""),
        Err(CryptoError::InvalidPassword)
    ));

    assert_eq!(
        Argon2idParams::new(MIN_ARGON2_M_COST_KIB - 1, 3, 1),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idParams::new(MAX_ARGON2_M_COST_KIB + 1, 3, 1),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idParams::new(65_536, MIN_ARGON2_T_COST - 1, 1),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idParams::new(65_536, MAX_ARGON2_T_COST + 1, 1),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idParams::new(65_536, 3, MIN_ARGON2_P_COST - 1),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idParams::new(65_536, 3, MAX_ARGON2_P_COST + 1),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idKemData::new([0_u8; 32], fast_params),
        Err(CryptoError::InvalidArgon2Params)
    );
    assert_eq!(
        Argon2idKemData::from_bytes(&[1_u8; ARGON2_KEM_DATA_LEN - 1]),
        Err(CryptoError::InvalidKemDataLength {
            expected: ARGON2_KEM_DATA_LEN,
            actual: ARGON2_KEM_DATA_LEN - 1,
        })
    );

    // 4. Wire-tampered DoS/downgrade Argon2id params & zero versions rejected BEFORE running Argon2id.
    assert_eq!(
        encrypt_private_product_password(
            metadata,
            &ctx,
            EnvelopeFlags::default(),
            password,
            0,
            fast_params,
            &[],
        ),
        Err(CryptoError::InvalidKeyVersion(0))
    );
    let fast_wire = encrypt_private_product_password(
        metadata,
        &ctx,
        EnvelopeFlags::default(),
        password,
        1,
        fast_params,
        &[],
    )?;
    assert!(matches!(
        rustcom_crypto_core::decrypt_private_product_password_version(
            &fast_wire, &ctx, 0, password,
        ),
        Err(CryptoError::InvalidKeyVersion(0))
    ));
    let mut zero_ver_wire = fast_wire.clone();
    // key_version sits at header(10) + type(1) + key_id(16) = 27..31.
    zero_ver_wire[RCENC_HEADER_LEN + 17..RCENC_HEADER_LEN + 21]
        .copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        extract_password_slot(&zero_ver_wire, &product_id),
        Err(CryptoError::InvalidKeyVersion(0))
    );
    assert!(matches!(
        decrypt_private_product_password(&zero_ver_wire, &ctx, password),
        Err(CryptoError::InvalidKeyVersion(0))
    ));
    // Client-side WASM Argon2id budget rejects 128 MiB / t=8 envelopes BEFORE running Argon2id.
    let mut heavy_wire = fast_wire.clone();
    let kem_offset = RCENC_HEADER_LEN + 1 + 16 + 4 + 2;
    heavy_wire[kem_offset + 32..kem_offset + 36]
        .copy_from_slice(&MAX_ARGON2_M_COST_KIB.to_be_bytes());
    heavy_wire[kem_offset + 36..kem_offset + 40].copy_from_slice(&MAX_ARGON2_T_COST.to_be_bytes());
    assert!(matches!(
        rustcom_crypto_core::decrypt_private_product_password_with_budget(
            &heavy_wire,
            &ctx,
            password,
            rustcom_crypto_core::Argon2idBudget::WASM_CLIENT,
        ),
        Err(CryptoError::InvalidArgon2Params)
    ));
    // Offset of kem_data inside slot 0: header(10) + type(1) + key_id(16) + ver(4) + len(2) = 33.
    let mut oom_dos_wire = fast_wire.clone();
    oom_dos_wire[kem_offset + 32..kem_offset + 36].copy_from_slice(&(512_u32 * 1024).to_be_bytes());
    assert!(matches!(
        decrypt_private_product_password(&oom_dos_wire, &ctx, password),
        Err(CryptoError::InvalidArgon2Params)
    ));
    assert_eq!(
        extract_password_slot(&oom_dos_wire, &product_id),
        Err(CryptoError::InvalidArgon2Params)
    );

    let mut downgrade_wire = fast_wire.clone();
    downgrade_wire[kem_offset + 32..kem_offset + 36].copy_from_slice(&8_u32.to_be_bytes());
    assert!(matches!(
        decrypt_private_product_password(&downgrade_wire, &ctx, password),
        Err(CryptoError::InvalidArgon2Params)
    ));

    // Tampered t_cost (<2, >8), p_cost (0, >4), and all-zero salt rejected BEFORE Argon2id.
    for bad_t in [1_u32, 9_u32] {
        let mut tampered_t = fast_wire.clone();
        tampered_t[kem_offset + 36..kem_offset + 40].copy_from_slice(&bad_t.to_be_bytes());
        assert!(matches!(
            decrypt_private_product_password(&tampered_t, &ctx, password),
            Err(CryptoError::InvalidArgon2Params)
        ));
    }
    for bad_p in [0_u32, 5_u32] {
        let mut tampered_p = fast_wire.clone();
        tampered_p[kem_offset + 40..kem_offset + 44].copy_from_slice(&bad_p.to_be_bytes());
        assert!(matches!(
            decrypt_private_product_password(&tampered_p, &ctx, password),
            Err(CryptoError::InvalidArgon2Params)
        ));
    }
    let mut zero_salt_wire = fast_wire.clone();
    zero_salt_wire[kem_offset..kem_offset + 32].fill(0_u8);
    assert!(matches!(
        decrypt_private_product_password(&zero_salt_wire, &ctx, password),
        Err(CryptoError::InvalidArgon2Params)
    ));

    // Cross-tenant, cross-product, and wrong-tier canonical_aad replay rejected.
    let mut wrong_tenant_ctx = ctx;
    wrong_tenant_ctx.tenant_id[0] ^= 0xFF;
    assert!(matches!(
        decrypt_private_product_password(&fast_wire, &wrong_tenant_ctx, password),
        Err(CryptoError::DecryptionFailed)
    ));
    let mut wrong_product_ctx = ctx;
    wrong_product_ctx.resource_id[0] ^= 0xFF;
    assert!(matches!(
        decrypt_private_product_password(&fast_wire, &wrong_product_ctx, password),
        Err(CryptoError::RecipientNotFound)
    ));
    let mut wrong_tier_ctx = ctx;
    wrong_tier_ctx.privacy_tier = PrivacyTier::Flexible;
    assert!(matches!(
        decrypt_private_product_password(&fast_wire, &wrong_tier_ctx, password),
        Err(CryptoError::DecryptionFailed)
    ));

    // RCSTR internal header (flags = 0x02) rejected by extract_password_slot & password decryptors.
    let rcstr_inner = &image_stream
        [RCSTR_FIXED_HEADER_LEN..image_stream.len() - (MIN_CHUNK_SIZE as usize + 16) - (512 + 16)];
    assert_eq!(
        extract_password_slot(rcstr_inner, &product_id),
        Err(CryptoError::UnsupportedFlags(0x02))
    );
    assert!(matches!(
        decrypt_private_product_password(rcstr_inner, &ctx, password),
        Err(CryptoError::UnsupportedFlags(0x02))
    ));
    assert!(matches!(
        decrypt_private_product_password_version(rcstr_inner, &ctx, 1, password),
        Err(CryptoError::UnsupportedFlags(0x02))
    ));

    // Pre-KDF recipient validation rejects duplicate password slot immediately (even with 64 MiB).
    assert_eq!(
        encrypt_private_product_password(
            metadata,
            &ctx,
            EnvelopeFlags::default(),
            password,
            1,
            Argon2idParams::DEFAULT,
            &[RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: product_id,
                key_version: 1,
                kem_data: &kem_wire,
                kek: &derived_kek,
            }],
        ),
        Err(CryptoError::DuplicateRecipientSlot)
    );

    // 5. Ambiguous dual password slots rejected by versionless decrypt, handled by versioned decrypt.
    let kem_v1 = Argon2idKemData::new([0x11; 32], fast_params)?;
    let kem_v2 = Argon2idKemData::new([0x22; 32], fast_params)?;
    let kek_v1 = derive_password_kek(b"old-pw", &kem_v1)?;
    let kek_v2 = derive_password_kek(b"new-pw", &kem_v2)?;
    let k1_bytes = kem_v1.to_bytes();
    let k2_bytes = kem_v2.to_bytes();
    let dual_pw_wire = encrypt(
        metadata,
        &ctx,
        EnvelopeFlags::default(),
        &[
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: product_id,
                key_version: 1,
                kem_data: &k1_bytes,
                kek: &kek_v1,
            },
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: product_id,
                key_version: 2,
                kem_data: &k2_bytes,
                kek: &kek_v2,
            },
        ],
    )?;
    assert!(matches!(
        decrypt_private_product_password(&dual_pw_wire, &ctx, b"new-pw"),
        Err(CryptoError::AmbiguousRecipientSlot)
    ));
    assert_eq!(
        extract_password_slot(&dual_pw_wire, &product_id),
        Err(CryptoError::AmbiguousRecipientSlot)
    );
    assert_eq!(
        decrypt_private_product_password_version(&dual_pw_wire, &ctx, 1, b"old-pw")?
            .plaintext
            .as_slice(),
        metadata
    );
    assert_eq!(
        decrypt_private_product_password_version(&dual_pw_wire, &ctx, 2, b"new-pw")?
            .plaintext
            .as_slice(),
        metadata
    );

    // 6. Wrong envelope kind and reserved VIP key wrap schema version rejected.
    let mut bad_kind_ctx = ctx;
    bad_kind_ctx.envelope_kind = EnvelopeKind::OrderFulfillment;
    assert_eq!(
        encrypt_private_product_password(
            metadata,
            &bad_kind_ctx,
            EnvelopeFlags::default(),
            password,
            1,
            fast_params,
            &[],
        ),
        Err(CryptoError::InvalidEnvelopeKind(0x01))
    );
    let mut reserved_ctx = ctx;
    reserved_ctx.schema_version = VIP_GROUP_KEY_WRAP_SCHEMA_VERSION;
    assert_eq!(
        encrypt_private_product_password(
            metadata,
            &reserved_ctx,
            EnvelopeFlags::default(),
            password,
            1,
            fast_params,
            &[],
        ),
        Err(CryptoError::ReservedSchemaVersion(
            VIP_GROUP_KEY_WRAP_SCHEMA_VERSION
        ))
    );

    Ok(())
}

#[test]
fn private_product_vip_group_wrapping_url_fragment_and_domain_separation()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = [0x51_u8; 16];
    let vip_group_id = [0x62_u8; 16];
    let product_id = [0x73_u8; 16];
    let group_key_version = 4_u32;

    let (org_sk, org_pk) = XWingSecretKey::generate()?;
    let (vip_sk, vip_pk) = XWingSecretKey::generate()?;
    let buyer_account = StrictAccountId::generate()?;
    let buyer_vault = buyer_account.derive_vault(&tenant_id)?;

    let org_spec = RecipientSpec::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: org_pk.key_id(),
        key_version: 1,
        public_key: &org_pk,
    };

    // 1. Wrap VIP group key to both StoreOrgKey and Strict Customer Vault.
    let wrapped_group = wrap_vip_group_key(
        tenant_id,
        vip_group_id,
        group_key_version,
        PrivacyTier::Strict,
        &vip_sk,
        &[org_spec, buyer_vault.recipient_spec(1)],
    )?;

    let (unwrapped_vip_sk, unwrapped_vip_pk) = unwrap_vip_group_key(
        &wrapped_group,
        tenant_id,
        vip_group_id,
        group_key_version,
        PrivacyTier::Strict,
        &buyer_vault.recipient_credential(1),
    )?;
    assert_eq!(unwrapped_vip_pk, vip_pk);

    // 2. Encrypt VIP Private Product metadata + RCSTR private asset.
    let ctx = product_ctx(tenant_id, product_id, PrivacyTier::Strict);
    let metadata = br#"{"title":"VIP Invite-Only Sneakers","sizes":["42","43"]}"#;
    let prod_wire = encrypt_private_product_vip(
        metadata,
        &ctx,
        EnvelopeFlags::default(),
        vip_group_id,
        group_key_version,
        &vip_pk,
        &[org_spec],
    )?;

    // Member unwraps & decrypts; merchant also decrypts via StoreOrgKey.
    let dec_member = decrypt_private_product_vip(
        &prod_wire,
        &ctx,
        vip_group_id,
        group_key_version,
        &unwrapped_vip_sk,
    )?;
    assert_eq!(dec_member.plaintext.as_slice(), metadata);
    let dec_org = decrypt(
        &prod_wire,
        &ctx,
        &RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_pk.key_id(),
            key_version: 1,
            secret_key: &org_sk,
        },
    )?;
    assert_eq!(dec_org.plaintext.as_slice(), metadata);

    // Zero key versions rejected for VIP wrap/unwrap/encrypt/decrypt and `#k=` fragments.
    assert_eq!(
        VipInviteFragment::from_secret_key(0, &vip_sk),
        Err(CryptoError::InvalidKeyVersion(0))
    );
    assert_eq!(
        wrap_vip_group_key(
            tenant_id,
            vip_group_id,
            0,
            PrivacyTier::Strict,
            &vip_sk,
            &[buyer_vault.recipient_spec(1)],
        ),
        Err(CryptoError::InvalidKeyVersion(0))
    );
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            tenant_id,
            vip_group_id,
            0,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::InvalidKeyVersion(0))
    ));
    assert_eq!(
        encrypt_private_product_vip(
            metadata,
            &ctx,
            EnvelopeFlags::default(),
            vip_group_id,
            0,
            &vip_pk,
            &[],
        ),
        Err(CryptoError::InvalidKeyVersion(0))
    );
    assert!(matches!(
        rustcom_crypto_core::decrypt_private_product_vip(
            &prod_wire,
            &ctx,
            vip_group_id,
            0,
            &vip_sk,
        ),
        Err(CryptoError::InvalidKeyVersion(0))
    ));

    // 3. URL hash fragment `#k=...` invite link roundtrip & decryption.
    let frag = VipInviteFragment::from_secret_key(group_key_version, &vip_sk)?;
    let token = frag.to_token();
    let url_frag = frag.to_url_fragment();
    assert_eq!(token.len(), VIP_FRAGMENT_TOKEN_LEN);
    assert_eq!(url_frag.len(), 3 + VIP_FRAGMENT_TOKEN_LEN);
    assert!(url_frag.starts_with("#k="));
    assert!(!token.contains('='));
    assert!(!token.contains('+'));
    assert!(!token.contains('/'));

    let parsed_1 = VipInviteFragment::parse_url_fragment(&url_frag)?;
    let parsed_2 = VipInviteFragment::parse_url_fragment(&format!("k={}", token.as_str()))?;
    let parsed_3 = VipInviteFragment::parse_url_fragment(&format!(
        " #view=grid&k={}&lang=en ",
        token.as_str()
    ))?;
    assert_eq!(parsed_1, frag);
    assert_eq!(parsed_2, frag);
    assert_eq!(parsed_3, frag);

    let dec_frag = decrypt_private_product_vip_fragment(&prod_wire, &ctx, vip_group_id, &parsed_1)?;
    assert_eq!(dec_frag.plaintext.as_slice(), metadata);

    // Debug redaction on VipInviteFragment.
    let frag_dbg = format!("{frag:?}");
    assert!(frag_dbg.contains("[REDACTED]"));
    assert!(!frag_dbg.contains(&*token));

    // Negative tests on VipInviteFragment: every single-char mutation fails checksum.
    for pos in 0..VIP_FRAGMENT_TOKEN_LEN {
        let mut bytes = token.as_bytes().to_vec();
        bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };
        let mutated = String::from_utf8(bytes)?;
        assert_eq!(
            VipInviteFragment::parse_token(&mutated),
            Err(CryptoError::InvalidInviteFragment),
            "VIP fragment tamper at pos={pos} was not detected"
        );
    }
    // Duplicate k=, missing k=, bad length, padded/non-url-safe base64, query strings/URLs,
    // wrong fragment version with valid recomputed checksum, and oversized input rejected.
    assert_eq!(
        VipInviteFragment::parse_url_fragment(&format!(
            "#k={}&k={}",
            token.as_str(),
            token.as_str()
        )),
        Err(CryptoError::InvalidInviteFragment)
    );
    assert_eq!(
        VipInviteFragment::parse_url_fragment("#tab=details"),
        Err(CryptoError::InvalidInviteFragment)
    );
    assert_eq!(
        VipInviteFragment::parse_token(&token[..51]),
        Err(CryptoError::InvalidInviteFragment)
    );
    for bad_b64_char in ['+', '/', '='] {
        let mut bad_b64 = token.as_bytes().to_vec();
        bad_b64[10] = u8::try_from(bad_b64_char)?;
        assert_eq!(
            VipInviteFragment::parse_token(&String::from_utf8(bad_b64)?),
            Err(CryptoError::InvalidInviteFragment)
        );
    }
    for non_fragment in [
        format!("?utm_source=mail&k={}", token.as_str()),
        format!("https://shop.example/p/1?ref=1&k={}", token.as_str()),
        format!("https://shop.example/p/1#k={}", token.as_str()),
        format!("/p/1&k={}", token.as_str()),
        format!("##k={}", token.as_str()),
    ] {
        assert_eq!(
            VipInviteFragment::parse_url_fragment(&non_fragment),
            Err(CryptoError::InvalidInviteFragment),
            "non-fragment URL/query was accepted: {non_fragment}"
        );
    }
    // Wrong version byte (0x02) WITH a validly recomputed BLAKE3 checksum must still fail!
    {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let mut raw_v2 = [0_u8; 39];
        raw_v2[0] = 0x02;
        raw_v2[1..5].copy_from_slice(&group_key_version.to_be_bytes());
        raw_v2[5..37].copy_from_slice(vip_sk.to_seed_bytes().as_ref());
        let chk = blake3::derive_key(VIP_FRAGMENT_CHK_CONTEXT, &raw_v2[0..37]);
        raw_v2[37..39].copy_from_slice(&chk[0..2]);
        let v2_token = Base64UrlUnpadded::encode_string(&raw_v2);
        assert_eq!(
            VipInviteFragment::parse_token(&v2_token),
            Err(CryptoError::InvalidInviteFragment)
        );
    }
    assert_eq!(
        VipInviteFragment::parse_url_fragment(&"a".repeat(VIP_FRAGMENT_MAX_INPUT_LEN + 1)),
        Err(CryptoError::InvalidInviteFragment)
    );

    // Cross-tenant & cross-product replay rejected on decrypt_private_product_vip(_fragment).
    let mut wrong_vip_tenant_ctx = ctx;
    wrong_vip_tenant_ctx.tenant_id[0] ^= 0x01;
    assert!(matches!(
        decrypt_private_product_vip(
            &prod_wire,
            &wrong_vip_tenant_ctx,
            vip_group_id,
            group_key_version,
            &vip_sk,
        ),
        Err(CryptoError::DecryptionFailed)
    ));
    assert!(matches!(
        decrypt_private_product_vip_fragment(
            &prod_wire,
            &wrong_vip_tenant_ctx,
            vip_group_id,
            &frag
        ),
        Err(CryptoError::DecryptionFailed)
    ));
    let mut wrong_vip_prod_ctx = ctx;
    wrong_vip_prod_ctx.resource_id[0] ^= 0x01;
    assert!(matches!(
        decrypt_private_product_vip_fragment(&prod_wire, &wrong_vip_prod_ctx, vip_group_id, &frag),
        Err(CryptoError::DecryptionFailed)
    ));

    // 4. Cross-object domain separation & replay defenses on RCVIP vs PrivateProduct metadata!
    // (a) Submitting wrapped RCVIP envelope as PrivateProduct metadata fails even with same resource_id!
    let same_id_ctx = product_ctx(tenant_id, vip_group_id, PrivacyTier::Strict);
    assert!(matches!(
        decrypt_private_product_vip(
            &wrapped_group,
            &same_id_ctx,
            vip_group_id,
            group_key_version,
            &vip_sk,
        ),
        Err(CryptoError::RecipientNotFound)
    ));
    // Even if attacker tries schema_version = VIP_GROUP_KEY_WRAP_SCHEMA_VERSION, helper rejects it.
    let mut bad_schema_ctx = same_id_ctx;
    bad_schema_ctx.schema_version = VIP_GROUP_KEY_WRAP_SCHEMA_VERSION;
    assert!(matches!(
        decrypt_private_product_vip(
            &wrapped_group,
            &bad_schema_ctx,
            vip_group_id,
            group_key_version,
            &vip_sk,
        ),
        Err(CryptoError::ReservedSchemaVersion(
            VIP_GROUP_KEY_WRAP_SCHEMA_VERSION
        ))
    ));
    // (b) Submitting PrivateProduct metadata envelope (even with resource_id = vip_group_id):
    // - Non-74B payload rejected BEFORE decapsulation with InvalidVipKeyPayload.
    let prod_same_id = encrypt_private_product_vip(
        metadata,
        &same_id_ctx,
        EnvelopeFlags::default(),
        vip_group_id,
        group_key_version,
        &vip_pk,
        &[buyer_vault.recipient_spec(1)],
    )?;
    assert!(matches!(
        unwrap_vip_group_key(
            &prod_same_id,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::InvalidVipKeyPayload)
    ));
    // - Exact 74B PrivateProduct metadata (schema_version = 1 != 0x8001) fails canonical_aad!
    let prod_74b = encrypt_private_product_vip(
        &[0x42_u8; VIP_KEY_WRAP_PAYLOAD_LEN],
        &same_id_ctx,
        EnvelopeFlags::default(),
        vip_group_id,
        group_key_version,
        &vip_pk,
        &[buyer_vault.recipient_spec(1)],
    )?;
    assert!(matches!(
        unwrap_vip_group_key(
            &prod_74b,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::DecryptionFailed)
    ));

    // (c) Pre-decapsulation checks on unwrap_vip_group_key: compressed_zstd flag & wrong length
    // rejected BEFORE X-Wing decapsulation (even with an unrelated credential!).
    let (unrelated_sk, unrelated_pk) = XWingSecretKey::generate()?;
    let unrelated_cred = RecipientCredential::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: unrelated_pk.key_id(),
        key_version: 99,
        secret_key: &unrelated_sk,
    };
    let wrap_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::PrivateProduct,
        tenant_id,
        resource_id: vip_group_id,
        privacy_tier: PrivacyTier::Strict,
        schema_version: VIP_GROUP_KEY_WRAP_SCHEMA_VERSION,
    };
    let compressed_wrap = encrypt(
        &[0x11_u8; VIP_KEY_WRAP_PAYLOAD_LEN],
        &wrap_ctx,
        EnvelopeFlags::new(true),
        &[buyer_vault.recipient_spec(1)],
    )?;
    assert!(matches!(
        unwrap_vip_group_key(
            &compressed_wrap,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &unrelated_cred,
        ),
        Err(CryptoError::UnsupportedFlags(0x01))
    ));
    let oversized_wrap = encrypt(
        &[0x11_u8; 200],
        &wrap_ctx,
        EnvelopeFlags::default(),
        &[buyer_vault.recipient_spec(1)],
    )?;
    assert!(matches!(
        unwrap_vip_group_key(
            &oversized_wrap,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &unrelated_cred,
        ),
        Err(CryptoError::InvalidVipKeyPayload)
    ));

    // Malformed RCVIP inner payloads (bad magic or bad version of exact 74B) rejected.
    let mut bad_magic_payload = [0_u8; VIP_KEY_WRAP_PAYLOAD_LEN];
    bad_magic_payload[0..5].copy_from_slice(b"BAD!!");
    bad_magic_payload[5] = 0x01;
    bad_magic_payload[6..22].copy_from_slice(&tenant_id);
    bad_magic_payload[22..38].copy_from_slice(&vip_group_id);
    bad_magic_payload[38..42].copy_from_slice(&group_key_version.to_be_bytes());
    let bad_magic_wrap = encrypt(
        &bad_magic_payload,
        &wrap_ctx,
        EnvelopeFlags::default(),
        &[buyer_vault.recipient_spec(1)],
    )?;
    assert!(matches!(
        unwrap_vip_group_key(
            &bad_magic_wrap,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::InvalidVipKeyPayload)
    ));
    let mut bad_ver_payload = bad_magic_payload;
    bad_ver_payload[0..5].copy_from_slice(VIP_KEY_WRAP_MAGIC);
    bad_ver_payload[5] = 0x02;
    let bad_ver_wrap = encrypt(
        &bad_ver_payload,
        &wrap_ctx,
        EnvelopeFlags::default(),
        &[buyer_vault.recipient_spec(1)],
    )?;
    assert!(matches!(
        unwrap_vip_group_key(
            &bad_ver_wrap,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::InvalidVipKeyPayload)
    ));

    // (d) Replaying wrapped RCVIP across wrong key_version, wrong tenant, wrong group, or wrong tier fails.
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            tenant_id,
            vip_group_id,
            group_key_version + 1,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::InvalidVipKeyPayload)
    ));
    let mut other_tenant = tenant_id;
    other_tenant[0] ^= 0x01;
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            other_tenant,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::DecryptionFailed)
    ));
    let mut other_group = vip_group_id;
    other_group[0] ^= 0x01;
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            tenant_id,
            other_group,
            group_key_version,
            PrivacyTier::Strict,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::DecryptionFailed)
    ));
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Flexible,
            &buyer_vault.recipient_credential(1),
        ),
        Err(CryptoError::DecryptionFailed)
    ));

    // (e) Self-wrapping VIP key to XWingVipGroup or Argon2idPassword rejected on both wrap & unwrap.
    assert_eq!(
        wrap_vip_group_key(
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &vip_sk,
            &[RecipientSpec::XWing {
                recipient_type: RecipientType::XWingVipGroup,
                key_id: vip_group_id,
                key_version: group_key_version,
                public_key: &vip_pk,
            }],
        ),
        Err(CryptoError::InvalidRecipientType(0x04))
    );
    let dummy_pw_kek = SymmetricKey::from_bytes([0x55; 32]);
    assert_eq!(
        wrap_vip_group_key(
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &vip_sk,
            &[RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: vip_group_id,
                key_version: 1,
                kem_data: &[0x11; ARGON2_KEM_DATA_LEN],
                kek: &dummy_pw_kek,
            }],
        ),
        Err(CryptoError::InvalidRecipientType(0x05))
    );
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingVipGroup,
                key_id: vip_group_id,
                key_version: group_key_version,
                secret_key: &vip_sk,
            },
        ),
        Err(CryptoError::InvalidRecipientType(0x04))
    ));
    assert!(matches!(
        unwrap_vip_group_key(
            &wrapped_group,
            tenant_id,
            vip_group_id,
            group_key_version,
            PrivacyTier::Strict,
            &RecipientCredential::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: vip_group_id,
                key_version: 1,
                kek: &dummy_pw_kek,
            },
        ),
        Err(CryptoError::InvalidRecipientType(0x05))
    ));

    Ok(())
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct S12KatVectors {
    strict_account_id_v1: StrictIdKat,
    private_product_password_v1: PrivateProductPasswordKat,
    private_product_vip_v1: PrivateProductVipKat,
}

#[derive(Debug, Deserialize)]
struct StrictIdKat {
    raw_16b_hex: String,
    tenant_id_hex: String,
    kms_pepper_hex: String,
    signature_message_hex: String,
    expected_formatted: String,
    expected_compact: String,
    expected_lookup_id_hex: String,
    expected_opaque_input_hex: String,
    expected_customer_vault_seed_hex: String,
    expected_server_lookup_index_hex: String,
    expected_xwing_pk_blake3_hex: String,
    expected_ed25519_vk_hex: String,
    expected_ed25519_sig_hex: String,
}

#[derive(Debug, Deserialize)]
struct PrivateProductPasswordKat {
    rng_label: String,
    org_seed_hex: String,
    tenant_id_hex: String,
    product_id_hex: String,
    password_utf8: String,
    password_version: u32,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    plaintext_hex: String,
    expected_kem_data_hex: String,
    expected_argon2_kek_hex: String,
    expected_envelope_blake3_hex: String,
    expected_envelope_len: usize,
}

#[derive(Debug, Deserialize)]
struct PrivateProductVipKat {
    rng_label_wrap: String,
    rng_label_product: String,
    org_seed_hex: String,
    vip_group_seed_hex: String,
    member_strict_id_hex: String,
    tenant_id_hex: String,
    vip_group_id_hex: String,
    product_id_hex: String,
    group_key_version: u32,
    plaintext_hex: String,
    expected_url_fragment: String,
    expected_member_wrap_blake3_hex: String,
    expected_member_wrap_len: usize,
    expected_product_envelope_blake3_hex: String,
    expected_product_envelope_len: usize,
}

fn decode_fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| format!("expected {N} decoded bytes").into())
}

#[test]
fn golden_kat_vectors_strict_id_and_private_product_v1() -> Result<(), Box<dyn std::error::Error>> {
    let raw_json = include_str!("../../../vectors/strict_id_private_product_v1.json");
    let vectors: S12KatVectors = serde_json::from_str(raw_json)?;

    // 1. Strict Account ID KAT.
    let sid = &vectors.strict_account_id_v1;
    let raw_16b: [u8; 16] = decode_fixed(&sid.raw_16b_hex)?;
    let tenant_id: [u8; 16] = decode_fixed(&sid.tenant_id_hex)?;
    let kms_pepper = SymmetricKey::from_bytes(decode_fixed(&sid.kms_pepper_hex)?);
    let sig_msg = hex::decode(&sid.signature_message_hex)?;

    let account = StrictAccountId::from_bytes(raw_16b);
    let formatted = account.to_formatted_string();
    let compact = account.to_compact_string();
    let keys = account.derive_keys(&tenant_id)?;
    let server_idx = compute_strict_lookup_index(&kms_pepper, &tenant_id, keys.auth_lookup_id());
    let vault = keys.derive_vault()?;
    let xwing_pk_hash = blake3::hash(&vault.xwing_public().to_bytes());
    let ed_vk_hex = hex::encode(vault.ed25519_verifying().to_bytes());
    let ed_sig = vault.ed25519_signing().sign(&sig_msg);

    // Independent spec verification of Crockford checksum & server index.
    let expected_chk_digest = blake3::derive_key("rustcom-v1-account-id-chk", &raw_16b);
    let top10 = u16::from_be_bytes([expected_chk_digest[0], expected_chk_digest[1]]) >> 6;
    assert_eq!(
        compact.as_bytes()[26],
        CROCKFORD_CHARS[usize::from((top10 >> 5) & 0x1F)]
    );
    assert_eq!(
        compact.as_bytes()[27],
        CROCKFORD_CHARS[usize::from(top10 & 0x1F)]
    );
    assert_eq!(StrictAccountId::parse(&formatted)?, account);
    vault.ed25519_verifying().verify_strict(&sig_msg, &ed_sig)?;

    // 2. Private Product Password KAT (full 64 MiB Argon2id).
    let pw = &vectors.private_product_password_v1;
    let (pw_org_sk, pw_org_pk) = XWingSecretKey::from_seed_bytes(decode_fixed(&pw.org_seed_hex)?);
    let pw_tenant: [u8; 16] = decode_fixed(&pw.tenant_id_hex)?;
    let pw_product: [u8; 16] = decode_fixed(&pw.product_id_hex)?;
    let pw_pt = hex::decode(&pw.plaintext_hex)?;
    let pw_ctx = product_ctx(pw_tenant, pw_product, PrivacyTier::Strict);
    let pw_params = Argon2idParams::new(pw.m_cost_kib, pw.t_cost, pw.p_cost)?;
    let mut pw_rng = DeterministicTestRng::from_label(pw.rng_label.as_bytes());
    let pw_wire = encrypt_private_product_password_with_rng(
        &mut pw_rng,
        &pw_pt,
        &pw_ctx,
        EnvelopeFlags::default(),
        pw.password_utf8.as_bytes(),
        pw.password_version,
        pw_params,
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: pw_org_pk.key_id(),
            key_version: 1,
            public_key: &pw_org_pk,
        }],
    )?;
    let (extracted_ver, extracted_kem) = extract_password_slot(&pw_wire, &pw_product)?;
    assert_eq!(extracted_ver, pw.password_version);
    let pw_kek = derive_password_kek(pw.password_utf8.as_bytes(), &extracted_kem)?;

    // 3. Private Product VIP KAT.
    let vip = &vectors.private_product_vip_v1;
    let (_vip_org_sk, vip_org_pk) =
        XWingSecretKey::from_seed_bytes(decode_fixed(&vip.org_seed_hex)?);
    let (vip_sk, vip_pk) = XWingSecretKey::from_seed_bytes(decode_fixed(&vip.vip_group_seed_hex)?);
    let vip_tenant: [u8; 16] = decode_fixed(&vip.tenant_id_hex)?;
    let vip_group_id: [u8; 16] = decode_fixed(&vip.vip_group_id_hex)?;
    let vip_product_id: [u8; 16] = decode_fixed(&vip.product_id_hex)?;
    let vip_pt = hex::decode(&vip.plaintext_hex)?;
    let member_vault = StrictAccountId::from_bytes(decode_fixed(&vip.member_strict_id_hex)?)
        .derive_vault(&vip_tenant)?;

    let frag = VipInviteFragment::from_secret_key(vip.group_key_version, &vip_sk)?;
    let frag_url = frag.to_url_fragment();

    let mut wrap_rng = DeterministicTestRng::from_label(vip.rng_label_wrap.as_bytes());
    let member_wrap = wrap_vip_group_key_with_rng(
        &mut wrap_rng,
        vip_tenant,
        vip_group_id,
        vip.group_key_version,
        PrivacyTier::Strict,
        &vip_sk,
        &[member_vault.recipient_spec(1)],
    )?;

    let vip_ctx = product_ctx(vip_tenant, vip_product_id, PrivacyTier::Strict);
    let mut prod_rng = DeterministicTestRng::from_label(vip.rng_label_product.as_bytes());
    let vip_prod_wire = encrypt_private_product_vip_with_rng(
        &mut prod_rng,
        &vip_pt,
        &vip_ctx,
        EnvelopeFlags::default(),
        vip_group_id,
        vip.group_key_version,
        &vip_pk,
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: vip_org_pk.key_id(),
            key_version: 1,
            public_key: &vip_org_pk,
        }],
    )?;

    assert_eq!(formatted.as_str(), sid.expected_formatted);
    assert_eq!(compact.as_str(), sid.expected_compact);
    assert_eq!(
        hex::encode(keys.auth_lookup_id()),
        sid.expected_lookup_id_hex
    );
    assert_eq!(
        hex::encode(keys.auth_secret().as_bytes()),
        sid.expected_opaque_input_hex
    );
    assert_eq!(
        hex::encode(keys.customer_vault_seed().as_bytes()),
        sid.expected_customer_vault_seed_hex
    );
    assert_eq!(
        hex::encode(server_idx),
        sid.expected_server_lookup_index_hex
    );
    assert_eq!(
        xwing_pk_hash.to_hex().as_str(),
        sid.expected_xwing_pk_blake3_hex
    );
    assert_eq!(ed_vk_hex, sid.expected_ed25519_vk_hex);
    assert_eq!(hex::encode(ed_sig), sid.expected_ed25519_sig_hex);

    assert_eq!(
        hex::encode(extracted_kem.to_bytes()),
        pw.expected_kem_data_hex
    );
    assert_eq!(hex::encode(pw_kek.as_bytes()), pw.expected_argon2_kek_hex);
    assert_eq!(pw_wire.len(), pw.expected_envelope_len);
    assert_eq!(
        blake3::hash(&pw_wire).to_hex().as_str(),
        pw.expected_envelope_blake3_hex
    );
    assert_eq!(
        decrypt_private_product_password(&pw_wire, &pw_ctx, pw.password_utf8.as_bytes())?
            .plaintext
            .as_slice(),
        pw_pt.as_slice()
    );
    assert_eq!(
        decrypt(
            &pw_wire,
            &pw_ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: pw_org_pk.key_id(),
                key_version: 1,
                secret_key: &pw_org_sk,
            },
        )?
        .plaintext
        .as_slice(),
        pw_pt.as_slice()
    );

    assert_eq!(frag_url.as_str(), vip.expected_url_fragment);
    assert_eq!(member_wrap.len(), vip.expected_member_wrap_len);
    assert_eq!(
        blake3::hash(&member_wrap).to_hex().as_str(),
        vip.expected_member_wrap_blake3_hex
    );
    assert_eq!(vip_prod_wire.len(), vip.expected_product_envelope_len);
    assert_eq!(
        blake3::hash(&vip_prod_wire).to_hex().as_str(),
        vip.expected_product_envelope_blake3_hex
    );

    let (unwrapped_sk, unwrapped_pk) = unwrap_vip_group_key(
        &member_wrap,
        vip_tenant,
        vip_group_id,
        vip.group_key_version,
        PrivacyTier::Strict,
        &member_vault.recipient_credential(1),
    )?;
    assert_eq!(unwrapped_pk, vip_pk);
    assert_eq!(
        decrypt_private_product_vip(
            &vip_prod_wire,
            &vip_ctx,
            vip_group_id,
            vip.group_key_version,
            &unwrapped_sk,
        )?
        .plaintext
        .as_slice(),
        vip_pt.as_slice()
    );
    let parsed_frag = VipInviteFragment::parse_url_fragment(&frag_url)?;
    assert_eq!(
        decrypt_private_product_vip_fragment(&vip_prod_wire, &vip_ctx, vip_group_id, &parsed_frag)?
            .plaintext
            .as_slice(),
        vip_pt.as_slice()
    );

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn proptest_strict_account_id_bijection_normalization_and_checksum_invariants(
        raw in any::<[u8; 16]>(),
        chk_pos in 26_usize..28,
        mutate_delta in 1_u8..32,
        data_pos in 0_usize..26,
    ) {
        let id = StrictAccountId::from_bytes(raw);
        let formatted = id.to_formatted_string();
        let compact = id.to_compact_string();

        prop_assert_eq!(formatted.len(), STRICT_ACCOUNT_ID_FORMATTED_LEN);
        prop_assert_eq!(compact.len(), STRICT_ACCOUNT_ID_TOTAL_CHARS);
        prop_assert_eq!(StrictAccountId::parse(&formatted), Ok(id.clone()));
        prop_assert_eq!(StrictAccountId::parse(&compact), Ok(id.clone()));

        // Lowercase + aliases + whitespace roundtrip.
        let aliased = format!(
            " {} ",
            formatted
                .to_lowercase()
                .replace('0', "o")
                .replace('1', "i")
                .replace('-', " ")
        );
        prop_assert_eq!(StrictAccountId::parse(&aliased), Ok(id.clone()));

        // Mutating either checksum character (positions 26..28) MUST deterministically fail 100%.
        let mut chk_mut = compact.as_bytes().to_vec();
        let cur_idx = CROCKFORD_CHARS
            .iter()
            .position(|&c| c == chk_mut[chk_pos])
            .ok_or_else(|| TestCaseError::fail("encoded char not in Crockford alphabet"))?;
        chk_mut[chk_pos] = CROCKFORD_CHARS[(cur_idx + usize::from(mutate_delta)) % 32];
        let chk_mut_str = String::from_utf8(chk_mut)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(
            StrictAccountId::parse(&chk_mut_str),
            Err(CryptoError::InvalidAccountIdChecksum)
        );

        // Mutating a data character (positions 0..26) can never decode back to the same Account ID;
        // if a rare 1-in-1024 10-bit BLAKE3 collision occurs, its re-encoded string must equal the
        // mutated string (proving canonical bijection).
        let mut data_mut = compact.as_bytes().to_vec();
        let data_idx = CROCKFORD_CHARS
            .iter()
            .position(|&c| c == data_mut[data_pos])
            .ok_or_else(|| TestCaseError::fail("encoded char not in Crockford alphabet"))?;
        data_mut[data_pos] = CROCKFORD_CHARS[(data_idx + usize::from(mutate_delta)) % 32];
        let data_mut_str = String::from_utf8(data_mut)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        if let Ok(other) = StrictAccountId::parse(&data_mut_str) {
            prop_assert_ne!(&other, &id);
            let reencoded = other.to_compact_string();
            prop_assert_eq!(reencoded.as_str(), data_mut_str.as_str());
        }
    }

    #[test]
    fn proptest_vip_invite_fragment_roundtrip_and_checksum_invariants(
        key_version in 1_u32..=u32::MAX,
        seed in any::<[u8; 32]>(),
        chk_char_pos in (VIP_FRAGMENT_TOKEN_LEN - 2)..VIP_FRAGMENT_TOKEN_LEN,
    ) {
        let (sk, pk) = XWingSecretKey::from_seed_bytes(seed);
        let frag = VipInviteFragment::from_secret_key(key_version, &sk)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let url_frag = frag.to_url_fragment();
        let token = frag.to_token();

        let parsed = VipInviteFragment::parse_url_fragment(&url_frag)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(parsed.key_version(), key_version);
        let (_, rebuilt_pk) = parsed.to_xwing_keypair();
        prop_assert_eq!(rebuilt_pk, pk);

        // Mutating either of the final 2 Base64URL chars strictly alters the 16-bit BLAKE3 checksum
        // without changing the 37-byte prefix, so parsing MUST deterministically fail 100%.
        let mut bytes = token.as_bytes().to_vec();
        bytes[chk_char_pos] = if bytes[chk_char_pos] == b'A' { b'B' } else { b'A' };
        let mutated = String::from_utf8(bytes)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(
            VipInviteFragment::parse_token(&mutated),
            Err(CryptoError::InvalidInviteFragment)
        );
    }

    #[test]
    fn proptest_arbitrary_strings_never_panic_parsers(raw in ".*") {
        let _ = StrictAccountId::parse(&raw);
        let _ = VipInviteFragment::parse_token(&raw);
        let _ = VipInviteFragment::parse_url_fragment(&raw);
    }
}

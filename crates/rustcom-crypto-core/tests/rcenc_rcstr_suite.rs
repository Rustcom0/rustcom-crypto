#![forbid(unsafe_code)]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use proptest::prelude::*;
use rand_core::{TryCryptoRng, TryRng};
use rustcom_crypto_core::{
    AEAD_TAG_LEN, CryptoError, DEFAULT_CHUNK_SIZE, EnvelopeContext, EnvelopeFlags, EnvelopeKind,
    MIN_CHUNK_SIZE, PrivacyTier, RCENC_HEADER_LEN, RCSTR_FIXED_HEADER_LEN, RcstrDecryptor,
    RcstrEncryptor, RecipientCredential, RecipientSpec, RecipientType, SymmetricKey,
    XWING_CIPHERTEXT_LEN, XWING_PUBLIC_KEY_LEN, XWingPublicKey, XWingSecretKey,
    build_canonical_aad, decrypt, decrypt_stream, encrypt, encrypt_stream, encrypt_stream_with_rng,
    encrypt_with_rng, parse_envelope,
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

fn sample_ctx(kind: EnvelopeKind, tier: PrivacyTier) -> EnvelopeContext {
    EnvelopeContext {
        envelope_kind: kind,
        tenant_id: [0x11; 16],
        resource_id: [0x22; 16],
        privacy_tier: tier,
        schema_version: 1,
    }
}

/// Known Curve25519 low-order u-coordinates (order 1, 2, 4, 8 on curve + twist + non-canonical >= p).
const LOW_ORDER_X25519_POINTS: [[u8; 32]; 7] = [
    // 0
    [0x00; 32],
    // 1
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 = 2^255 - 20
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Non-canonical p = 2^255 - 19 (equiv 0 mod p)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // Non-canonical p + 1 = 2^255 - 18 (equiv 1 mod p)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

#[test]
fn xwing_keypair_roundtrip_redaction_and_low_order_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = XWingSecretKey::generate()?;
    let pk_bytes = pk.to_bytes();
    assert_eq!(pk_bytes.len(), XWING_PUBLIC_KEY_LEN);

    let pk_parsed = XWingPublicKey::from_bytes(&pk_bytes)?;
    assert_eq!(pk_parsed, pk);
    assert_eq!(pk_parsed.key_id(), pk.key_id());

    let seed = sk.to_seed_bytes();
    let (sk_rebuilt, pk_rebuilt) = XWingSecretKey::from_seed_slice(seed.as_slice())?;
    assert_eq!(pk_rebuilt, pk);
    assert_eq!(sk_rebuilt.public_key(), pk);

    let (ct, ss_sender) = pk.encapsulate()?;
    assert_eq!(ct.len(), XWING_CIPHERTEXT_LEN);
    let ss_receiver = sk_rebuilt.decapsulate(ct.as_ref())?;
    assert_eq!(ss_sender, ss_receiver);

    // Secret Debug output must never leak key bytes.
    assert_eq!(format!("{sk:?}"), "XWingSecretKey([REDACTED])");
    assert_eq!(format!("{ss_sender:?}"), "SymmetricKey([REDACTED])");

    // Low-order Curve25519 points rejected BOTH in XWingPublicKey::from_bytes AND decapsulate.
    for low_order_u in LOW_ORDER_X25519_POINTS {
        let mut bad_pk = pk_bytes;
        bad_pk[1184..1216].copy_from_slice(&low_order_u);
        assert_eq!(
            XWingPublicKey::from_bytes(&bad_pk),
            Err(CryptoError::InvalidPublicKey)
        );

        let mut bad_ct = *ct;
        bad_ct[1088..1120].copy_from_slice(&low_order_u);
        assert_eq!(sk.decapsulate(&bad_ct), Err(CryptoError::InvalidCiphertext));
    }

    // Malformed lengths rejected.
    assert_eq!(
        XWingPublicKey::from_bytes(&pk_bytes[..100]),
        Err(CryptoError::InvalidPublicKey)
    );
    assert_eq!(
        sk.decapsulate(&ct[..100]),
        Err(CryptoError::InvalidCiphertext)
    );
    assert_eq!(
        XWingSecretKey::from_seed_slice(&[0_u8; 16]).err(),
        Some(CryptoError::InvalidSecretKey)
    );
    Ok(())
}

#[test]
fn rcenc_multi_recipient_roundtrip_debug_redaction_and_wrong_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (org_sk, org_pk) = XWingSecretKey::generate()?;
    let (buyer_sk, buyer_pk) = XWingSecretKey::generate()?;
    let (other_sk, other_pk) = XWingSecretKey::generate()?;

    let password_kek = SymmetricKey::from_bytes([0xAB; 32]);
    let wrong_kek = SymmetricKey::from_bytes([0x99; 32]);
    let recovery_kek = SymmetricKey::from_bytes([0xCD; 32]);
    let argon2_kem_data = [0x42_u8; 44];

    let ctx = sample_ctx(EnvelopeKind::OrderFulfillment, PrivacyTier::Strict);
    let plaintext = br#"{"name":"Alice Example","street":"123 Privacy Way","postal":"10115"}"#;

    let org_id = org_pk.key_id();
    let buyer_id = buyer_pk.key_id();
    let pw_id = [0x55; 16];
    let rec_id = [0x66; 16];

    let recipients = [
        RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_id,
            key_version: 3,
            public_key: &org_pk,
        },
        RecipientSpec::XWing {
            recipient_type: RecipientType::XWingCustomerVault,
            key_id: buyer_id,
            key_version: 1,
            public_key: &buyer_pk,
        },
        RecipientSpec::SymmetricKek {
            recipient_type: RecipientType::Argon2idPassword,
            key_id: pw_id,
            key_version: 1,
            kem_data: &argon2_kem_data,
            kek: &password_kek,
        },
        RecipientSpec::SymmetricKek {
            recipient_type: RecipientType::RecoveryBip39,
            key_id: rec_id,
            key_version: 1,
            kem_data: &[],
            kek: &recovery_kek,
        },
    ];

    let flags = EnvelopeFlags::new(true);
    let wire = encrypt(plaintext, &ctx, flags, &recipients)?;

    // Inspect public header and slots without decrypting.
    let parsed = parse_envelope(&wire)?;
    assert_eq!(parsed.header.recipient_count, 4);
    assert_eq!(parsed.header.envelope_kind, EnvelopeKind::OrderFulfillment);
    assert_eq!(parsed.header.flags, flags);
    assert_eq!(parsed.slots[2].kem_data, &argon2_kem_data);
    assert!(parsed.slots[3].kem_data.is_empty());

    // All 4 authorized recipients decrypt the exact same plaintext; Debug redacts plaintext.
    for cred in [
        RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_id,
            key_version: 3,
            secret_key: &org_sk,
        },
        RecipientCredential::XWing {
            recipient_type: RecipientType::XWingCustomerVault,
            key_id: buyer_id,
            key_version: 1,
            secret_key: &buyer_sk,
        },
        RecipientCredential::SymmetricKek {
            recipient_type: RecipientType::Argon2idPassword,
            key_id: pw_id,
            key_version: 1,
            kek: &password_kek,
        },
        RecipientCredential::SymmetricKek {
            recipient_type: RecipientType::RecoveryBip39,
            key_id: rec_id,
            key_version: 1,
            kek: &recovery_kek,
        },
    ] {
        let dec = decrypt(&wire, &ctx, &cred)?;
        assert_eq!(dec.plaintext.as_slice(), plaintext);
        assert_eq!(dec.header.flags, flags);

        let debug_str = format!("{dec:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("Alice"));
        assert!(!debug_str.contains("123"));
    }

    // Wrong XWingSecretKey with matching slot key_id fails AEAD unwrap.
    assert!(matches!(
        decrypt(
            &wire,
            &ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: org_id,
                key_version: 3,
                secret_key: &other_sk,
            },
        ),
        Err(CryptoError::DecryptionFailed)
    ));

    // Wrong SymmetricKey with matching slot key_id fails AEAD unwrap.
    assert!(matches!(
        decrypt(
            &wire,
            &ctx,
            &RecipientCredential::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: pw_id,
                key_version: 1,
                kek: &wrong_kek,
            },
        ),
        Err(CryptoError::DecryptionFailed)
    ));

    // Unrelated recipient key_id returns RecipientNotFound.
    assert!(matches!(
        decrypt(
            &wire,
            &ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: other_pk.key_id(),
                key_version: 3,
                secret_key: &other_sk,
            },
        ),
        Err(CryptoError::RecipientNotFound)
    ));
    Ok(())
}

#[test]
fn rcenc_defeats_slot_stripping_duplicate_slots_replay_and_malformed_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let (org_sk, org_pk) = XWingSecretKey::generate()?;
    let (_buyer_sk, buyer_pk) = XWingSecretKey::generate()?;
    let ctx = sample_ctx(EnvelopeKind::OrderFulfillment, PrivacyTier::Strict);
    let plaintext = b"strict zero-knowledge shipping blob";

    let org_id = org_pk.key_id();
    let buyer_id = buyer_pk.key_id();
    let wire = encrypt(
        plaintext,
        &ctx,
        EnvelopeFlags::default(),
        &[
            RecipientSpec::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: org_id,
                key_version: 1,
                public_key: &org_pk,
            },
            RecipientSpec::XWing {
                recipient_type: RecipientType::XWingCustomerVault,
                key_id: buyer_id,
                key_version: 1,
                public_key: &buyer_pk,
            },
        ],
    )?;

    let org_cred = RecipientCredential::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: org_id,
        key_version: 1,
        secret_key: &org_sk,
    };

    // 1. T3: Recipient-slot stripping attack.
    let slot_wire_len = 1 + 16 + 4 + 2 + XWING_CIPHERTEXT_LEN + 24 + 48;
    let payload_start = RCENC_HEADER_LEN + 2 * slot_wire_len;
    let mut stripped = Vec::new();
    stripped.extend_from_slice(&wire[..RCENC_HEADER_LEN]);
    stripped[9] = 1;
    stripped.extend_from_slice(&wire[RCENC_HEADER_LEN..RCENC_HEADER_LEN + slot_wire_len]);
    stripped.extend_from_slice(&wire[payload_start..]);
    assert!(matches!(
        decrypt(&stripped, &ctx, &org_cred),
        Err(CryptoError::DecryptionFailed)
    ));

    // 2. Duplicate recipient slots on parse/decrypt rejected.
    let mut dup_wire = wire.clone();
    // Overwrite slot 2's (type, key_id, key_version) with slot 1's identity.
    let slot2_start = RCENC_HEADER_LEN + slot_wire_len;
    dup_wire[slot2_start..slot2_start + 21]
        .copy_from_slice(&wire[RCENC_HEADER_LEN..RCENC_HEADER_LEN + 21]);
    assert!(matches!(
        parse_envelope(&dup_wire),
        Err(CryptoError::DuplicateRecipientSlot)
    ));
    assert!(matches!(
        decrypt(&dup_wire, &ctx, &org_cred),
        Err(CryptoError::DuplicateRecipientSlot)
    ));

    // 3. Cross-tenant, cross-order, cross-kind, cross-tier, cross-schema replay all fail.
    let mut wrong_tenant = ctx;
    wrong_tenant.tenant_id[0] ^= 0x01;
    assert!(matches!(
        decrypt(&wire, &wrong_tenant, &org_cred),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut wrong_order = ctx;
    wrong_order.resource_id[15] ^= 0x80;
    assert!(matches!(
        decrypt(&wire, &wrong_order, &org_cred),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut wrong_tier = ctx;
    wrong_tier.privacy_tier = PrivacyTier::Flexible;
    assert!(matches!(
        decrypt(&wire, &wrong_tier, &org_cred),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut wrong_schema = ctx;
    wrong_schema.schema_version = 2;
    assert!(matches!(
        decrypt(&wire, &wrong_schema, &org_cred),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut wrong_kind = ctx;
    wrong_kind.envelope_kind = EnvelopeKind::OrderAccounting;
    assert!(matches!(
        decrypt(&wire, &wrong_kind, &org_cred),
        Err(CryptoError::InvalidEnvelopeKind(0x01))
    ));

    // 4. Malformed headers: magic, version, cipher suite, flags, trailing bytes, payload length.
    let mut bad_magic = wire.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        parse_envelope(&bad_magic),
        Err(CryptoError::InvalidMagic)
    ));

    let mut bad_ver = wire.clone();
    bad_ver[5] = 0x02;
    assert!(matches!(
        parse_envelope(&bad_ver),
        Err(CryptoError::UnsupportedFormatVersion(0x02))
    ));

    let mut bad_suite = wire.clone();
    bad_suite[6] = 0x09;
    assert!(matches!(
        parse_envelope(&bad_suite),
        Err(CryptoError::UnsupportedCipherSuite(0x09))
    ));

    let mut bad_flags = wire.clone();
    bad_flags[8] = 0x04;
    assert!(matches!(
        parse_envelope(&bad_flags),
        Err(CryptoError::UnsupportedFlags(0x04))
    ));

    let mut with_trailing = wire.clone();
    with_trailing.push(0x00);
    assert!(matches!(
        parse_envelope(&with_trailing),
        Err(CryptoError::TrailingBytes)
    ));

    let mut tiny_payload = wire.clone();
    tiny_payload[payload_start + 24..payload_start + 28].copy_from_slice(&15_u32.to_be_bytes());
    assert!(matches!(
        parse_envelope(&tiny_payload),
        Err(CryptoError::InvalidPayloadLength)
    ));

    let mut huge_payload = wire.clone();
    huge_payload[payload_start + 24..payload_start + 28]
        .copy_from_slice(&(65_u32 * 1024 * 1024).to_be_bytes());
    assert!(matches!(
        parse_envelope(&huge_payload),
        Err(CryptoError::InvalidPayloadLength)
    ));

    // 5. Validation errors on encrypt/decrypt: 0 recipients, 9 recipients, duplicate slot,
    //    wrong kem_data length, mismatched RecipientType for variant.
    assert!(matches!(
        encrypt(plaintext, &ctx, EnvelopeFlags::default(), &[]),
        Err(CryptoError::InvalidRecipientCount(0))
    ));

    let nine_recipients: Vec<RecipientSpec<'_>> = (0_u32..9)
        .map(|ver| RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_id,
            key_version: ver,
            public_key: &org_pk,
        })
        .collect();
    assert!(matches!(
        encrypt(plaintext, &ctx, EnvelopeFlags::default(), &nine_recipients),
        Err(CryptoError::InvalidRecipientCount(9))
    ));

    let dup_specs = [
        RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_id,
            key_version: 1,
            public_key: &org_pk,
        },
        RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: org_id,
            key_version: 1,
            public_key: &org_pk,
        },
    ];
    assert!(matches!(
        encrypt(plaintext, &ctx, EnvelopeFlags::default(), &dup_specs),
        Err(CryptoError::DuplicateRecipientSlot)
    ));

    let kek = SymmetricKey::from_bytes([0x12; 32]);
    assert!(matches!(
        encrypt(
            plaintext,
            &ctx,
            EnvelopeFlags::default(),
            &[RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: [1; 16],
                key_version: 1,
                kem_data: &[0; 10],
                kek: &kek,
            }]
        ),
        Err(CryptoError::InvalidKemDataLength {
            expected: 44,
            actual: 10
        })
    ));
    assert!(matches!(
        encrypt(
            plaintext,
            &ctx,
            EnvelopeFlags::default(),
            &[RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::RecoveryBip39,
                key_id: [1; 16],
                key_version: 1,
                kem_data: &[0; 1],
                kek: &kek,
            }]
        ),
        Err(CryptoError::InvalidKemDataLength {
            expected: 0,
            actual: 1
        })
    ));
    assert!(matches!(
        encrypt(
            plaintext,
            &ctx,
            EnvelopeFlags::default(),
            &[RecipientSpec::XWing {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: org_id,
                key_version: 1,
                public_key: &org_pk,
            }]
        ),
        Err(CryptoError::InvalidRecipientType(0x05))
    ));
    assert!(matches!(
        encrypt(
            plaintext,
            &ctx,
            EnvelopeFlags::default(),
            &[RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: [1; 16],
                key_version: 1,
                kem_data: &[],
                kek: &kek,
            }]
        ),
        Err(CryptoError::InvalidRecipientType(0x01))
    ));
    assert!(matches!(
        decrypt(
            &wire,
            &ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::RecoveryBip39,
                key_id: org_id,
                key_version: 1,
                secret_key: &org_sk,
            }
        ),
        Err(CryptoError::InvalidRecipientType(0x06))
    ));
    assert!(matches!(
        decrypt(
            &wire,
            &ctx,
            &RecipientCredential::SymmetricKek {
                recipient_type: RecipientType::XWingStaffKey,
                key_id: org_id,
                key_version: 1,
                kek: &kek,
            }
        ),
        Err(CryptoError::InvalidRecipientType(0x03))
    ));

    Ok(())
}

#[test]
fn rcstr_domain_separation_streaming_and_tamper_defenses() -> Result<(), Box<dyn std::error::Error>>
{
    let (sk, pk) = XWingSecretKey::generate()?;
    let (wrong_sk, wrong_pk) = XWingSecretKey::generate()?;
    let ctx = sample_ctx(EnvelopeKind::PrivateProduct, PrivacyTier::Strict);
    let key_id = pk.key_id();
    let recipients = [RecipientSpec::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id,
        key_version: 1,
        public_key: &pk,
    }];
    let cred = RecipientCredential::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id,
        key_version: 1,
        secret_key: &sk,
    };

    // Test boundary lengths: 0B, 1B, exact 1 chunk, exact 2 chunks, 2.5 chunks.
    for size in [
        0_usize,
        1,
        MIN_CHUNK_SIZE as usize,
        2 * MIN_CHUNK_SIZE as usize,
        2 * MIN_CHUNK_SIZE as usize + 777,
    ] {
        let mut pt = vec![0_u8; size];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = u8::try_from(i % 251)?;
        }
        let wire = encrypt_stream(&pt, &ctx, MIN_CHUNK_SIZE, &recipients)?;
        let dec = decrypt_stream(&wire, &ctx, &cred)?;
        assert_eq!(dec.as_slice(), pt.as_slice(), "failed for size={size}");
    }

    // Incremental exact-multiple stream followed by an explicit 0-byte final chunk.
    let (mut enc_exact, hdr_exact) = RcstrEncryptor::new(&ctx, MIN_CHUNK_SIZE, &recipients)?;
    let full_chunk = vec![0x77_u8; MIN_CHUNK_SIZE as usize];
    let c0 = enc_exact.encrypt_chunk(&full_chunk, false)?;
    let c1_empty_final = enc_exact.encrypt_chunk(&[], true)?;
    let mut exact_stream = Vec::new();
    exact_stream.extend_from_slice(&hdr_exact);
    exact_stream.extend_from_slice(&c0);
    exact_stream.extend_from_slice(&c1_empty_final);
    let (mut dec_exact, consumed_exact) = RcstrDecryptor::new(&exact_stream, &ctx, &cred)?;
    assert_eq!(consumed_exact, hdr_exact.len());
    assert_eq!(
        dec_exact.decrypt_chunk(&c0, false)?.as_slice(),
        full_chunk.as_slice()
    );
    assert!(dec_exact.decrypt_chunk(&c1_empty_final, true)?.is_empty());

    // Cross-protocol domain separation:
    // (a) Stripping RCSTR prefix and submitting embedded RCENC to standalone rcenc::decrypt MUST fail!
    let inner_rcenc = &hdr_exact[RCSTR_FIXED_HEADER_LEN..];
    assert!(matches!(
        decrypt(inner_rcenc, &ctx, &cred),
        Err(CryptoError::UnsupportedFlags(0x02))
    ));
    // (b) Wrapping a standalone RCENC (flags=0x00) inside an RCSTR prefix MUST fail before decapsulation!
    let standalone_rcenc = encrypt(&[0_u8; 58], &ctx, EnvelopeFlags::default(), &recipients)?;
    let mut forged_rcstr = Vec::new();
    forged_rcstr.extend_from_slice(&hdr_exact[..RCSTR_FIXED_HEADER_LEN]);
    forged_rcstr.extend_from_slice(&standalone_rcenc);
    assert!(matches!(
        RcstrDecryptor::new(&forged_rcstr, &ctx, &cred),
        Err(CryptoError::UnsupportedFlags(0x00))
    ));
    // (c) Forged RCSTR header with flags=0x02 but wrong ciphertext_len (!= 74) rejected BEFORE decapsulation!
    let mut forged_big_len = hdr_exact.clone();
    let fake_len_pos = hdr_exact.len() - 74 - 4;
    forged_big_len[fake_len_pos..fake_len_pos + 4].copy_from_slice(&100_u32.to_be_bytes());
    forged_big_len.extend_from_slice(&[0_u8; 26]);
    let wrong_cred = RecipientCredential::XWing {
        recipient_type: RecipientType::XWingOrgKey,
        key_id: wrong_pk.key_id(),
        key_version: 1,
        secret_key: &wrong_sk,
    };
    assert!(matches!(
        RcstrDecryptor::new(&forged_big_len, &ctx, &wrong_cred),
        Err(CryptoError::StreamHeaderMismatch)
    ));

    // Incremental multi-chunk streaming + reorder / truncation / extension / header tamper tests.
    let chunk0 = vec![0xAA_u8; MIN_CHUNK_SIZE as usize];
    let chunk1 = vec![0xBB_u8; MIN_CHUNK_SIZE as usize];
    let chunk2_final = vec![0xCC_u8; 123];

    let (mut enc, header) = RcstrEncryptor::new(&ctx, MIN_CHUNK_SIZE, &recipients)?;
    // Non-final wrong chunk length rejected; oversized final chunk rejected.
    assert!(matches!(
        enc.encrypt_chunk(&[1, 2, 3], false),
        Err(CryptoError::InvalidChunkLength)
    ));
    assert!(matches!(
        enc.encrypt_chunk(&vec![0_u8; MIN_CHUNK_SIZE as usize + 1], true),
        Err(CryptoError::InvalidChunkLength)
    ));
    let ct0 = enc.encrypt_chunk(&chunk0, false)?;
    let ct1 = enc.encrypt_chunk(&chunk1, false)?;
    let ct2 = enc.encrypt_chunk(&chunk2_final, true)?;
    assert!(enc.is_finished());
    assert!(matches!(
        enc.encrypt_chunk(&[], true),
        Err(CryptoError::StreamFinished)
    ));

    let mut full_stream = Vec::new();
    full_stream.extend_from_slice(&header);
    full_stream.extend_from_slice(&ct0);
    full_stream.extend_from_slice(&ct1);
    full_stream.extend_from_slice(&ct2);

    let (mut dec, header_len) = RcstrDecryptor::new(&full_stream, &ctx, &cred)?;
    assert_eq!(header_len, header.len());
    assert!(matches!(
        dec.decrypt_chunk(&[0_u8; 10], false),
        Err(CryptoError::InvalidChunkLength)
    ));
    assert!(matches!(
        dec.decrypt_chunk(&[0_u8; 10], true),
        Err(CryptoError::InvalidChunkLength)
    ));
    assert_eq!(
        dec.decrypt_chunk(&ct0, false)?.as_slice(),
        chunk0.as_slice()
    );
    assert_eq!(
        dec.decrypt_chunk(&ct1, false)?.as_slice(),
        chunk1.as_slice()
    );
    assert_eq!(
        dec.decrypt_chunk(&ct2, true)?.as_slice(),
        chunk2_final.as_slice()
    );
    assert!(dec.is_finished());
    assert!(matches!(
        dec.decrypt_chunk(&ct2, true),
        Err(CryptoError::StreamFinished)
    ));

    // Empty / short stream body (< 16 B) rejected with TruncatedInput.
    assert!(matches!(
        decrypt_stream(&header, &ctx, &cred),
        Err(CryptoError::TruncatedInput)
    ));
    let mut short_body = header.clone();
    short_body.extend_from_slice(&[0_u8; 15]);
    assert!(matches!(
        decrypt_stream(&short_body, &ctx, &cred),
        Err(CryptoError::TruncatedInput)
    ));

    // Truncation attacks, chunk reorder, extension attack.
    let truncated_len = header.len() + ct0.len() + ct1.len();
    assert!(matches!(
        decrypt_stream(&full_stream[..truncated_len], &ctx, &cred),
        Err(CryptoError::DecryptionFailed)
    ));
    assert!(matches!(
        decrypt_stream(&full_stream[..full_stream.len() - 1], &ctx, &cred),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut swapped = Vec::new();
    swapped.extend_from_slice(&header);
    swapped.extend_from_slice(&ct1);
    swapped.extend_from_slice(&ct0);
    swapped.extend_from_slice(&ct2);
    assert!(matches!(
        decrypt_stream(&swapped, &ctx, &cred),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut extended = full_stream.clone();
    extended.extend_from_slice(&ct2);
    assert!(decrypt_stream(&extended, &ctx, &cred).is_err());

    // RCSTR header tampering: magic, version, chunk_size, file_nonce_prefix.
    let small_stream =
        encrypt_stream(b"tiny private image", &ctx, DEFAULT_CHUNK_SIZE, &recipients)?;
    let mut bad_magic = small_stream.clone();
    bad_magic[0] = b'Z';
    assert!(matches!(
        decrypt_stream(&bad_magic, &ctx, &cred),
        Err(CryptoError::InvalidMagic)
    ));

    let mut bad_ver = small_stream.clone();
    bad_ver[5] = 0x99;
    assert!(matches!(
        decrypt_stream(&bad_ver, &ctx, &cred),
        Err(CryptoError::UnsupportedFormatVersion(0x99))
    ));

    let mut tampered_chunk_sz = small_stream.clone();
    tampered_chunk_sz[6..10].copy_from_slice(&MIN_CHUNK_SIZE.to_be_bytes());
    assert!(matches!(
        decrypt_stream(&tampered_chunk_sz, &ctx, &cred),
        Err(CryptoError::StreamHeaderMismatch)
    ));

    let mut tampered_nonce_prefix = small_stream.clone();
    tampered_nonce_prefix[12] ^= 0x01;
    assert!(matches!(
        decrypt_stream(&tampered_nonce_prefix, &ctx, &cred),
        Err(CryptoError::StreamHeaderMismatch)
    ));

    // Invalid chunk_size bounds & cross-file replay rejected.
    assert!(matches!(
        RcstrEncryptor::new(&ctx, 1024, &recipients),
        Err(CryptoError::InvalidChunkSize(1024))
    ));
    assert!(matches!(
        RcstrEncryptor::new(&ctx, 8 * 1024 * 1024, &recipients),
        Err(CryptoError::InvalidChunkSize(_))
    ));
    let mut other_file_ctx = ctx;
    other_file_ctx.resource_id[0] ^= 0xFF;
    assert!(decrypt_stream(&full_stream, &other_file_ctx, &cred).is_err());

    assert_eq!(RCSTR_FIXED_HEADER_LEN, 26);
    assert_eq!(AEAD_TAG_LEN, 16);
    Ok(())
}

#[derive(Debug, Deserialize)]
struct KatVectors {
    rcenc_v1: RcencKat,
    rcenc_v1_multi_compressed: RcencMultiKat,
    rcstr_v1: RcstrKat,
    rcstr_v1_multi_chunk: RcstrMultiChunkKat,
}

#[derive(Debug, Deserialize)]
struct RcencKat {
    rng_label: String,
    seed_hex: String,
    tenant_id_hex: String,
    resource_id_hex: String,
    envelope_kind: u8,
    privacy_tier: u8,
    schema_version: u16,
    key_version: u32,
    plaintext_hex: String,
    expected_public_key_blake3_hex: String,
    expected_canonical_aad_hex: String,
    expected_envelope_blake3_hex: String,
    expected_envelope_len: usize,
}

#[derive(Debug, Deserialize)]
struct RcencMultiKat {
    rng_label: String,
    seed_hex: String,
    argon2_kem_data_hex: String,
    argon2_kek_hex: String,
    recovery_kek_hex: String,
    tenant_id_hex: String,
    resource_id_hex: String,
    plaintext_hex: String,
    expected_envelope_blake3_hex: String,
    expected_envelope_len: usize,
}

#[derive(Debug, Deserialize)]
struct RcstrKat {
    rng_label: String,
    seed_hex: String,
    tenant_id_hex: String,
    file_id_hex: String,
    chunk_size: u32,
    plaintext_hex: String,
    expected_stream_blake3_hex: String,
    expected_stream_len: usize,
}

#[derive(Debug, Deserialize)]
struct RcstrMultiChunkKat {
    rng_label: String,
    seed_hex: String,
    tenant_id_hex: String,
    file_id_hex: String,
    chunk_size: u32,
    plaintext_len: usize,
    expected_stream_blake3_hex: String,
    expected_stream_len: usize,
}

fn decode_fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| format!("expected {N} decoded bytes").into())
}

#[test]
fn golden_kat_vectors_match_protocol_spec_byte_for_byte() -> Result<(), Box<dyn std::error::Error>>
{
    let raw_json = include_str!("../../../vectors/rcenc_rcstr_v1.json");
    let vectors: KatVectors = serde_json::from_str(raw_json)?;

    // 1. Single-recipient RCENC v1 KAT.
    let rcenc_kat = &vectors.rcenc_v1;
    let seed: [u8; 32] = decode_fixed(&rcenc_kat.seed_hex)?;
    let tenant_id: [u8; 16] = decode_fixed(&rcenc_kat.tenant_id_hex)?;
    let resource_id: [u8; 16] = decode_fixed(&rcenc_kat.resource_id_hex)?;
    let plaintext = hex::decode(&rcenc_kat.plaintext_hex)?;
    let (sk, pk) = XWingSecretKey::from_seed_bytes(seed);
    let ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::from_u8(rcenc_kat.envelope_kind)?,
        tenant_id,
        resource_id,
        privacy_tier: PrivacyTier::from_u8(rcenc_kat.privacy_tier)?,
        schema_version: rcenc_kat.schema_version,
    };
    let mut rng = DeterministicTestRng::from_label(rcenc_kat.rng_label.as_bytes());
    let wire = encrypt_with_rng(
        &mut rng,
        &plaintext,
        &ctx,
        EnvelopeFlags::default(),
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: pk.key_id(),
            key_version: rcenc_kat.key_version,
            public_key: &pk,
        }],
    )?;
    let parsed = parse_envelope(&wire)?;
    let aad = build_canonical_aad(&ctx, parsed.raw_header_and_slots);

    // 2. Multi-recipient compressed RCENC v1 KAT (XWing + Argon2idPassword + RecoveryBip39).
    let multi = &vectors.rcenc_v1_multi_compressed;
    let (m_sk, m_pk) = XWingSecretKey::from_seed_bytes(decode_fixed(&multi.seed_hex)?);
    let m_argon2_kem = hex::decode(&multi.argon2_kem_data_hex)?;
    let m_argon2_kek = SymmetricKey::from_bytes(decode_fixed(&multi.argon2_kek_hex)?);
    let m_rec_kek = SymmetricKey::from_bytes(decode_fixed(&multi.recovery_kek_hex)?);
    let m_pt = hex::decode(&multi.plaintext_hex)?;
    let m_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::PrivateProduct,
        tenant_id: decode_fixed(&multi.tenant_id_hex)?,
        resource_id: decode_fixed(&multi.resource_id_hex)?,
        privacy_tier: PrivacyTier::Flexible,
        schema_version: 1,
    };
    let mut m_rng = DeterministicTestRng::from_label(multi.rng_label.as_bytes());
    let multi_wire = encrypt_with_rng(
        &mut m_rng,
        &m_pt,
        &m_ctx,
        EnvelopeFlags::new(true),
        &[
            RecipientSpec::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: m_pk.key_id(),
                key_version: 2,
                public_key: &m_pk,
            },
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: [0xA1; 16],
                key_version: 1,
                kem_data: &m_argon2_kem,
                kek: &m_argon2_kek,
            },
            RecipientSpec::SymmetricKek {
                recipient_type: RecipientType::RecoveryBip39,
                key_id: [0xB2; 16],
                key_version: 1,
                kem_data: &[],
                kek: &m_rec_kek,
            },
        ],
    )?;

    // 3. Single-chunk RCSTR v1 KAT (flags = 0x02).
    let rcstr_kat = &vectors.rcstr_v1;
    let (s_sk, s_pk) = XWingSecretKey::from_seed_bytes(decode_fixed(&rcstr_kat.seed_hex)?);
    let s_pt = hex::decode(&rcstr_kat.plaintext_hex)?;
    let s_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::PrivateProduct,
        tenant_id: decode_fixed(&rcstr_kat.tenant_id_hex)?,
        resource_id: decode_fixed(&rcstr_kat.file_id_hex)?,
        privacy_tier: PrivacyTier::Strict,
        schema_version: 1,
    };
    let mut s_rng = DeterministicTestRng::from_label(rcstr_kat.rng_label.as_bytes());
    let stream_wire = encrypt_stream_with_rng(
        &mut s_rng,
        &s_pt,
        &s_ctx,
        rcstr_kat.chunk_size,
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: s_pk.key_id(),
            key_version: 1,
            public_key: &s_pk,
        }],
    )?;

    // 4. Multi-chunk RCSTR v1 KAT (exercises chunk_index 0 non-final + chunk_index 1 final).
    let mc = &vectors.rcstr_v1_multi_chunk;
    let (mc_sk, mc_pk) = XWingSecretKey::from_seed_bytes(decode_fixed(&mc.seed_hex)?);
    let mc_pt: Vec<u8> = (0..mc.plaintext_len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let mc_ctx = EnvelopeContext {
        envelope_kind: EnvelopeKind::PrivateProduct,
        tenant_id: decode_fixed(&mc.tenant_id_hex)?,
        resource_id: decode_fixed(&mc.file_id_hex)?,
        privacy_tier: PrivacyTier::Strict,
        schema_version: 1,
    };
    let mut mc_rng = DeterministicTestRng::from_label(mc.rng_label.as_bytes());
    let mc_wire = encrypt_stream_with_rng(
        &mut mc_rng,
        &mc_pt,
        &mc_ctx,
        mc.chunk_size,
        &[RecipientSpec::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: mc_pk.key_id(),
            key_version: 1,
            public_key: &mc_pk,
        }],
    )?;

    assert_eq!(
        blake3::hash(&pk.to_bytes()).to_hex().as_str(),
        rcenc_kat.expected_public_key_blake3_hex
    );
    assert_eq!(wire.len(), rcenc_kat.expected_envelope_len);
    assert_eq!(
        blake3::hash(&wire).to_hex().as_str(),
        rcenc_kat.expected_envelope_blake3_hex
    );
    assert_eq!(hex::encode(aad), rcenc_kat.expected_canonical_aad_hex);
    assert_eq!(
        decrypt(
            &wire,
            &ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: pk.key_id(),
                key_version: rcenc_kat.key_version,
                secret_key: &sk,
            },
        )?
        .plaintext
        .as_slice(),
        plaintext.as_slice()
    );

    assert_eq!(multi_wire.len(), multi.expected_envelope_len);
    assert_eq!(
        blake3::hash(&multi_wire).to_hex().as_str(),
        multi.expected_envelope_blake3_hex
    );
    assert_eq!(
        decrypt(
            &multi_wire,
            &m_ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: m_pk.key_id(),
                key_version: 2,
                secret_key: &m_sk,
            },
        )?
        .plaintext
        .as_slice(),
        m_pt.as_slice()
    );
    assert_eq!(
        decrypt(
            &multi_wire,
            &m_ctx,
            &RecipientCredential::SymmetricKek {
                recipient_type: RecipientType::Argon2idPassword,
                key_id: [0xA1; 16],
                key_version: 1,
                kek: &m_argon2_kek,
            },
        )?
        .plaintext
        .as_slice(),
        m_pt.as_slice()
    );
    assert_eq!(
        decrypt(
            &multi_wire,
            &m_ctx,
            &RecipientCredential::SymmetricKek {
                recipient_type: RecipientType::RecoveryBip39,
                key_id: [0xB2; 16],
                key_version: 1,
                kek: &m_rec_kek,
            },
        )?
        .plaintext
        .as_slice(),
        m_pt.as_slice()
    );

    assert_eq!(stream_wire.len(), rcstr_kat.expected_stream_len);
    assert_eq!(
        blake3::hash(&stream_wire).to_hex().as_str(),
        rcstr_kat.expected_stream_blake3_hex
    );
    assert_eq!(
        decrypt_stream(
            &stream_wire,
            &s_ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: s_pk.key_id(),
                key_version: 1,
                secret_key: &s_sk,
            },
        )?
        .as_slice(),
        s_pt.as_slice()
    );

    assert_eq!(mc_wire.len(), mc.expected_stream_len);
    assert_eq!(
        blake3::hash(&mc_wire).to_hex().as_str(),
        mc.expected_stream_blake3_hex
    );
    assert_eq!(
        decrypt_stream(
            &mc_wire,
            &mc_ctx,
            &RecipientCredential::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id: mc_pk.key_id(),
                key_version: 1,
                secret_key: &mc_sk,
            },
        )?
        .as_slice(),
        mc_pt.as_slice()
    );

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn proptest_rcenc_roundtrip_and_any_single_bit_flip_fails(
        seed in any::<[u8; 32]>(),
        rng_seed in any::<[u8; 16]>(),
        tenant_id in any::<[u8; 16]>(),
        resource_id in any::<[u8; 16]>(),
        kind_idx in 0_u8..6,
        tier_idx in 0_u8..3,
        schema_version in any::<u16>(),
        compressed_zstd in any::<bool>(),
        key_version in 1_u32..=u32::MAX,
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        flip_byte_selector in any::<usize>(),
        flip_bit in 0_u8..8,
    ) {
        let (sk, pk) = XWingSecretKey::from_seed_bytes(seed);
        let kind = EnvelopeKind::from_u8(kind_idx + 1).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let tier = PrivacyTier::from_u8(tier_idx + 1).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let ctx = EnvelopeContext {
            envelope_kind: kind,
            tenant_id,
            resource_id,
            privacy_tier: tier,
            schema_version,
        };
        let flags = EnvelopeFlags::new(compressed_zstd);
        let key_id = pk.key_id();

        let mut rng = DeterministicTestRng::from_label(&rng_seed);
        let wire = encrypt_with_rng(
            &mut rng,
            &plaintext,
            &ctx,
            flags,
            &[RecipientSpec::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id,
                key_version,
                public_key: &pk,
            }],
        ).map_err(|e| TestCaseError::fail(e.to_string()))?;

        let cred = RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id,
            key_version,
            secret_key: &sk,
        };

        let dec = decrypt(&wire, &ctx, &cred).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(dec.plaintext.as_slice(), plaintext.as_slice());
        prop_assert_eq!(dec.header.flags, flags);

        let mut tampered = wire;
        let idx = flip_byte_selector % tampered.len();
        tampered[idx] ^= 1_u8 << flip_bit;
        prop_assert!(decrypt(&tampered, &ctx, &cred).is_err());
    }

    #[test]
    fn proptest_rcstr_roundtrip_and_any_single_bit_flip_fails(
        seed in any::<[u8; 32]>(),
        rng_seed in any::<[u8; 16]>(),
        tenant_id in any::<[u8; 16]>(),
        file_id in any::<[u8; 16]>(),
        plaintext in prop::collection::vec(any::<u8>(), 0..10_000),
        flip_byte_selector in any::<usize>(),
        flip_bit in 0_u8..8,
    ) {
        let (sk, pk) = XWingSecretKey::from_seed_bytes(seed);
        let ctx = EnvelopeContext {
            envelope_kind: EnvelopeKind::PrivateProduct,
            tenant_id,
            resource_id: file_id,
            privacy_tier: PrivacyTier::Strict,
            schema_version: 1,
        };
        let key_id = pk.key_id();

        let mut rng = DeterministicTestRng::from_label(&rng_seed);
        let wire = encrypt_stream_with_rng(
            &mut rng,
            &plaintext,
            &ctx,
            MIN_CHUNK_SIZE,
            &[RecipientSpec::XWing {
                recipient_type: RecipientType::XWingOrgKey,
                key_id,
                key_version: 1,
                public_key: &pk,
            }],
        ).map_err(|e| TestCaseError::fail(e.to_string()))?;

        let cred = RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id,
            key_version: 1,
            secret_key: &sk,
        };

        let dec = decrypt_stream(&wire, &ctx, &cred).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(dec.as_slice(), plaintext.as_slice());

        let mut tampered = wire;
        let idx = flip_byte_selector % tampered.len();
        tampered[idx] ^= 1_u8 << flip_bit;
        prop_assert!(decrypt_stream(&tampered, &ctx, &cred).is_err());
    }

    #[test]
    fn proptest_arbitrary_bytes_never_panic_parsers(
        raw in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let (sk, pk) = XWingSecretKey::from_seed_bytes([0x42; 32]);
        let ctx = sample_ctx(EnvelopeKind::OrderFulfillment, PrivacyTier::Strict);
        let cred = RecipientCredential::XWing {
            recipient_type: RecipientType::XWingOrgKey,
            key_id: pk.key_id(),
            key_version: 1,
            secret_key: &sk,
        };
        let _ = parse_envelope(&raw);
        let _ = decrypt(&raw, &ctx, &cred);
        let _ = decrypt_stream(&raw, &ctx, &cred);
    }
}

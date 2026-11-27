#![forbid(unsafe_code)]
#![allow(clippy::similar_names, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use base64ct::{Base64, Encoding};
use der::asn1::{BitString, GeneralizedTime, Int, OctetString, SetOfVec, Utf8StringRef};
use der::{Any, Decode, Encode, Header, Length, Sequence, Tag};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature as P256DerSig, SigningKey as P256SigningKey};
use p256::pkcs8::EncodePublicKey as _;
use p384::ecdsa::{DerSignature as P384DerSig, SigningKey as P384SigningKey};
use sha2::{Digest, Sha256};
use sovret_crypto_core::{Ed25519SigningKey, SklEntryV1, VaultRole, XWingSecretKey};
use sovret_verify::{
    DEFAULT_GITHUB_OIDC_ISSUER, DEFAULT_SOVRET_SAN_PREFIX, ReleaseManifestV1, SigstorePolicy,
    SigstoreTrustRoot, SklCheckpointJson, SklDocumentJson, ToolchainVersions, VerifyError,
    audit_csp_header, audit_csp_headers, audit_html_scripts, audit_live_site,
    audit_page_content_type, build_docker_rebuild_args, compute_sha256_hex, compute_sri_sha384,
    extract_origin, hash_manifest_artifact, parse_checkpoint_json, parse_rfc3339_utc_unix,
    skl_entry_to_json, verify_merkle_inclusion_proof, verify_rebuilt_directory,
    verify_served_artifact, verify_sigstore_bundle, verify_skl_document,
};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_FULCIO_ISSUER_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
const OID_FULCIO_SOURCE_REPO_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.13");
const OID_CMS_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_CMS_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_CMS_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_TST_POLICY_TEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.1");

#[derive(Sequence)]
struct RawTbsCertificate {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: Version,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Vec<Extension>>,
}

#[derive(Sequence)]
struct RawX509Certificate {
    tbs_certificate: RawTbsCertificate,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

#[derive(Sequence)]
struct TestMessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(Sequence)]
struct TestTstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: TestMessageImprint,
    serial_number: Int,
    gen_time: GeneralizedTime,
}

#[derive(Sequence)]
struct TestCmsAttr {
    attr_type: ObjectIdentifier,
    attr_values: SetOfVec<Any>,
}

#[derive(Sequence)]
struct TestIssuerAndSerial {
    issuer: Name,
    serial_number: SerialNumber,
}

#[derive(Sequence)]
struct TestEncapContentInfo {
    e_content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    e_content: OctetString,
}

#[derive(Sequence)]
struct TestContentInfo {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: Any,
}

fn unix_time(secs: u64) -> Result<Time, Box<dyn std::error::Error>> {
    Ok(Time::from(der::DateTime::from_unix_duration(
        std::time::Duration::from_secs(secs),
    )?))
}

fn build_test_ca_cert(
    ca_sk: &P384SigningKey,
    cn: &str,
    not_before: u64,
    not_after: u64,
) -> Result<(Certificate, Vec<u8>), Box<dyn std::error::Error>> {
    let spki_der = ca_sk.verifying_key().to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
    let name: Name = format!("CN={cn}").parse()?;
    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: Some(1),
    };
    let ku = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
    let exts = vec![
        Extension {
            extn_id: OID_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(bc.to_der()?)?,
        },
        Extension {
            extn_id: OID_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(ku.to_der()?)?,
        },
    ];
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA384,
        parameters: None,
    };
    let tbs = RawTbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1])?,
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity: Validity::new(unix_time(not_before)?, unix_time(not_after)?),
        subject: name,
        subject_public_key_info: spki,
        extensions: Some(exts),
    };
    let tbs_der = tbs.to_der()?;
    let sig: P384DerSig = ca_sk.sign(&tbs_der);
    let raw_cert = RawX509Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(sig.as_bytes())?,
    };
    let der = raw_cert.to_der()?;
    let cert = Certificate::from_der(&der)?;
    Ok((cert, der))
}

fn build_test_tsa_leaf(
    tsa_ca_sk: &P384SigningKey,
    tsa_ca_cert: &Certificate,
    tsa_leaf_sk: &P256SigningKey,
    not_before: u64,
    not_after: u64,
) -> Result<(Certificate, Vec<u8>), Box<dyn std::error::Error>> {
    let spki_der = tsa_leaf_sk.verifying_key().to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
    let subject: Name = "CN=test-sigstore-tsa".parse()?;
    let exts = vec![
        Extension {
            extn_id: OID_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(
                BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                }
                .to_der()?,
            )?,
        },
        Extension {
            extn_id: OID_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(KeyUsage(KeyUsages::DigitalSignature.into()).to_der()?)?,
        },
        Extension {
            extn_id: OID_EXT_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(ExtendedKeyUsage(vec![OID_KP_TIME_STAMPING]).to_der()?)?,
        },
    ];
    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA384,
        parameters: None,
    };
    let tbs = RawTbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[7])?,
        signature: sig_alg.clone(),
        issuer: tsa_ca_cert.tbs_certificate().subject().clone(),
        validity: Validity::new(unix_time(not_before)?, unix_time(not_after)?),
        subject,
        subject_public_key_info: spki,
        extensions: Some(exts),
    };
    let tbs_der = tbs.to_der()?;
    let sig: P384DerSig = tsa_ca_sk.sign(&tbs_der);
    let raw = RawX509Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(sig.as_bytes())?,
    };
    let der = raw.to_der()?;
    let cert = Certificate::from_der(&der)?;
    Ok((cert, der))
}

/// Builds a real DER RFC 3161 `TimeStampToken` (CMS `ContentInfo` `SignedData` encapsulating
/// `TSTInfo` over `SHA-256(artifact_signature)`) signed by `tsa_leaf_sk`.
fn build_real_rfc3161_token(
    tsa_leaf_sk: &P256SigningKey,
    tsa_leaf_cert: &Certificate,
    artifact_signature: &[u8],
    gen_time_unix: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sig_hash = Sha256::digest(artifact_signature);
    let tst = TestTstInfo {
        version: 1,
        policy: OID_TST_POLICY_TEST,
        message_imprint: TestMessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: OID_SHA256,
                parameters: None,
            },
            hashed_message: OctetString::new(sig_hash.as_slice())?,
        },
        serial_number: Int::new(&[1])?,
        gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            gen_time_unix,
        ))?,
    };
    let tst_der = tst.to_der()?;
    let tst_hash = Sha256::digest(&tst_der);

    let mut ct_vals = SetOfVec::new();
    ct_vals.insert(Any::from_der(&OID_ID_CT_TST_INFO.to_der()?)?)?;
    let attr_ct = TestCmsAttr {
        attr_type: OID_CMS_CONTENT_TYPE,
        attr_values: ct_vals,
    };

    let mut md_vals = SetOfVec::new();
    md_vals.insert(Any::from_der(
        &OctetString::new(tst_hash.as_slice())?.to_der()?,
    )?)?;
    let attr_md = TestCmsAttr {
        attr_type: OID_CMS_MESSAGE_DIGEST,
        attr_values: md_vals,
    };

    let mut signed_attrs_set = SetOfVec::new();
    signed_attrs_set.insert(Any::from_der(&attr_ct.to_der()?)?)?;
    signed_attrs_set.insert(Any::from_der(&attr_md.to_der()?)?)?;
    let signed_attrs_set_der = signed_attrs_set.to_der()?;
    let tsa_sig: P256DerSig = tsa_leaf_sk.sign(&signed_attrs_set_der);

    // Build `[0] IMPLICIT signedAttrs` from the inner bytes of the DER SET.
    let signed_attrs_inner = Any::from_der(&signed_attrs_set_der)?;
    let mut implicit_attrs = Vec::new();
    // Context-specific constructed tag 0 = 0xA0.
    implicit_attrs.push(0xA0_u8);
    Length::try_from(signed_attrs_inner.value().len())?.encode_to_vec(&mut implicit_attrs)?;
    implicit_attrs.extend_from_slice(signed_attrs_inner.value());

    let sid = TestIssuerAndSerial {
        issuer: tsa_leaf_cert.tbs_certificate().issuer().clone(),
        serial_number: tsa_leaf_cert.tbs_certificate().serial_number().clone(),
    };
    let sha256_alg = AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: None,
    };
    let ecdsa_sha256_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA256,
        parameters: None,
    };

    // Assemble SignerInfo SEQUENCE manually so `[0] IMPLICIT` is exact.
    let mut si_body = Vec::new();
    1_u8.encode_to_vec(&mut si_body)?;
    sid.encode_to_vec(&mut si_body)?;
    sha256_alg.encode_to_vec(&mut si_body)?;
    si_body.extend_from_slice(&implicit_attrs);
    ecdsa_sha256_alg.encode_to_vec(&mut si_body)?;
    OctetString::new(tsa_sig.as_bytes())?.encode_to_vec(&mut si_body)?;

    let mut si_seq = Vec::new();
    Header::new(Tag::Sequence, Length::try_from(si_body.len())?).encode_to_vec(&mut si_seq)?;
    si_seq.extend_from_slice(&si_body);

    let mut si_set = Vec::new();
    Header::new(Tag::Set, Length::try_from(si_seq.len())?).encode_to_vec(&mut si_set)?;
    si_set.extend_from_slice(&si_seq);

    let mut digest_algs = SetOfVec::new();
    digest_algs.insert(sha256_alg)?;
    let encap = TestEncapContentInfo {
        e_content_type: OID_ID_CT_TST_INFO,
        e_content: OctetString::new(tst_der)?,
    };

    let mut sd_body = Vec::new();
    3_u8.encode_to_vec(&mut sd_body)?;
    digest_algs.encode_to_vec(&mut sd_body)?;
    encap.encode_to_vec(&mut sd_body)?;
    sd_body.extend_from_slice(&si_set);

    let mut sd_seq = Vec::new();
    Header::new(Tag::Sequence, Length::try_from(sd_body.len())?).encode_to_vec(&mut sd_seq)?;
    sd_seq.extend_from_slice(&sd_body);

    let ci = TestContentInfo {
        content_type: OID_CMS_SIGNED_DATA,
        content: Any::from_der(&sd_seq)?,
    };
    Ok(ci.to_der()?)
}

#[allow(clippy::too_many_arguments)]
fn build_test_fulcio_leaf(
    ca_sk: &P384SigningKey,
    ca_cert: &Certificate,
    leaf_sk: &P256SigningKey,
    not_before: u64,
    not_after: u64,
    oidc_issuer: &str,
    san_uri: &str,
    git_commit: Option<&str>,
    include_code_signing_eku: bool,
    mark_as_ca: bool,
    extra_unknown_critical_ext: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let spki_der = leaf_sk.verifying_key().to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
    let subject: Name = "CN=sovret-ephemeral".parse()?;

    let mut exts = vec![
        Extension {
            extn_id: OID_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(
                BasicConstraints {
                    ca: mark_as_ca,
                    path_len_constraint: None,
                }
                .to_der()?,
            )?,
        },
        Extension {
            extn_id: OID_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(KeyUsage(KeyUsages::DigitalSignature.into()).to_der()?)?,
        },
    ];

    if include_code_signing_eku {
        exts.push(Extension {
            extn_id: OID_EXT_KEY_USAGE,
            critical: false,
            extn_value: OctetString::new(ExtendedKeyUsage(vec![OID_KP_CODE_SIGNING]).to_der()?)?,
        });
    }

    let san = SubjectAltName(vec![GeneralName::UniformResourceIdentifier(
        der::asn1::Ia5String::new(san_uri)?,
    )]);
    exts.push(Extension {
        extn_id: OID_SUBJECT_ALT_NAME,
        critical: false,
        extn_value: OctetString::new(san.to_der()?)?,
    });

    let issuer_utf8 = Utf8StringRef::new(oidc_issuer)?.to_der()?;
    exts.push(Extension {
        extn_id: OID_FULCIO_ISSUER_V2,
        critical: false,
        extn_value: OctetString::new(issuer_utf8)?,
    });

    if let Some(commit) = git_commit {
        exts.push(Extension {
            extn_id: OID_FULCIO_SOURCE_REPO_DIGEST,
            critical: false,
            extn_value: OctetString::new(Utf8StringRef::new(commit)?.to_der()?)?,
        });
    }

    if extra_unknown_critical_ext {
        exts.push(Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9"),
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00])?,
        });
    }

    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA384,
        parameters: None,
    };
    let tbs = RawTbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[2])?,
        signature: sig_alg.clone(),
        issuer: ca_cert.tbs_certificate().subject().clone(),
        validity: Validity::new(unix_time(not_before)?, unix_time(not_after)?),
        subject,
        subject_public_key_info: spki,
        extensions: Some(exts),
    };
    let tbs_der = tbs.to_der()?;
    let sig: P384DerSig = ca_sk.sign(&tbs_der);
    let raw_cert = RawX509Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(sig.as_bytes())?,
    };
    Ok(raw_cert.to_der()?)
}

fn ed25519_spki_der(vk_bytes: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_ED25519,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(vk_bytes)?,
    };
    Ok(spki.to_der()?)
}

fn build_rfc6962_merkle_proof(leaves: &[&[u8]], leaf_idx: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00_u8]);
        h.update(data);
        h.finalize().into()
    }
    fn hash_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01_u8]);
        h.update(l);
        h.update(r);
        h.finalize().into()
    }
    fn tree_hash(hashes: &[[u8; 32]]) -> [u8; 32] {
        match hashes.len() {
            1 => hashes[0],
            n => {
                let k = n.next_power_of_two() >> 1;
                hash_node(&tree_hash(&hashes[..k]), &tree_hash(&hashes[k..]))
            }
        }
    }
    fn proof(hashes: &[[u8; 32]], idx: usize, out: &mut Vec<[u8; 32]>) {
        let n = hashes.len();
        if n <= 1 {
            return;
        }
        let k = n.next_power_of_two() >> 1;
        if idx < k {
            proof(&hashes[..k], idx, out);
            out.push(tree_hash(&hashes[k..]));
        } else {
            proof(&hashes[k..], idx - k, out);
            out.push(tree_hash(&hashes[..k]));
        }
    }

    let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|d| hash_leaf(d)).collect();
    let root = tree_hash(&leaf_hashes);
    let mut p = Vec::new();
    proof(&leaf_hashes, leaf_idx, &mut p);
    (root, p)
}

type SampleManifestBundle = (ReleaseManifestV1, Vec<u8>, Vec<u8>);

fn sample_manifest() -> Result<SampleManifestBundle, Box<dyn std::error::Error>> {
    let js_bytes = b"export async function init() { return true; }\n".to_vec();
    let wasm_bytes = b"\0asm\x01\0\0\0sovret-test-wasm-payload".to_vec();
    let manifest = ReleaseManifestV1::build_from_artifacts(
        "0.1.0".to_owned(),
        "0123456789abcdef0123456789abcdef01234567".to_owned(),
        1_795_400_000,
        "sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b".to_owned(),
        ToolchainVersions {
            rustc: "1.97.1".to_owned(),
            wasm_bindgen_cli: "0.2.130".to_owned(),
            binaryen: "version_133".to_owned(),
        },
        vec![
            hash_manifest_artifact(
                "/assets/v0.1.0/sovret_crypto_wasm.js".to_owned(),
                "text/javascript".to_owned(),
                &js_bytes,
            ),
            hash_manifest_artifact(
                "/assets/v0.1.0/sovret_crypto_wasm_bg.wasm".to_owned(),
                "application/wasm".to_owned(),
                &wasm_bytes,
            ),
        ],
    )?;
    Ok((manifest, js_bytes, wasm_bytes))
}

#[test]
fn embedded_sigstore_public_good_trust_root_and_strict_rfc3339_dates()
-> Result<(), Box<dyn std::error::Error>> {
    let tr = SigstoreTrustRoot::public_good()?;
    assert!(tr.tlog_count() >= 2, "expected Rekor v1 + Rekor v2 tlogs");
    assert!(tr.ca_count() >= 2, "expected Fulcio CA chains");
    assert!(tr.tsa_count() >= 1, "expected Sigstore TSA chain");

    assert_eq!(parse_rfc3339_utc_unix("1970-01-01T00:00:00Z")?, 0);
    assert_eq!(
        parse_rfc3339_utc_unix("2024-02-29T12:00:00Z")?,
        1_709_208_000
    );
    assert_eq!(
        parse_rfc3339_utc_unix("2025-09-23T00:00:00Z")?,
        1_758_585_600
    );
    assert_eq!(
        parse_rfc3339_utc_unix("2022-12-31T23:59:59.999Z")?,
        1_672_531_199
    );

    // Impossible dates, non-leap Feb 29, garbage fractions, and overflow years rejected.
    for bad in [
        "2026-02-29T00:00:00Z",
        "2026-02-31T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-01-01T00:00:00.garbageZ",
        "99999999999999999-01-01T00:00:00Z",
        "1969-12-31T23:59:59Z",
    ] {
        assert!(
            parse_rfc3339_utc_unix(bad).is_err(),
            "expected reject: {bad}"
        );
    }
    Ok(())
}

#[test]
fn rfc6962_merkle_inclusion_proof_exhaustive_sizes_1_to_25()
-> Result<(), Box<dyn std::error::Error>> {
    let raw_items: Vec<Vec<u8>> = (0..25_u8)
        .map(|i| format!("rekor-v2-entry-{i}").into_bytes())
        .collect();
    for tree_size in 1..=25_usize {
        let slice_refs: Vec<&[u8]> = raw_items[..tree_size].iter().map(Vec::as_slice).collect();
        for leaf_idx in 0..tree_size {
            let (root, proof) = build_rfc6962_merkle_proof(&slice_refs, leaf_idx);
            verify_merkle_inclusion_proof(
                slice_refs[leaf_idx],
                u64::try_from(leaf_idx)?,
                u64::try_from(tree_size)?,
                &proof,
                &root,
            )?;

            let mut tampered = slice_refs[leaf_idx].to_vec();
            tampered[0] ^= 0x01;
            assert!(
                verify_merkle_inclusion_proof(
                    &tampered,
                    u64::try_from(leaf_idx)?,
                    u64::try_from(tree_size)?,
                    &proof,
                    &root
                )
                .is_err()
            );

            let mut with_extra = proof.clone();
            with_extra.push([0xAA_u8; 32]);
            assert!(
                verify_merkle_inclusion_proof(
                    slice_refs[leaf_idx],
                    u64::try_from(leaf_idx)?,
                    u64::try_from(tree_size)?,
                    &with_extra,
                    &root
                )
                .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn sigstore_rekor_v2_tsa_and_rekor_v1_set_verification_and_attacks()
-> Result<(), Box<dyn std::error::Error>> {
    let (manifest, _js, _wasm) = sample_manifest()?;
    let manifest_bytes = manifest.to_canonical_json()?.into_bytes();
    let manifest_sha256: [u8; 32] = Sha256::digest(&manifest_bytes).into();

    // Real Fulcio Root CA + P-256 ephemeral leaf cert (with Source Repository Digest OID .13).
    let ca_sk = P384SigningKey::from_slice(&[0x42_u8; 48])?;
    let (ca_cert, ca_der) =
        build_test_ca_cert(&ca_sk, "Test Fulcio Root CA", 1_700_000_000, 1_900_000_000)?;
    let leaf_sk = P256SigningKey::from_slice(&[0x24_u8; 32])?;
    let san_uri = format!("{DEFAULT_SOVRET_SAN_PREFIX}v{}", manifest.release_version);
    let signing_ts = 1_795_400_300_u64;
    let leaf_der = build_test_fulcio_leaf(
        &ca_sk,
        &ca_cert,
        &leaf_sk,
        1_795_400_000,
        1_795_400_600,
        DEFAULT_GITHUB_OIDC_ISSUER,
        &san_uri,
        Some(&manifest.git_commit),
        true,
        false,
        false,
    )?;
    let blob_sig: P256DerSig = leaf_sk.sign(&manifest_bytes);

    // Real RFC 3161 TSA CA + TSA signer cert + real CMS SignedData TimeStampToken over blob_sig.
    let tsa_ca_sk = P384SigningKey::from_slice(&[0x53_u8; 48])?;
    let (tsa_ca_cert, tsa_ca_der) = build_test_ca_cert(
        &tsa_ca_sk,
        "Test Sigstore TSA Root",
        1_700_000_000,
        1_900_000_000,
    )?;
    let tsa_leaf_sk = P256SigningKey::from_slice(&[0x64_u8; 32])?;
    let (tsa_leaf_cert, tsa_leaf_der) = build_test_tsa_leaf(
        &tsa_ca_sk,
        &tsa_ca_cert,
        &tsa_leaf_sk,
        1_700_000_000,
        1_900_000_000,
    )?;
    let rfc3161_der = build_real_rfc3161_token(
        &tsa_leaf_sk,
        &tsa_leaf_cert,
        blob_sig.as_bytes(),
        signing_ts,
    )?;

    // Real Rekor v2 Ed25519 log key (C2SP keyId = SHA-256(origin || "\n" || 0x01 || raw32)).
    let (rekor_ed_sk, rekor_ed_vk) = Ed25519SigningKey::from_seed_slice(&[0x77_u8; 32])?;
    let rekor_spki_der = ed25519_spki_der(&rekor_ed_vk.to_bytes())?;
    let mut c2sp_hasher = Sha256::new();
    c2sp_hasher.update(b"log2025-1.rekor.sigstore.dev\n\x01");
    c2sp_hasher.update(rekor_ed_vk.to_bytes());
    let rekor_log_id: [u8; 32] = c2sp_hasher.finalize().into();

    // Real Rekor v1 P-256 log key.
    let rekor_v1_sk = P256SigningKey::from_slice(&[0x88_u8; 32])?;
    let rekor_v1_spki = rekor_v1_sk.verifying_key().to_public_key_der()?;
    let rekor_v1_log_id: [u8; 32] = Sha256::digest(rekor_v1_spki.as_bytes()).into();

    let trust_root_json = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "baseUrl": "https://log2025-1.rekor.sigstore.dev",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": Base64::encode_string(&rekor_spki_der),
                    "keyDetails": "PKIX_ED25519",
                    "validFor": { "start": "2025-09-23T00:00:00Z" }
                },
                "logId": { "keyId": Base64::encode_string(&rekor_log_id) }
            },
            {
                "baseUrl": "https://rekor.sigstore.dev",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": Base64::encode_string(rekor_v1_spki.as_bytes()),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": { "start": "2021-01-12T11:53:27Z" }
                },
                "logId": { "keyId": Base64::encode_string(&rekor_v1_log_id) }
            }
        ],
        "certificateAuthorities": [{
            "uri": "https://fulcio.sigstore.dev",
            "certChain": { "certificates": [{ "rawBytes": Base64::encode_string(&ca_der) }] },
            "validFor": { "start": "2024-01-01T00:00:00Z" }
        }],
        "timestampAuthorities": [{
            "uri": "https://timestamp.sigstore.dev/api/v1/timestamp",
            "certChain": {
                "certificates": [
                    { "rawBytes": Base64::encode_string(&tsa_leaf_der) },
                    { "rawBytes": Base64::encode_string(&tsa_ca_der) }
                ]
            },
            "validFor": { "start": "2025-07-04T00:00:00Z" }
        }]
    });
    let trust_root = SigstoreTrustRoot::from_json_bytes(trust_root_json.to_string().as_bytes())?;

    // 1. Rekor v2 bundle (`integratedTime` omitted, authenticated via real RFC 3161 TSA token!).
    let v2_body = serde_json::json!({
        "apiVersion": "0.0.2",
        "kind": "hashedrekord",
        "spec": {
            "hashedRekordV002": {
                "data": {
                    "algorithm": "SHA2_256",
                    "digest": Base64::encode_string(&manifest_sha256)
                },
                "signature": {
                    "content": Base64::encode_string(blob_sig.as_bytes()),
                    "verifier": {
                        "x509Certificate": { "rawBytes": Base64::encode_string(&leaf_der) }
                    }
                }
            }
        }
    })
    .to_string()
    .into_bytes();

    let leaves: [&[u8]; 7] = [
        b"other-0", b"other-1", b"other-2", b"other-3", &v2_body, b"other-5", b"other-6",
    ];
    let (root_hash, proof_hashes) = build_rfc6962_merkle_proof(&leaves, 4);

    let note_body = format!(
        "log2025-1.rekor.sigstore.dev\n7\n{}",
        Base64::encode_string(&root_hash)
    );
    let ckpt_sig = rekor_ed_sk.sign(format!("{note_body}\n").as_bytes());
    let mut ckpt_payload = Vec::with_capacity(68);
    ckpt_payload.extend_from_slice(&rekor_log_id[..4]);
    ckpt_payload.extend_from_slice(&ckpt_sig);
    let checkpoint_envelope = format!(
        "{note_body}\n\n\u{2014} log2025-1.rekor.sigstore.dev {}\n",
        Base64::encode_string(&ckpt_payload)
    );

    let bundle_v3 = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": { "rawBytes": Base64::encode_string(&leaf_der) },
            "timestampVerificationData": {
                "rfc3161Timestamps": [{ "signedTimestamp": Base64::encode_string(&rfc3161_der) }]
            },
            "tlogEntries": [{
                "logIndex": "4",
                "logId": { "keyId": Base64::encode_string(&rekor_log_id) },
                "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
                "canonicalizedBody": Base64::encode_string(&v2_body),
                "inclusionProof": {
                    "logIndex": "4",
                    "rootHash": Base64::encode_string(&root_hash),
                    "treeSize": "7",
                    "hashes": proof_hashes.iter().map(|h| Base64::encode_string(h)).collect::<Vec<_>>(),
                    "checkpoint": { "envelope": checkpoint_envelope }
                }
            }]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": Base64::encode_string(&manifest_sha256)
            },
            "signature": Base64::encode_string(blob_sig.as_bytes())
        }
    });
    let bundle_bytes = bundle_v3.to_string().into_bytes();

    // Strict manifest-bound policy binds BOTH exact SAN tag AND git_commit OID .13!
    let policy = SigstorePolicy::for_manifest(
        DEFAULT_GITHUB_OIDC_ISSUER.to_owned(),
        DEFAULT_SOVRET_SAN_PREFIX.to_owned(),
        &manifest,
    )?;
    let att = verify_sigstore_bundle(&manifest_bytes, &bundle_bytes, &trust_root, &policy)?;
    assert_eq!(att.log_index, 4);
    assert_eq!(att.tree_size, 7);
    assert_eq!(att.verified_timestamp, i64::try_from(signing_ts)?);
    assert_eq!(att.san_uri, san_uri);
    assert_eq!(
        att.source_repo_digest.as_deref(),
        Some(manifest.git_commit.as_str())
    );

    // 2. Rekor v1 bundle authenticated via real `inclusionPromise.signedEntryTimestamp` (SET).
    let leaf_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        Base64::encode_string(&leaf_der)
    );
    let v1_body = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": { "hash": { "algorithm": "sha256", "value": hex::encode(manifest_sha256) } },
            "signature": {
                "content": Base64::encode_string(blob_sig.as_bytes()),
                "publicKey": { "content": Base64::encode_string(leaf_pem.as_bytes()) }
            }
        }
    })
    .to_string()
    .into_bytes();
    let v1_body_b64 = Base64::encode_string(&v1_body);
    let set_canonical = format!(
        r#"{{"body":"{v1_body_b64}","integratedTime":{signing_ts},"logID":"{}","logIndex":0}}"#,
        hex::encode(rekor_v1_log_id)
    );
    let set_sig: P256DerSig = rekor_v1_sk.sign(set_canonical.as_bytes());
    let (v1_root, v1_proof) = build_rfc6962_merkle_proof(&[&v1_body], 0);
    let v1_note = format!(
        "rekor.sigstore.dev - 1193050959916656506\n1\n{}",
        Base64::encode_string(&v1_root)
    );
    let v1_ckpt_sig: P256DerSig = rekor_v1_sk.sign(format!("{v1_note}\n").as_bytes());
    let mut v1_ckpt_payload = Vec::new();
    v1_ckpt_payload.extend_from_slice(&rekor_v1_log_id[..4]);
    v1_ckpt_payload.extend_from_slice(v1_ckpt_sig.as_bytes());
    let v1_bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [{ "rawBytes": Base64::encode_string(&leaf_der) }]
            },
            "tlogEntries": [{
                "logIndex": 0,
                "logId": { "keyId": Base64::encode_string(&rekor_v1_log_id) },
                "kindVersion": { "kind": "hashedrekord", "version": "0.0.1" },
                "integratedTime": signing_ts,
                "canonicalizedBody": v1_body_b64,
                "inclusionPromise": {
                    "signedEntryTimestamp": Base64::encode_string(set_sig.as_bytes())
                },
                "inclusionProof": {
                    "logIndex": 0,
                    "rootHash": Base64::encode_string(&v1_root),
                    "treeSize": 1,
                    "hashes": v1_proof.iter().map(|h| Base64::encode_string(h)).collect::<Vec<_>>(),
                    "checkpoint": {
                        "envelope": format!(
                            "{v1_note}\n\n\u{2014} rekor.sigstore.dev {}\n",
                            Base64::encode_string(&v1_ckpt_payload)
                        )
                    }
                }
            }]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": Base64::encode_string(&manifest_sha256)
            },
            "signature": Base64::encode_string(blob_sig.as_bytes())
        }
    });
    let att_v1 = verify_sigstore_bundle(
        &manifest_bytes,
        v1_bundle.to_string().as_bytes(),
        &trust_root,
        &policy,
    )?;
    assert_eq!(att_v1.tlog_base_url, "https://rekor.sigstore.dev");

    // Attack 1 (Critical #1 regression): Unsigned `integratedTime` with NO TSA and NO SET MUST FAIL!
    let mut unsigned_ts_bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)?;
    unsigned_ts_bundle["verificationMaterial"]["timestampVerificationData"] = serde_json::json!({});
    unsigned_ts_bundle["verificationMaterial"]["tlogEntries"][0]["integratedTime"] =
        serde_json::json!(signing_ts);
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            unsigned_ts_bundle.to_string().as_bytes(),
            &trust_root,
            &policy
        )
        .is_err()
    );

    // Attack 2 (Critical #1 regression): Rewriting Rekor v1 `integratedTime` breaks SET verification!
    let mut forged_set_ts = v1_bundle.clone();
    forged_set_ts["verificationMaterial"]["tlogEntries"][0]["integratedTime"] =
        serde_json::json!(signing_ts + 1);
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            forged_set_ts.to_string().as_bytes(),
            &trust_root,
            &policy
        )
        .is_err()
    );

    // Attack 3 (Critical #1 regression): Valid TSA timestamp outside Fulcio leaf cert validity fails!
    let expired_tsa = build_real_rfc3161_token(
        &tsa_leaf_sk,
        &tsa_leaf_cert,
        blob_sig.as_bytes(),
        1_795_499_999,
    )?;
    let mut expired_tsa_bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)?;
    expired_tsa_bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
        [0]["signedTimestamp"] = serde_json::json!(Base64::encode_string(&expired_tsa));
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            expired_tsa_bundle.to_string().as_bytes(),
            &trust_root,
            &policy
        )
        .is_err()
    );

    // Attack 4 (High #5 regression): Unknown critical X.509 extension on leaf cert rejected.
    let crit_ext_leaf = build_test_fulcio_leaf(
        &ca_sk,
        &ca_cert,
        &leaf_sk,
        1_795_400_000,
        1_795_400_600,
        DEFAULT_GITHUB_OIDC_ISSUER,
        &san_uri,
        Some(&manifest.git_commit),
        true,
        false,
        true,
    )?;
    let mut crit_bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)?;
    crit_bundle["verificationMaterial"]["certificate"]["rawBytes"] =
        serde_json::json!(Base64::encode_string(&crit_ext_leaf));
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            crit_bundle.to_string().as_bytes(),
            &trust_root,
            &policy
        )
        .is_err()
    );

    // Attack 5 (High #6 + Finding #11 regression): Wrong git commit OR wrong SAN tag fails
    // manifest policy, and SigstorePolicy::new_exact rejects loose/invalid prefixes or issuers.
    let bad_commit_policy = SigstorePolicy::new_exact(
        DEFAULT_GITHUB_OIDC_ISSUER.to_owned(),
        DEFAULT_SOVRET_SAN_PREFIX.to_owned(),
        san_uri.clone(),
        "ffffffffffffffffffffffffffffffffffffffff".to_owned(),
    )?;
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            &bundle_bytes,
            &trust_root,
            &bad_commit_policy
        )
        .is_err()
    );
    // Delimiter-free SAN prefix, non-HTTPS issuer, and non-40-hex commit fail at construction.
    assert!(
        SigstorePolicy::new_exact(
            DEFAULT_GITHUB_OIDC_ISSUER.to_owned(),
            "https://github.com/sovret/sovret-crypto".to_owned(),
            san_uri.clone(),
            manifest.git_commit.clone(),
        )
        .is_err()
    );
    assert!(
        SigstorePolicy::new_exact(
            "http://token.actions.githubusercontent.com".to_owned(),
            DEFAULT_SOVRET_SAN_PREFIX.to_owned(),
            san_uri.clone(),
            manifest.git_commit.clone(),
        )
        .is_err()
    );
    assert!(
        SigstorePolicy::new_exact(
            DEFAULT_GITHUB_OIDC_ISSUER.to_owned(),
            DEFAULT_SOVRET_SAN_PREFIX.to_owned(),
            san_uri,
            "not-a-commit".to_owned(),
        )
        .is_err()
    );

    // Duplicate JSON key smuggling in Sigstore bundle rejected (Finding #14).
    let bundle_str = String::from_utf8(bundle_bytes.clone())?;
    let dup_bundle = format!(
        r#"{{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",{}"#,
        &bundle_str[1..]
    );
    assert!(
        verify_sigstore_bundle(&manifest_bytes, dup_bundle.as_bytes(), &trust_root, &policy)
            .is_err()
    );

    // Attack 6 (Medium #9 regression): Wrong C2SP checkpoint origin or wrong 4-byte key hint fails.
    let wrong_origin_note = format!(
        "evil.rekor.example\n7\n{}",
        Base64::encode_string(&root_hash)
    );
    let wrong_origin_sig = rekor_ed_sk.sign(format!("{wrong_origin_note}\n").as_bytes());
    let mut wrong_origin_payload = Vec::with_capacity(68);
    wrong_origin_payload.extend_from_slice(&rekor_log_id[..4]);
    wrong_origin_payload.extend_from_slice(&wrong_origin_sig);
    let mut bad_origin_bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)?;
    bad_origin_bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"] =
        serde_json::json!(format!(
            "{wrong_origin_note}\n\n\u{2014} evil.rekor.example {}\n",
            Base64::encode_string(&wrong_origin_payload)
        ));
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            bad_origin_bundle.to_string().as_bytes(),
            &trust_root,
            &policy
        )
        .is_err()
    );

    let mut wrong_hint_payload = ckpt_payload;
    wrong_hint_payload[0] ^= 0xFF;
    let mut bad_hint_bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)?;
    bad_hint_bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"] =
        serde_json::json!(format!(
            "{note_body}\n\n\u{2014} log2025-1.rekor.sigstore.dev {}\n",
            Base64::encode_string(&wrong_hint_payload)
        ));
    assert!(
        verify_sigstore_bundle(
            &manifest_bytes,
            bad_hint_bundle.to_string().as_bytes(),
            &trust_root,
            &policy
        )
        .is_err()
    );

    Ok(())
}

#[test]
fn csp_allowlist_and_html5_smuggling_defenses() -> Result<(), Box<dyn std::error::Error>> {
    let (manifest, js_bytes, wasm_bytes) = sample_manifest()?;
    let js_sri = compute_sri_sha384(&js_bytes);

    // Strict allowlist CSP passes (including `'wasm-unsafe-eval'` + multi-header intersection).
    audit_csp_header(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; script-src-elem 'self'; script-src-attr 'none'; object-src 'none'; base-uri 'none'; worker-src 'none'; connect-src 'self'",
    )?;
    audit_csp_headers(&[
        "default-src 'self'",
        "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; worker-src 'none'",
    ])?;

    // CSP attacks (Critical #2 regressions): comma-splitting, script-src-elem/attr overrides,
    // external HTTPS hosts, nonces, hashes, missing worker-src fallback!
    for bad_csp in [
        "",
        "default-src 'none'; script-src 'self' https://evil.example; object-src 'none'; base-uri 'none'; worker-src 'none'",
        "default-src 'none'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'none'; worker-src 'none'",
        "default-src 'none'; script-src 'self' 'sha256-abcdef'; object-src 'none'; base-uri 'none'; worker-src 'none'",
        "default-src 'none'; script-src 'self'; script-src-elem 'unsafe-inline'; object-src 'none'; base-uri 'none'; worker-src 'none'",
        "default-src 'none'; script-src 'self'; script-src-attr 'unsafe-inline'; object-src 'none'; base-uri 'none'; worker-src 'none'",
        // Missing worker-src falls back to script-src 'self' -> MUST FAIL!
        "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'",
        // Comma-smuggled multi-policy with permissive second policy and weak first policy -> MUST FAIL!
        "x foo, script-src 'unsafe-inline' https://evil.example; default-src 'none'; object-src 'none'; base-uri 'none'; worker-src 'none'",
        // Duplicate directive -> MUST FAIL!
        "default-src 'none'; script-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; worker-src 'none'",
    ] {
        assert!(
            audit_csp_header(bad_csp).is_err(),
            "expected CSP reject: {bad_csp}"
        );
    }

    // Valid checkout HTML passes.
    let good_html = format!(
        r#"<!doctype html>
<html>
<head>
  <title>Sovret Checkout</title>
  <!-- <script>inert inside comment</script> -->
  <script type="application/ld+json">{{"@type":"Product","name":"Widget"}}</script>
  <script type="module" src="/assets/v0.1.0/sovret_crypto_wasm.js" integrity="{js_sri}" crossorigin="anonymous"></script>
</head>
<body><main>Checkout</main></body>
</html>"#
    );
    let scripts = audit_html_scripts(&good_html, &manifest)?;
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].src_path, "/assets/v0.1.0/sovret_crypto_wasm.js");

    // ALL Critical #3 HTML5 smuggling & XSS vectors MUST FAIL:
    let bad_htmls = [
        // 1. Abruptly / bang-closed comments (`<!-->` and `--!>`).
        "<!--><script>alert(1)</script><!-- -->".to_owned(),
        "<!-- comment --!><script>alert(1)</script><!-- -->".to_owned(),
        // 2. RCDATA/RAWTEXT state switch attacks (`<title>`, `<style>`).
        "<title><!--</title><script>alert(1)</script><!-- -->".to_owned(),
        "<style>a[x=\"</style><script>alert(1)</script>".to_owned(),
        // 3. Non-minimal `</script/>` and `</script foo=bar>` end tags.
        "<script type=\"application/json\">{\"a\":1}</script/><script>alert(1)</script>".to_owned(),
        "<script type=\"application/json\">{\"a\":1}</script foo=1><script>alert(1)</script>"
            .to_owned(),
        // Invalid JSON inside application/json script block.
        "<script type=\"application/json\">alert(1)</script>".to_owned(),
        // 4. Forbidden active / differential elements (`<iframe>`, `<svg>`, `<object>`, `<noscript>`, `<xmp>`, `<plaintext>`).
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>".to_owned(),
        "<svg onload=\"alert(1)\"></svg>".to_owned(),
        "<object data=\"https://evil.example/a.swf\"></object>".to_owned(),
        "<noscript><!--</noscript><script>alert(1)</script><!-- -->".to_owned(),
        "<noscript><a title=\"</noscript><script>alert(1)</script>\">".to_owned(),
        "<xmp></xmp><script>alert(1)</script>".to_owned(),
        "<plaintext><script>alert(1)</script>".to_owned(),
        // 4b. Non-UTF-8 meta charset / content-type overrides.
        "<meta charset=\"iso-2022-jp\">".to_owned(),
        "<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-16\">".to_owned(),
        "<meta http-equiv=\"content-type\" content=\"application/xhtml+xml\">".to_owned(),
        // 5. HTML entity-encoded `javascript:` URI & entity-encoded `<meta http-equiv="refresh">`.
        "<a href=\"&#106;avascript:alert(1)\">click</a>".to_owned(),
        "<meta http-equiv=\"&#114;efresh\" content=\"0;url=https://evil.example\">".to_owned(),
        // 6. Standard script/SRI/handler/base checks.
        "<script>alert(1)</script>".to_owned(),
        format!("<script src=\"/assets/v0.1.0/unlisted.js\" integrity=\"{js_sri}\"></script>"),
        "<script src=\"/assets/v0.1.0/sovret_crypto_wasm.js\"></script>".to_owned(),
        format!(
            "<script src=\"/assets/v0.1.0/sovret_crypto_wasm.js\" integrity=\"{js_sri}\">smuggled()</script>"
        ),
        format!(
            "<script src=\"/assets/v0.1.0/sovret_crypto_wasm.js\" src=\"/evil.js\" integrity=\"{js_sri}\"></script>"
        ),
        "<button OnClIcK=\"steal()\">Pay</button>".to_owned(),
        "<base href=\"https://evil.example/\">".to_owned(),
    ];
    for bad_html in &bad_htmls {
        assert!(
            audit_html_scripts(bad_html, &manifest).is_err(),
            "expected HTML5 smuggling reject: {bad_html}"
        );
    }

    // Checkout page Content-Type / charset parser-differential checks (explicit UTF-8 required).
    audit_page_content_type(Some("text/html; charset=utf-8"))?;
    audit_page_content_type(Some("TEXT/HTML; CHARSET=\"UTF-8\""))?;
    for bad_ct in [
        None,
        Some("text/html"),
        Some("text/html;"),
        Some("text/html; charset='utf-8'"),
        Some("application/xhtml+xml"),
        Some("text/html; charset=iso-2022-jp"),
        Some("text/html; charset=utf-16"),
        Some("text/html; charset=utf-8; charset=utf-8"),
    ] {
        assert!(
            audit_page_content_type(bad_ct).is_err(),
            "expected page Content-Type reject: {bad_ct:?}"
        );
    }

    // Duplicate JSON key smuggling (literal and Unicode-escaped) rejected in manifests (Finding #14).
    let canonical_manifest = manifest.to_canonical_json()?;
    assert!(ReleaseManifestV1::parse_and_validate(canonical_manifest.as_bytes()).is_ok());
    let dup_literal = canonical_manifest.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"schema_version\": 1,",
        1,
    );
    assert!(ReleaseManifestV1::parse_and_validate(dup_literal.as_bytes()).is_err());
    let dup_escaped = canonical_manifest.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"\\u0073chema_version\": 1,",
        1,
    );
    assert!(ReleaseManifestV1::parse_and_validate(dup_escaped.as_bytes()).is_err());

    // Served artifact checks.
    let wasm_art = manifest
        .find_artifact("/assets/v0.1.0/sovret_crypto_wasm_bg.wasm")
        .ok_or("missing wasm artifact")?;
    verify_served_artifact(
        wasm_art,
        Some("application/wasm"),
        Some("public, max-age=31536000, immutable"),
        &wasm_bytes,
        true,
    )?;

    // Manifest path & semver hardening checks (Medium #13).
    assert!(
        ReleaseManifestV1::build_from_artifacts(
            "0.1.0-..".to_owned(),
            manifest.git_commit.clone(),
            manifest.source_date_epoch,
            manifest.builder_image_digest.clone(),
            manifest.toolchain.clone(),
            manifest.artifacts.clone(),
        )
        .is_err()
    );
    assert!(
        ReleaseManifestV1::build_from_artifacts(
            "0.1.0".to_owned(),
            manifest.git_commit.clone(),
            manifest.source_date_epoch,
            manifest.builder_image_digest.clone(),
            manifest.toolchain.clone(),
            vec![hash_manifest_artifact(
                "/assets/v0.1.0/./sovret_crypto_wasm.js".to_owned(),
                "text/javascript".to_owned(),
                &js_bytes,
            )],
        )
        .is_err()
    );
    assert!(
        ReleaseManifestV1::build_from_artifacts(
            "0.1.0".to_owned(),
            manifest.git_commit,
            manifest.source_date_epoch,
            manifest.builder_image_digest,
            manifest.toolchain,
            vec![hash_manifest_artifact(
                "/assets/v0.1.0/.hidden.js".to_owned(),
                "text/javascript".to_owned(),
                &js_bytes,
            )],
        )
        .is_err()
    );

    Ok(())
}

#[test]
fn live_http_no_redirects_skl_and_hardened_rebuild_checks() -> Result<(), Box<dyn std::error::Error>>
{
    let (manifest, js_bytes, wasm_bytes) = sample_manifest()?;
    let js_sri = compute_sri_sha384(&js_bytes);
    let checkout_html = format!(
        "<!doctype html><html><head><script src=\"/assets/v0.1.0/sovret_crypto_wasm.js\" integrity=\"{js_sri}\"></script></head><body>OK</body></html>"
    );

    // 1. Live local HTTP server returning 200 OK passes.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let js_clone = js_bytes.clone();
    let wasm_clone = wasm_bytes.clone();
    let html_clone = checkout_html.into_bytes();

    let server = thread::spawn(move || {
        for _ in 0..3 {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0_u8; 2048];
                let n = stream.read(&mut req_buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let path = req_str
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (ct, extra_hdr, body): (&str, &str, &[u8]) = match path {
                    "/checkout" => (
                        "text/html; charset=utf-8",
                        "Content-Security-Policy: default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; worker-src 'none'\r\n",
                        &html_clone,
                    ),
                    "/assets/v0.1.0/sovret_crypto_wasm.js" => (
                        "text/javascript; charset=utf-8",
                        "Cache-Control: public, max-age=31536000, immutable\r\n",
                        &js_clone,
                    ),
                    "/assets/v0.1.0/sovret_crypto_wasm_bg.wasm" => (
                        "application/wasm",
                        "Cache-Control: public, max-age=31536000, immutable\r\n",
                        &wasm_clone,
                    ),
                    _ => ("text/plain", "", b"not found"),
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n{extra_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body);
            }
        }
    });

    let page_url = format!("http://{addr}/checkout");
    assert!(audit_live_site(&page_url, &manifest, false, true).is_err());
    let report = audit_live_site(&page_url, &manifest, true, true)?;
    assert_eq!(report.scripts_verified.len(), 1);
    assert_eq!(report.artifacts_verified, 2);
    let _ = server.join();

    // 2. High #4 regression: 302 redirect MUST be rejected (max_redirects = 0)!
    let redir_listener = TcpListener::bind("127.0.0.1:0")?;
    let redir_addr = redir_listener.local_addr()?;
    let redir_server = thread::spawn(move || {
        if let Ok((mut stream, _)) = redir_listener.accept() {
            let mut buf = [0_u8; 512];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    assert!(
        audit_live_site(
            &format!("http://{redir_addr}/checkout"),
            &manifest,
            true,
            true
        )
        .is_err()
    );
    let _ = redir_server.join();

    // Strict origin validation rejects non-http(s), credentials, backslashes, port 0.
    for bad_url in [
        "file:///etc/passwd",
        "https://user@example.com/checkout",
        "https://example.com\\evil/checkout",
        "https://example.com:0/checkout",
    ] {
        assert!(
            extract_origin(bad_url).is_err(),
            "expected origin reject: {bad_url}"
        );
    }

    // 3. SKL JSON + pinned checkpoint.
    let tenant_id = [0x5A_u8; 16];
    let tenant_hex = hex::encode(tenant_id);
    let (id_sk, id_vk) = Ed25519SigningKey::generate()?;
    let (_, org_pk) = XWingSecretKey::generate()?;
    let e0 = SklEntryV1::sign_genesis(
        tenant_id,
        VaultRole::OrgMaster,
        org_pk,
        &id_sk,
        1_795_400_000,
    )?;
    let skl_bytes = serde_json::to_vec(&SklDocumentJson {
        entries: vec![skl_entry_to_json(&e0)],
    })?;
    let cp_json = serde_json::to_vec(&SklCheckpointJson {
        seq: 0,
        entry_hash_hex: hex::encode(e0.entry_hash()),
        identity_ed25519_pk_hex: hex::encode(id_vk.to_bytes()),
    })?;
    let cp = parse_checkpoint_json(&cp_json)?;
    assert_eq!(
        verify_skl_document(&tenant_hex, &skl_bytes, Some(&cp))?.latest_seq(),
        0
    );
    // Duplicate JSON keys rejected in SKL and checkpoint parsers (Finding #14).
    let dup_skl = format!(
        r#"{{"entries":[],"\u0065ntries":{}}}"#,
        &String::from_utf8(skl_bytes)?[11..]
    );
    assert!(verify_skl_document(&tenant_hex, dup_skl.as_bytes(), Some(&cp)).is_err());
    let cp_str = String::from_utf8(cp_json)?;
    let dup_cp = cp_str.replacen(r#""seq":0,"#, r#""seq":0,"\u0073eq":0,"#, 1);
    assert!(parse_checkpoint_json(dup_cp.as_bytes()).is_err());

    // 4. Hardened Docker rebuild checks (High #7, Medium #13, Finding #10).
    let tmp = tempfile::tempdir()?;
    std::fs::write(tmp.path().join("sovret_crypto_wasm.js"), &js_bytes)?;
    std::fs::write(tmp.path().join("sovret_crypto_wasm_bg.wasm"), &wasm_bytes)?;
    assert_eq!(verify_rebuilt_directory(&manifest, tmp.path())?, 2);

    // Unexpected extra file and unexpected subdirectory rejected recursively.
    std::fs::write(tmp.path().join("injected.js"), b"alert(1)")?;
    assert!(verify_rebuilt_directory(&manifest, tmp.path()).is_err());
    std::fs::remove_file(tmp.path().join("injected.js"))?;

    std::fs::create_dir(tmp.path().join("sneaky"))?;
    assert!(verify_rebuilt_directory(&manifest, tmp.path()).is_err());
    std::fs::remove_dir(tmp.path().join("sneaky"))?;

    // Valid nested artifact path supported and nested extra files rejected recursively.
    let nested_js = b"export const nested = 1;\n".to_vec();
    let mut nested_artifacts = manifest.artifacts.clone();
    nested_artifacts.push(hash_manifest_artifact(
        "/assets/v0.1.0/chunks/helper.js".to_owned(),
        "text/javascript".to_owned(),
        &nested_js,
    ));
    let nested_manifest = ReleaseManifestV1::build_from_artifacts(
        manifest.release_version.clone(),
        manifest.git_commit.clone(),
        manifest.source_date_epoch,
        manifest.builder_image_digest.clone(),
        manifest.toolchain.clone(),
        nested_artifacts,
    )?;
    std::fs::create_dir(tmp.path().join("chunks"))?;
    std::fs::write(tmp.path().join("chunks").join("helper.js"), &nested_js)?;
    assert_eq!(verify_rebuilt_directory(&nested_manifest, tmp.path())?, 3);
    std::fs::write(tmp.path().join("chunks").join("extra.js"), b"evil()")?;
    assert!(verify_rebuilt_directory(&nested_manifest, tmp.path()).is_err());
    std::fs::remove_dir_all(tmp.path().join("chunks"))?;

    // Oversized file fails bounded metadata length check immediately.
    let mut oversized = wasm_bytes.clone();
    oversized.push(0x00);
    std::fs::write(tmp.path().join("sovret_crypto_wasm_bg.wasm"), &oversized)?;
    assert!(matches!(
        verify_rebuilt_directory(&manifest, tmp.path()),
        Err(VerifyError::ArtifactHashMismatch { .. })
    ));

    // 1-byte change in rebuilt output fails.
    let mut modified = wasm_bytes;
    modified[0] ^= 0x01;
    std::fs::write(tmp.path().join("sovret_crypto_wasm_bg.wasm"), &modified)?;
    assert!(matches!(
        verify_rebuilt_directory(&manifest, tmp.path()),
        Err(VerifyError::ArtifactHashMismatch { .. })
    ));

    let valid_ref = format!(
        "ghcr.io/sovret/wasm-builder@{}",
        manifest.builder_image_digest
    );
    let args = build_docker_rebuild_args(&manifest, &valid_ref, tmp.path(), tmp.path(), false)?;
    assert!(args.contains(&"--network=none".to_owned()));
    assert!(args.contains(&"--mount".to_owned()));

    // Forbidden bind-mount paths (CSV comma injection, extra colon, relative drive, leading dash) rejected.
    for bad_path in [
        std::path::Path::new("-leading-dash"),
        std::path::Path::new("C:\\foo,readonly=false"),
        std::path::Path::new("C:\\foo:bar"),
        std::path::Path::new("C:relative"),
        std::path::Path::new("/tmp/a:b"),
    ] {
        assert!(
            build_docker_rebuild_args(&manifest, &valid_ref, bad_path, tmp.path(), false).is_err(),
            "expected bind-mount path reject: {}",
            bad_path.display()
        );
    }

    // Digest mismatch, unpinned tag, and leading-dash Docker flag injection rejected!
    for bad_ref in [
        "ghcr.io/sovret/wasm-builder:latest",
        "ghcr.io/sovret/wasm-builder@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "--privileged@sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b",
        "evil;rm -rf /",
    ] {
        assert!(
            build_docker_rebuild_args(&manifest, bad_ref, tmp.path(), tmp.path(), false).is_err(),
            "expected builder ref reject: {bad_ref}"
        );
    }
    assert_eq!(compute_sha256_hex(b"").len(), 64);

    Ok(())
}

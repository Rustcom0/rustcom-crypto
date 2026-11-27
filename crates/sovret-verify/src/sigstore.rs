use std::collections::BTreeSet;

use base64ct::{Base64, Encoding};
use der::asn1::{GeneralizedTime, Int, OctetString, SetOfVec, Utf8StringRef};
use der::{
    Any, Decode, Encode, Header, Length, Reader, Sequence, SliceReader, Tag, TagNumber, Tagged,
};
use p256::ecdsa::{
    DerSignature as P256DerSignature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
use p256::pkcs8::DecodePublicKey as _;
use p384::ecdsa::{DerSignature as P384DerSignature, VerifyingKey as P384VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sovret_crypto_core::Ed25519VerifyingKey;
use subtle::ConstantTimeEq;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

use crate::VerifyError;
use crate::manifest::{ReleaseManifestV1, is_lowercase_hex};

/// Official Sigstore Public Good `trusted_root.json` (`SHA-256 = 6494e21e...0b66`),
/// containing Fulcio CA chains, Sigstore TSA chain, and Rekor v1 (`PKIX_ECDSA_P256`) +
/// Rekor v2 (`PKIX_ED25519`).
pub const EMBEDDED_SIGSTORE_PUBLIC_GOOD_TRUST_ROOT: &str =
    include_str!("../trust/sigstore_public_good_trusted_root.json");

/// Default Fulcio OIDC Issuer expected for official Sovret GitHub Actions releases.
pub const DEFAULT_GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// Default Fulcio SAN URI prefix expected for `sovret/sovret-crypto` release builds.
pub const DEFAULT_SOVRET_SAN_PREFIX: &str =
    "https://github.com/sovret/sovret-crypto/.github/workflows/release-wasm.yml@refs/tags/";

const MAX_TRUST_ROOT_JSON_LEN: usize = 2 * 1024 * 1024;
const MAX_BUNDLE_JSON_LEN: usize = 4 * 1024 * 1024;
const MAX_MERKLE_PROOF_HASHES: usize = 64;

const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_CT_PRECERT_SCTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

const OID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

const OID_FULCIO_ISSUER_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
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

/// Validated identity policy enforced against the Fulcio leaf X.509 certificate.
///
/// Fields are private and always bind an exact OIDC issuer, exact tag SAN URI, and exact 40-char
/// git commit SHA (`1.3.6.1.4.1.57264.1.13`) so callers cannot accidentally construct a loose
/// prefix-only policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigstorePolicy {
    oidc_issuer: String,
    san_prefix: String,
    san_exact: String,
    git_commit: String,
}

impl SigstorePolicy {
    /// Constructs a strict manifest-bound policy tying the Fulcio leaf SAN tag directly to
    /// `manifest.release_version` (`<san_prefix>v<release_version>`) and Fulcio's Source
    /// Repository Digest OID (`1.3.6.1.4.1.57264.1.13`) to `manifest.git_commit`.
    pub fn for_manifest(
        expected_oidc_issuer: String,
        expected_san_prefix: String,
        manifest: &ReleaseManifestV1,
    ) -> Result<Self, VerifyError> {
        manifest.validate()?;
        let exact = format!("{expected_san_prefix}v{}", manifest.release_version);
        Self::new_exact(
            expected_oidc_issuer,
            expected_san_prefix,
            exact,
            manifest.git_commit.clone(),
        )
    }

    /// Convenience constructor binding `manifest` against the official `sovret/sovret-crypto`
    /// GitHub Actions OIDC issuer and release workflow tag SAN prefix.
    pub fn sovret_for_manifest(manifest: &ReleaseManifestV1) -> Result<Self, VerifyError> {
        Self::for_manifest(
            DEFAULT_GITHUB_OIDC_ISSUER.to_owned(),
            DEFAULT_SOVRET_SAN_PREFIX.to_owned(),
            manifest,
        )
    }

    /// Constructs a validated policy with explicit exact OIDC issuer, SAN prefix, exact SAN URI,
    /// and 40-character lowercase hex git commit SHA.
    pub fn new_exact(
        expected_oidc_issuer: String,
        expected_san_prefix: String,
        expected_san_exact: String,
        expected_git_commit: String,
    ) -> Result<Self, VerifyError> {
        validate_oidc_issuer(&expected_oidc_issuer)?;
        validate_san_prefix(&expected_san_prefix)?;
        if !expected_san_exact.starts_with(&expected_san_prefix)
            || expected_san_exact.len() <= expected_san_prefix.len()
            || expected_san_exact
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(VerifyError::SigstoreVerificationFailed(format!(
                "expected_san_exact '{expected_san_exact}' must strictly extend '{expected_san_prefix}'"
            )));
        }
        if !is_lowercase_hex(&expected_git_commit, 40) {
            return Err(VerifyError::SigstoreVerificationFailed(
                "expected_git_commit must be a 40-character lowercase hex SHA-1".to_owned(),
            ));
        }
        Ok(Self {
            oidc_issuer: expected_oidc_issuer,
            san_prefix: expected_san_prefix,
            san_exact: expected_san_exact,
            git_commit: expected_git_commit,
        })
    }

    #[must_use]
    pub fn expected_oidc_issuer(&self) -> &str {
        &self.oidc_issuer
    }

    #[must_use]
    pub fn expected_san_prefix(&self) -> &str {
        &self.san_prefix
    }

    #[must_use]
    pub fn expected_san_exact(&self) -> &str {
        &self.san_exact
    }

    #[must_use]
    pub fn expected_git_commit(&self) -> &str {
        &self.git_commit
    }
}

fn validate_oidc_issuer(issuer: &str) -> Result<(), VerifyError> {
    if !issuer.starts_with("https://")
        || issuer.len() <= "https://".len()
        || issuer
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "expected_oidc_issuer '{issuer}' must be a valid https:// URL"
        )));
    }
    Ok(())
}

fn validate_san_prefix(prefix: &str) -> Result<(), VerifyError> {
    if !prefix.starts_with("https://")
        || !prefix.ends_with('/')
        || prefix
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "expected_san_prefix '{prefix}' must start with 'https://' and end with '/'"
        )));
    }
    Ok(())
}

/// Verified cryptographic summary returned upon successful Fulcio + Rekor v2/v1 + TSA verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigstoreAttestation {
    pub oidc_issuer: String,
    pub san_uri: String,
    pub source_repo_digest: Option<String>,
    pub tlog_base_url: String,
    pub log_index: u64,
    pub tree_size: u64,
    pub verified_timestamp: i64,
    pub root_hash_hex: String,
}

#[derive(Debug, Clone)]
enum ParsedPublicKey {
    Ed25519(Ed25519VerifyingKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
}

impl ParsedPublicKey {
    fn from_spki_der(spki_der: &[u8]) -> Result<Self, VerifyError> {
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
            .map_err(|e| VerifyError::InvalidTrustRoot(format!("invalid SPKI DER: {e}")))?;
        Self::from_spki(&spki)
    }

    fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self, VerifyError> {
        let oid = spki.algorithm.oid;
        if oid == OID_ED25519 {
            let raw = spki.subject_public_key.raw_bytes();
            let vk = Ed25519VerifyingKey::from_bytes(raw).map_err(|_| {
                VerifyError::SigstoreVerificationFailed("invalid or weak Ed25519 SPKI".to_owned())
            })?;
            return Ok(Self::Ed25519(vk));
        }
        if oid == OID_EC_PUBLIC_KEY {
            let param_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| {
                    VerifyError::SigstoreVerificationFailed(
                        "EC public key missing curve OID parameter".to_owned(),
                    )
                })?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| {
                    VerifyError::SigstoreVerificationFailed(
                        "invalid EC curve OID parameter".to_owned(),
                    )
                })?;
            let spki_der = spki
                .to_der()
                .map_err(|e| VerifyError::SigstoreVerificationFailed(e.to_string()))?;
            if param_oid == OID_CURVE_P256 {
                let vk = P256VerifyingKey::from_public_key_der(&spki_der).map_err(|e| {
                    VerifyError::SigstoreVerificationFailed(format!("invalid P-256 SPKI: {e}"))
                })?;
                return Ok(Self::P256(vk));
            }
            if param_oid == OID_CURVE_P384 {
                let vk = P384VerifyingKey::from_public_key_der(&spki_der).map_err(|e| {
                    VerifyError::SigstoreVerificationFailed(format!("invalid P-384 SPKI: {e}"))
                })?;
                return Ok(Self::P384(vk));
            }
        }
        Err(VerifyError::SigstoreVerificationFailed(format!(
            "unsupported public key algorithm OID {oid}"
        )))
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        match self {
            Self::Ed25519(vk) => vk.verify_strict(message, signature).map_err(|_| {
                VerifyError::SigstoreVerificationFailed(
                    "Ed25519 strict signature verification failed".to_owned(),
                )
            }),
            Self::P256(vk) => {
                let sig = P256DerSignature::from_bytes(signature).map_err(|_| {
                    VerifyError::SigstoreVerificationFailed(
                        "malformed ECDSA P-256 DER signature".to_owned(),
                    )
                })?;
                vk.verify(message, &sig).map_err(|_| {
                    VerifyError::SigstoreVerificationFailed(
                        "ECDSA P-256 signature verification failed".to_owned(),
                    )
                })
            }
            Self::P384(vk) => {
                let sig = P384DerSignature::from_bytes(signature).map_err(|_| {
                    VerifyError::SigstoreVerificationFailed(
                        "malformed ECDSA P-384 DER signature".to_owned(),
                    )
                })?;
                vk.verify(message, &sig).map_err(|_| {
                    VerifyError::SigstoreVerificationFailed(
                        "ECDSA P-384 signature verification failed".to_owned(),
                    )
                })
            }
        }
    }

    fn matches_sig_alg(&self, sig_alg_oid: ObjectIdentifier) -> bool {
        match self {
            Self::Ed25519(_) => sig_alg_oid == OID_ED25519,
            Self::P256(_) => sig_alg_oid == OID_ECDSA_SHA256,
            Self::P384(_) => sig_alg_oid == OID_ECDSA_SHA384,
        }
    }
}

/// Parsed Sigstore `TrustedRoot` containing verified Fulcio CA chains, RFC 3161 Timestamp
/// Authorities, and Rekor v1/v2 transparency log keys.
#[derive(Debug, Clone)]
pub struct SigstoreTrustRoot {
    tlogs: Vec<ParsedTlog>,
    cas: Vec<ParsedCa>,
    tsas: Vec<ParsedCa>,
}

#[derive(Debug, Clone)]
struct ParsedTlog {
    base_url: String,
    origin_host: String,
    key_id: [u8; 32],
    public_key: ParsedPublicKey,
    valid_start: Option<i64>,
    valid_end: Option<i64>,
}

#[derive(Debug, Clone)]
struct ParsedCa {
    uri: String,
    chain: Vec<Certificate>,
    valid_start: Option<i64>,
    valid_end: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedRootJson {
    media_type: String,
    #[serde(default)]
    tlogs: Vec<TlogJson>,
    #[serde(default)]
    certificate_authorities: Vec<CaJson>,
    #[serde(default)]
    timestamp_authorities: Vec<CaJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogJson {
    base_url: String,
    hash_algorithm: String,
    public_key: PublicKeyJson,
    log_id: LogIdJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyJson {
    raw_bytes: String,
    key_details: String,
    #[serde(default)]
    valid_for: Option<TimeRangeJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogIdJson {
    key_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaJson {
    uri: String,
    cert_chain: CertChainJson,
    #[serde(default)]
    valid_for: Option<TimeRangeJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertChainJson {
    certificates: Vec<RawCertJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCertJson {
    raw_bytes: String,
}

#[derive(Deserialize)]
struct TimeRangeJson {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Strictly parses an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS(.frac)?Z`, year `1970..=9999`)
/// into Unix epoch seconds using checked arithmetic and exact Gregorian month lengths.
pub fn parse_rfc3339_utc_unix(input: &str) -> Result<i64, VerifyError> {
    let trimmed = input
        .strip_suffix('Z')
        .or_else(|| input.strip_suffix('z'))
        .ok_or_else(|| {
            VerifyError::InvalidTrustRoot(format!("timestamp '{input}' must be UTC ('Z')"))
        })?;
    let (date_part, time_part) = trimmed.split_once('T').ok_or_else(|| {
        VerifyError::InvalidTrustRoot(format!("timestamp '{input}' missing 'T' separator"))
    })?;
    let mut date_it = date_part.split('-');
    let year_s = date_it
        .next()
        .ok_or_else(|| VerifyError::InvalidTrustRoot("missing year".to_owned()))?;
    let month_s = date_it
        .next()
        .ok_or_else(|| VerifyError::InvalidTrustRoot("missing month".to_owned()))?;
    let day_s = date_it
        .next()
        .ok_or_else(|| VerifyError::InvalidTrustRoot("missing day".to_owned()))?;
    if date_it.next().is_some() || year_s.len() != 4 || month_s.len() != 2 || day_s.len() != 2 {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "invalid ISO-8601 date format in '{input}'"
        )));
    }
    let year: i64 = year_s
        .parse()
        .map_err(|_| VerifyError::InvalidTrustRoot(format!("invalid year in '{input}'")))?;
    let month: u32 = month_s
        .parse()
        .map_err(|_| VerifyError::InvalidTrustRoot(format!("invalid month in '{input}'")))?;
    let day: u32 = day_s
        .parse()
        .map_err(|_| VerifyError::InvalidTrustRoot(format!("invalid day in '{input}'")))?;
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "date out of bounds in '{input}'"
        )));
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "invalid calendar day in '{input}'"
        )));
    }

    let (core_time, frac_opt) = match time_part.split_once('.') {
        Some((c, f)) => (c, Some(f)),
        None => (time_part, None),
    };
    if let Some(frac) = frac_opt
        && (frac.is_empty() || frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "invalid fractional seconds in '{input}'"
        )));
    }

    let mut time_it = core_time.split(':');
    let hour_s = time_it
        .next()
        .ok_or_else(|| VerifyError::InvalidTrustRoot("missing hour".to_owned()))?;
    let min_s = time_it
        .next()
        .ok_or_else(|| VerifyError::InvalidTrustRoot("missing minute".to_owned()))?;
    let sec_s = time_it
        .next()
        .ok_or_else(|| VerifyError::InvalidTrustRoot("missing second".to_owned()))?;
    if time_it.next().is_some() || hour_s.len() != 2 || min_s.len() != 2 || sec_s.len() != 2 {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "invalid ISO-8601 time format in '{input}'"
        )));
    }
    let hour: i64 = hour_s
        .parse()
        .map_err(|_| VerifyError::InvalidTrustRoot(format!("invalid hour in '{input}'")))?;
    let minute: i64 = min_s
        .parse()
        .map_err(|_| VerifyError::InvalidTrustRoot(format!("invalid minute in '{input}'")))?;
    let second: i64 = sec_s
        .parse()
        .map_err(|_| VerifyError::InvalidTrustRoot(format!("invalid second in '{input}'")))?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "invalid clock time in '{input}'"
        )));
    }

    // Howard Hinnant civil-from-days inverse algorithm (checked arithmetic, exact for 1970..=9999).
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era
        .checked_mul(146_097)
        .and_then(|v| v.checked_add(doe))
        .and_then(|v| v.checked_sub(719_468))
        .ok_or_else(|| VerifyError::InvalidTrustRoot("timestamp day overflow".to_owned()))?;
    days_since_epoch
        .checked_mul(86_400)
        .and_then(|v| v.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| VerifyError::InvalidTrustRoot("timestamp second overflow".to_owned()))
}

fn parse_time_range(
    range: Option<&TimeRangeJson>,
) -> Result<(Option<i64>, Option<i64>), VerifyError> {
    let Some(r) = range else {
        return Ok((None, None));
    };
    let start = match r.start.as_deref() {
        Some(s) => Some(parse_rfc3339_utc_unix(s)?),
        None => None,
    };
    let end = match r.end.as_deref() {
        Some(e) => Some(parse_rfc3339_utc_unix(e)?),
        None => None,
    };
    Ok((start, end))
}

fn parse_tlog_instance(t: TlogJson) -> Result<ParsedTlog, VerifyError> {
    let spki_der = Base64::decode_vec(&t.public_key.raw_bytes).map_err(|_| {
        VerifyError::InvalidTrustRoot(format!("invalid base64 SPKI for tlog {}", t.base_url))
    })?;
    let key_id_vec = Base64::decode_vec(&t.log_id.key_id).map_err(|_| {
        VerifyError::InvalidTrustRoot(format!("invalid base64 keyId for tlog {}", t.base_url))
    })?;
    let key_id: [u8; 32] = key_id_vec.try_into().map_err(|_| {
        VerifyError::InvalidTrustRoot(format!("tlog keyId must be 32 B ({})", t.base_url))
    })?;
    let public_key = ParsedPublicKey::from_spki_der(&spki_der)?;
    let details_ok = matches!(
        (&public_key, t.public_key.key_details.as_str()),
        (ParsedPublicKey::Ed25519(_), "PKIX_ED25519")
            | (ParsedPublicKey::P256(_), "PKIX_ECDSA_P256_SHA_256")
            | (ParsedPublicKey::P384(_), "PKIX_ECDSA_P384_SHA_384")
    );
    if !details_ok {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "tlog {} keyDetails '{}' does not match SPKI",
            t.base_url, t.public_key.key_details
        )));
    }
    let origin_host = t
        .base_url
        .strip_prefix("https://")
        .unwrap_or(&t.base_url)
        .trim_end_matches('/')
        .to_owned();

    // Verify logId.keyId matches either RFC 6962 / Rekor v1 `SHA-256(spki_der)` OR
    // Rekor v2 / C2SP signed-note Ed25519 key hash `SHA-256(origin || "\n" || 0x01 || raw32)`.
    let spki_hash = Sha256::digest(&spki_der);
    let mut key_id_valid = bool::from(spki_hash.as_slice().ct_eq(&key_id));
    if !key_id_valid && let ParsedPublicKey::Ed25519(vk) = &public_key {
        let mut h = Sha256::new();
        h.update(origin_host.as_bytes());
        h.update([b'\n', 0x01_u8]);
        h.update(vk.to_bytes());
        let c2sp_id = h.finalize();
        key_id_valid = bool::from(c2sp_id.as_slice().ct_eq(&key_id));
    }
    if !key_id_valid {
        return Err(VerifyError::InvalidTrustRoot(format!(
            "tlog {} keyId does not match SPKI or C2SP Ed25519 key hash",
            t.base_url
        )));
    }
    let (valid_start, valid_end) = parse_time_range(t.public_key.valid_for.as_ref())?;
    Ok(ParsedTlog {
        base_url: t.base_url,
        origin_host,
        key_id,
        public_key,
        valid_start,
        valid_end,
    })
}

fn parse_ca_list(raw_list: Vec<CaJson>) -> Result<Vec<ParsedCa>, VerifyError> {
    let mut out = Vec::new();
    for ca in raw_list {
        if ca.cert_chain.certificates.is_empty() {
            continue;
        }
        let mut chain = Vec::with_capacity(ca.cert_chain.certificates.len());
        for c in ca.cert_chain.certificates {
            let der_bytes = Base64::decode_vec(&c.raw_bytes).map_err(|_| {
                VerifyError::InvalidTrustRoot(format!("invalid CA/TSA cert base64 ({})", ca.uri))
            })?;
            let cert = Certificate::from_der(&der_bytes).map_err(|e| {
                VerifyError::InvalidTrustRoot(format!("invalid CA/TSA cert DER ({}): {e}", ca.uri))
            })?;
            chain.push(cert);
        }
        let (valid_start, valid_end) = parse_time_range(ca.valid_for.as_ref())?;
        out.push(ParsedCa {
            uri: ca.uri,
            chain,
            valid_start,
            valid_end,
        });
    }
    Ok(out)
}

impl SigstoreTrustRoot {
    /// Loads the embedded official Sigstore Public Good trust root.
    pub fn public_good() -> Result<Self, VerifyError> {
        Self::from_json_bytes(EMBEDDED_SIGSTORE_PUBLIC_GOOD_TRUST_ROOT.as_bytes())
    }

    /// Parses and validates a Sigstore `trusted_root.json` document, rejecting duplicate JSON keys.
    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, VerifyError> {
        if raw.len() > MAX_TRUST_ROOT_JSON_LEN {
            return Err(VerifyError::InputTooLarge("trusted_root.json"));
        }
        crate::reject_duplicate_json_keys(raw)?;
        let parsed: TrustedRootJson =
            serde_json::from_slice(raw).map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
        if !parsed
            .media_type
            .starts_with("application/vnd.dev.sigstore.trustedroot+json")
        {
            return Err(VerifyError::InvalidTrustRoot(format!(
                "unexpected trust root mediaType '{}'",
                parsed.media_type
            )));
        }

        let mut tlogs = Vec::new();
        for t in parsed.tlogs {
            if t.hash_algorithm != "SHA2_256" {
                continue;
            }
            tlogs.push(parse_tlog_instance(t)?);
        }

        let cas = parse_ca_list(parsed.certificate_authorities)?;
        let tsas = parse_ca_list(parsed.timestamp_authorities)?;

        if tlogs.is_empty() || cas.is_empty() {
            return Err(VerifyError::InvalidTrustRoot(
                "trust root must contain at least one transparency log and one CA".to_owned(),
            ));
        }

        Ok(Self { tlogs, cas, tsas })
    }

    #[must_use]
    pub fn tlog_count(&self) -> usize {
        self.tlogs.len()
    }

    #[must_use]
    pub fn ca_count(&self) -> usize {
        self.cas.len()
    }

    #[must_use]
    pub fn tsa_count(&self) -> usize {
        self.tsas.len()
    }
}

fn de_u64_str_or_int<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrInt {
        Int(u64),
        Str(String),
    }
    match StrOrInt::deserialize(deserializer)? {
        StrOrInt::Int(v) => Ok(v),
        StrOrInt::Str(s) => s.parse::<u64>().map_err(serde::de::Error::custom),
    }
}

fn de_opt_i64_str_or_int<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrInt {
        Int(i64),
        Str(String),
    }
    match Option::<StrOrInt>::deserialize(deserializer)? {
        None => Ok(None),
        Some(StrOrInt::Int(v)) => Ok(Some(v)),
        Some(StrOrInt::Str(s)) => s.parse::<i64>().map(Some).map_err(serde::de::Error::custom),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigstoreBundleJson {
    media_type: String,
    verification_material: VerificationMaterialJson,
    message_signature: MessageSignatureJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationMaterialJson {
    #[serde(default)]
    certificate: Option<RawCertJson>,
    #[serde(default)]
    x509_certificate_chain: Option<CertChainJson>,
    #[serde(default)]
    tlog_entries: Vec<TlogEntryJson>,
    #[serde(default)]
    timestamp_verification_data: Option<TimestampVerificationDataJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimestampVerificationDataJson {
    #[serde(default)]
    rfc3161_timestamps: Vec<Rfc3161SignedTimestampJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rfc3161SignedTimestampJson {
    signed_timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageSignatureJson {
    message_digest: MessageDigestJson,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageDigestJson {
    algorithm: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogEntryJson {
    #[serde(deserialize_with = "de_u64_str_or_int")]
    log_index: u64,
    log_id: LogIdJson,
    kind_version: KindVersionJson,
    #[serde(default, deserialize_with = "de_opt_i64_str_or_int")]
    integrated_time: Option<i64>,
    canonicalized_body: String,
    #[serde(default)]
    inclusion_proof: Option<InclusionProofJson>,
    #[serde(default)]
    inclusion_promise: Option<InclusionPromiseJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionPromiseJson {
    signed_entry_timestamp: String,
}

#[derive(Deserialize)]
struct KindVersionJson {
    kind: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionProofJson {
    #[serde(deserialize_with = "de_u64_str_or_int")]
    log_index: u64,
    root_hash: String,
    #[serde(deserialize_with = "de_u64_str_or_int")]
    tree_size: u64,
    #[serde(default)]
    hashes: Vec<String>,
    checkpoint: CheckpointJson,
}

#[derive(Deserialize)]
struct CheckpointJson {
    envelope: String,
}

/// Verifies an RFC 6962 / Rekor v2 Merkle inclusion proof from `leaf_bytes` up to `expected_root_hash`.
pub fn verify_merkle_inclusion_proof(
    leaf_bytes: &[u8],
    log_index: u64,
    tree_size: u64,
    proof_hashes: &[[u8; 32]],
    expected_root_hash: &[u8; 32],
) -> Result<(), VerifyError> {
    if tree_size == 0 || log_index >= tree_size || proof_hashes.len() > MAX_MERKLE_PROOF_HASHES {
        return Err(VerifyError::RekorProofFailed(
            "invalid Merkle inclusion proof bounds".to_owned(),
        ));
    }

    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update([0x00_u8]);
    leaf_hasher.update(leaf_bytes);
    let mut current: [u8; 32] = leaf_hasher.finalize().into();

    let mut fn_idx = log_index;
    let mut sn_idx = tree_size - 1;

    for sibling in proof_hashes {
        if sn_idx == 0 {
            return Err(VerifyError::RekorProofFailed(
                "Merkle inclusion proof has trailing unused hashes".to_owned(),
            ));
        }
        let mut node_hasher = Sha256::new();
        node_hasher.update([0x01_u8]);
        if (fn_idx & 1) == 1 || fn_idx == sn_idx {
            node_hasher.update(sibling);
            node_hasher.update(current);
            while (fn_idx & 1) == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn_idx >>= 1;
            }
        } else {
            node_hasher.update(current);
            node_hasher.update(sibling);
        }
        current = node_hasher.finalize().into();
        fn_idx >>= 1;
        sn_idx >>= 1;
    }

    if sn_idx != 0 {
        return Err(VerifyError::RekorProofFailed(
            "Merkle inclusion proof truncated before reaching tree root".to_owned(),
        ));
    }
    if !bool::from(current.ct_eq(expected_root_hash)) {
        return Err(VerifyError::RekorProofFailed(
            "computed Merkle root hash does not match checkpoint root".to_owned(),
        ));
    }
    Ok(())
}

/// Strictly verifies a C2SP Signed Note checkpoint against `tlog.origin_host`,
/// `expected_tree_size`, `expected_root_hash`, 4-byte `tlog.key_id[..4]` hint, and `tlog.public_key`.
fn verify_c2sp_checkpoint(
    envelope: &str,
    expected_tree_size: u64,
    expected_root_hash: &[u8; 32],
    tlog: &ParsedTlog,
) -> Result<(), VerifyError> {
    if envelope.contains('\r') {
        return Err(VerifyError::RekorProofFailed(
            "C2SP checkpoint must use LF line endings (CR forbidden)".to_owned(),
        ));
    }
    let (body, sig_block) = envelope.split_once("\n\n").ok_or_else(|| {
        VerifyError::RekorProofFailed("C2SP checkpoint missing blank-line separator".to_owned())
    })?;
    let mut lines = body.split('\n');
    let origin = lines.next().ok_or_else(|| {
        VerifyError::RekorProofFailed("C2SP checkpoint missing origin line".to_owned())
    })?;
    let origin_matches =
        origin == tlog.origin_host || origin.starts_with(&format!("{} - ", tlog.origin_host));
    if !origin_matches {
        return Err(VerifyError::RekorProofFailed(format!(
            "C2SP checkpoint origin '{origin}' does not match trusted log host '{}'",
            tlog.origin_host
        )));
    }
    let tree_size_str = lines.next().ok_or_else(|| {
        VerifyError::RekorProofFailed("C2SP checkpoint missing tree size".to_owned())
    })?;
    let tree_size: u64 = tree_size_str.parse().map_err(|_| {
        VerifyError::RekorProofFailed("C2SP checkpoint tree size is not an integer".to_owned())
    })?;
    if tree_size != expected_tree_size {
        return Err(VerifyError::RekorProofFailed(format!(
            "C2SP checkpoint tree size {tree_size} != inclusion proof tree size {expected_tree_size}"
        )));
    }
    let root_b64 = lines.next().ok_or_else(|| {
        VerifyError::RekorProofFailed("C2SP checkpoint missing root hash".to_owned())
    })?;
    let root_bytes = Base64::decode_vec(root_b64).map_err(|_| {
        VerifyError::RekorProofFailed("C2SP checkpoint root hash is invalid base64".to_owned())
    })?;
    if root_bytes.len() != 32 || !bool::from(root_bytes.as_slice().ct_eq(expected_root_hash)) {
        return Err(VerifyError::RekorProofFailed(
            "C2SP checkpoint root hash does not match inclusion proof root".to_owned(),
        ));
    }

    let signed_note_bytes = format!("{body}\n");
    let mut verified_sig = false;

    for raw_sig_line in sig_block.split('\n') {
        if raw_sig_line.is_empty() {
            continue;
        }
        // C2SP signed-note signature prefix: U+2014 EM DASH + ASCII space ("— ").
        let Some(rest) = raw_sig_line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((_signer_name, sig_b64)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Ok(sig_payload) = Base64::decode_vec(sig_b64) else {
            continue;
        };
        if sig_payload.len() <= 4 {
            continue;
        }
        // Verify 4-byte C2SP key hint matches tlog.key_id[..4] in constant time.
        if !bool::from(sig_payload[..4].ct_eq(&tlog.key_id[..4])) {
            continue;
        }
        let sig_bytes = &sig_payload[4..];
        if tlog
            .public_key
            .verify_signature(signed_note_bytes.as_bytes(), sig_bytes)
            .is_ok()
        {
            verified_sig = true;
            break;
        }
    }

    if !verified_sig {
        return Err(VerifyError::RekorProofFailed(format!(
            "no valid C2SP checkpoint signature matching key hint for {}",
            tlog.base_url
        )));
    }
    Ok(())
}

// ============================================================================
// RFC 5280 X.509 Extension & Chain Validation
// ============================================================================

fn is_recognized_extension(oid: ObjectIdentifier) -> bool {
    if oid == OID_BASIC_CONSTRAINTS
        || oid == OID_KEY_USAGE
        || oid == OID_EXT_KEY_USAGE
        || oid == OID_SUBJECT_ALT_NAME
        || oid == OID_SUBJECT_KEY_ID
        || oid == OID_AUTHORITY_KEY_ID
        || oid == OID_AUTHORITY_INFO_ACCESS
        || oid == OID_CT_PRECERT_SCTS
    {
        return true;
    }
    // Fulcio OIDC extensions under 1.3.6.1.4.1.57264.1.*
    oid.to_string().starts_with("1.3.6.1.4.1.57264.1.")
}

struct ParsedCertConstraints {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    ext_key_usage: Option<ExtendedKeyUsage>,
}

fn parse_and_validate_cert_extensions(
    cert: &Certificate,
) -> Result<ParsedCertConstraints, VerifyError> {
    let mut seen_oids = BTreeSet::new();
    let mut basic_constraints = None;
    let mut key_usage = None;
    let mut ext_key_usage = None;

    if let Some(exts) = cert.tbs_certificate().extensions() {
        for ext in exts {
            if !seen_oids.insert(ext.extn_id) {
                return Err(VerifyError::SigstoreVerificationFailed(format!(
                    "certificate contains duplicate extension OID {}",
                    ext.extn_id
                )));
            }
            if ext.critical && !is_recognized_extension(ext.extn_id) {
                return Err(VerifyError::SigstoreVerificationFailed(format!(
                    "certificate contains unrecognized critical extension OID {}",
                    ext.extn_id
                )));
            }
            if ext.extn_id == OID_BASIC_CONSTRAINTS {
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    VerifyError::SigstoreVerificationFailed(format!(
                        "invalid BasicConstraints: {e}"
                    ))
                })?;
                basic_constraints = Some(bc);
            } else if ext.extn_id == OID_KEY_USAGE {
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    VerifyError::SigstoreVerificationFailed(format!("invalid KeyUsage: {e}"))
                })?;
                key_usage = Some(ku);
            } else if ext.extn_id == OID_EXT_KEY_USAGE {
                let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    VerifyError::SigstoreVerificationFailed(format!("invalid EKU: {e}"))
                })?;
                ext_key_usage = Some(eku);
            }
        }
    }

    Ok(ParsedCertConstraints {
        basic_constraints,
        key_usage,
        ext_key_usage,
    })
}

fn cert_validity_unix(cert: &Certificate) -> Result<(i64, i64), VerifyError> {
    let not_before = i64::try_from(
        cert.tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs(),
    )
    .map_err(|_| VerifyError::SigstoreVerificationFailed("cert notBefore overflow".to_owned()))?;
    let not_after = i64::try_from(
        cert.tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs(),
    )
    .map_err(|_| VerifyError::SigstoreVerificationFailed("cert notAfter overflow".to_owned()))?;
    Ok((not_before, not_after))
}

fn check_time_in_window(
    ts: i64,
    start: Option<i64>,
    end: Option<i64>,
    label: &str,
) -> Result<(), VerifyError> {
    if let Some(s) = start
        && ts < s
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "verified timestamp {ts} precedes {label} validity start {s}"
        )));
    }
    if let Some(e) = end
        && ts > e
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "verified timestamp {ts} exceeds {label} validity end {e}"
        )));
    }
    Ok(())
}

fn verify_cert_issued_by(
    child: &Certificate,
    parent: &Certificate,
    intermediate_ca_depth: usize,
) -> Result<(), VerifyError> {
    // RFC 5280 §4.1.1.2: inner tbs.signature must equal outer signatureAlgorithm.
    if child.tbs_certificate().signature() != child.signature_algorithm() {
        return Err(VerifyError::SigstoreVerificationFailed(
            "certificate tbs.signature does not match outer signatureAlgorithm".to_owned(),
        ));
    }
    if child.tbs_certificate().issuer() != parent.tbs_certificate().subject() {
        return Err(VerifyError::SigstoreVerificationFailed(
            "certificate issuer DN does not match parent subject DN".to_owned(),
        ));
    }

    let parent_constraints = parse_and_validate_cert_extensions(parent)?;
    let Some(bc) = parent_constraints.basic_constraints else {
        return Err(VerifyError::SigstoreVerificationFailed(
            "CA certificate missing BasicConstraints".to_owned(),
        ));
    };
    if !bc.ca {
        return Err(VerifyError::SigstoreVerificationFailed(
            "parent certificate lacks BasicConstraints CA=true".to_owned(),
        ));
    }
    if let Some(max_path_len) = bc.path_len_constraint
        && intermediate_ca_depth > usize::from(max_path_len)
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "CA pathLenConstraint {max_path_len} exceeded at depth {intermediate_ca_depth}"
        )));
    }
    if let Some(ku) = parent_constraints.key_usage
        && !ku.0.contains(KeyUsages::KeyCertSign)
    {
        return Err(VerifyError::SigstoreVerificationFailed(
            "CA certificate KeyUsage lacks keyCertSign".to_owned(),
        ));
    }

    let parent_pk = ParsedPublicKey::from_spki(parent.tbs_certificate().subject_public_key_info())?;
    if !parent_pk.matches_sig_alg(child.signature_algorithm().oid) {
        return Err(VerifyError::SigstoreVerificationFailed(
            "certificate signature algorithm does not match parent key type".to_owned(),
        ));
    }
    let tbs_der = child
        .tbs_certificate()
        .to_der()
        .map_err(|e| VerifyError::SigstoreVerificationFailed(e.to_string()))?;
    parent_pk.verify_signature(&tbs_der, child.signature().raw_bytes())
}

fn validate_leaf_constraints(
    leaf: &Certificate,
    required_eku: ObjectIdentifier,
    label: &str,
) -> Result<(), VerifyError> {
    let constraints = parse_and_validate_cert_extensions(leaf)?;
    if constraints.basic_constraints.is_some_and(|bc| bc.ca) {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "{label} leaf certificate must not be a CA"
        )));
    }
    if let Some(ku) = constraints.key_usage
        && (!ku.0.contains(KeyUsages::DigitalSignature) || ku.0.contains(KeyUsages::KeyCertSign))
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "{label} leaf certificate KeyUsage must set digitalSignature and not keyCertSign"
        )));
    }
    let has_eku = constraints
        .ext_key_usage
        .is_some_and(|eku| eku.0.contains(&required_eku));
    if !has_eku {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "{label} leaf certificate missing required EKU {required_eku}"
        )));
    }
    Ok(())
}

fn verify_ca_chain_validity(ca_chain: &[Certificate], ts: i64) -> Result<(), VerifyError> {
    for (idx, ca_cert) in ca_chain.iter().enumerate() {
        let (s, e) = cert_validity_unix(ca_cert)?;
        check_time_in_window(ts, Some(s), Some(e), "CA cert")?;
        if let Some(parent) = ca_chain.get(idx + 1) {
            verify_cert_issued_by(ca_cert, parent, idx + 1)?;
        } else {
            // Self-signed root CA.
            verify_cert_issued_by(ca_cert, ca_cert, idx)?;
        }
    }
    Ok(())
}

fn verify_leaf_against_cas(
    leaf: &Certificate,
    verified_timestamp: i64,
    cas: &[ParsedCa],
    required_eku: ObjectIdentifier,
    label: &str,
) -> Result<(), VerifyError> {
    validate_leaf_constraints(leaf, required_eku, label)?;
    let (leaf_start, leaf_end) = cert_validity_unix(leaf)?;
    check_time_in_window(verified_timestamp, Some(leaf_start), Some(leaf_end), label)?;

    let mut last_err = format!("no matching {label} CA chain in trust root");
    for ca in cas {
        if check_time_in_window(verified_timestamp, ca.valid_start, ca.valid_end, &ca.uri).is_err()
        {
            continue;
        }
        let Some(first_ca) = ca.chain.first() else {
            continue;
        };
        if let Err(e) = verify_cert_issued_by(leaf, first_ca, 0) {
            last_err = e.to_string();
            continue;
        }
        if let Err(e) = verify_ca_chain_validity(&ca.chain, verified_timestamp) {
            last_err = e.to_string();
            continue;
        }
        return Ok(());
    }

    Err(VerifyError::SigstoreVerificationFailed(last_err))
}

struct FulcioIdentity {
    oidc_issuer: String,
    san_uri: String,
    source_repo_digest: Option<String>,
}

fn extract_fulcio_identity(leaf: &Certificate) -> Result<FulcioIdentity, VerifyError> {
    let exts = leaf.tbs_certificate().extensions().ok_or_else(|| {
        VerifyError::SigstoreVerificationFailed(
            "Fulcio leaf certificate has no extensions".to_owned(),
        )
    })?;

    let mut issuer_v2: Option<String> = None;
    let mut issuer_v1: Option<String> = None;
    let mut san_uri: Option<String> = None;
    let mut source_repo_digest: Option<String> = None;

    for ext in exts {
        if ext.extn_id == OID_FULCIO_ISSUER_V2 {
            if issuer_v2.is_some() {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "duplicate Fulcio OIDC Issuer v2 extension".to_owned(),
                ));
            }
            let utf8 = Utf8StringRef::from_der(ext.extn_value.as_bytes()).map_err(|_| {
                VerifyError::SigstoreVerificationFailed(
                    "invalid DER UTF8String in Fulcio OIDC Issuer v2 extension".to_owned(),
                )
            })?;
            issuer_v2 = Some(utf8.as_str().to_owned());
        } else if ext.extn_id == OID_FULCIO_ISSUER_V1 {
            if issuer_v1.is_some() {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "duplicate Fulcio OIDC Issuer v1 extension".to_owned(),
                ));
            }
            let raw_str = core::str::from_utf8(ext.extn_value.as_bytes()).map_err(|_| {
                VerifyError::SigstoreVerificationFailed(
                    "non-UTF8 Fulcio OIDC Issuer v1 extension".to_owned(),
                )
            })?;
            issuer_v1 = Some(raw_str.to_owned());
        } else if ext.extn_id == OID_FULCIO_SOURCE_REPO_DIGEST {
            if source_repo_digest.is_some() {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "duplicate Fulcio Source Repository Digest extension".to_owned(),
                ));
            }
            let utf8 = Utf8StringRef::from_der(ext.extn_value.as_bytes()).map_err(|_| {
                VerifyError::SigstoreVerificationFailed(
                    "invalid DER UTF8String in Fulcio Source Repository Digest".to_owned(),
                )
            })?;
            source_repo_digest = Some(utf8.as_str().to_owned());
        } else if ext.extn_id == OID_SUBJECT_ALT_NAME {
            if san_uri.is_some() {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "duplicate SAN extension".to_owned(),
                ));
            }
            let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                VerifyError::SigstoreVerificationFailed(format!("invalid SAN extension: {e}"))
            })?;
            if san.0.len() != 1 {
                return Err(VerifyError::SigstoreVerificationFailed(format!(
                    "Fulcio leaf SAN must contain exactly 1 GeneralName (found {})",
                    san.0.len()
                )));
            }
            if let Some(GeneralName::UniformResourceIdentifier(uri)) = san.0.first() {
                san_uri = Some(uri.as_str().to_owned());
            } else {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "Fulcio leaf SAN GeneralName must be a URI".to_owned(),
                ));
            }
        }
    }

    if let (Some(v1), Some(v2)) = (&issuer_v1, &issuer_v2)
        && v1 != v2
    {
        return Err(VerifyError::SigstoreVerificationFailed(
            "Fulcio OIDC Issuer v1 and v2 extensions disagree".to_owned(),
        ));
    }

    let oidc_issuer = issuer_v2.or(issuer_v1).ok_or_else(|| {
        VerifyError::SigstoreVerificationFailed(
            "Fulcio leaf certificate missing OIDC Issuer extension".to_owned(),
        )
    })?;
    let san_uri = san_uri.ok_or_else(|| {
        VerifyError::SigstoreVerificationFailed(
            "Fulcio leaf certificate missing SAN URI".to_owned(),
        )
    })?;

    Ok(FulcioIdentity {
        oidc_issuer,
        san_uri,
        source_repo_digest,
    })
}

// ============================================================================
// RFC 3161 TSA SignedData Verification (Required for Rekor v2 Timestamps)
// ============================================================================

#[derive(Sequence)]
struct CmsContentInfo {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: Any,
}

#[derive(Sequence)]
struct Rfc3161TimeStampResp {
    #[allow(dead_code)]
    status: Any,
    time_stamp_token: Option<CmsContentInfo>,
}

#[derive(Sequence)]
struct EncapsulatedContentInfo {
    e_content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    e_content: Option<OctetString>,
}

#[derive(Sequence)]
struct CmsAttribute {
    attr_type: ObjectIdentifier,
    attr_values: SetOfVec<Any>,
}

#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

struct ParsedTstInfo {
    imprint: MessageImprint,
    gen_time: i64,
}

fn parse_tst_info(der_bytes: &[u8]) -> Result<ParsedTstInfo, VerifyError> {
    let mut outer = SliceReader::new(der_bytes)
        .map_err(|e| VerifyError::SigstoreVerificationFailed(format!("invalid TSTInfo: {e}")))?;
    outer
        .sequence(|reader| {
            let _version: u8 = reader.decode()?;
            let _policy: ObjectIdentifier = reader.decode()?;
            let imprint: MessageImprint = reader.decode()?;
            let _serial: Int = reader.decode()?;
            let gen_time: GeneralizedTime = reader.decode()?;
            // Consume any optional trailing RFC 3161 fields (accuracy, ordering, nonce, tsa, extensions).
            while !reader.is_finished() {
                let _: Any = reader.decode()?;
            }
            Ok((imprint, gen_time))
        })
        .map_err(|e: der::Error| {
            VerifyError::SigstoreVerificationFailed(format!("invalid TSTInfo DER: {e}"))
        })
        .and_then(|(imprint, gen_time)| {
            let secs = i64::try_from(gen_time.to_unix_duration().as_secs()).map_err(|_| {
                VerifyError::SigstoreVerificationFailed("TSA genTime overflow".to_owned())
            })?;
            Ok(ParsedTstInfo {
                imprint,
                gen_time: secs,
            })
        })
}

fn hash_with_oid(alg_oid: ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, VerifyError> {
    if alg_oid == OID_SHA256 {
        Ok(Sha256::digest(data).to_vec())
    } else if alg_oid == OID_SHA384 {
        Ok(Sha384::digest(data).to_vec())
    } else if alg_oid == OID_SHA512 {
        Ok(Sha512::digest(data).to_vec())
    } else {
        Err(VerifyError::SigstoreVerificationFailed(format!(
            "unsupported RFC 3161 hash OID {alg_oid}"
        )))
    }
}

struct ParsedSignerInfo {
    digest_alg: AlgorithmIdentifierOwned,
    signed_attrs_raw_value: Vec<u8>,
    sig_alg: AlgorithmIdentifierOwned,
    signature: Vec<u8>,
}

fn parse_signer_info(der_bytes: &[u8]) -> Result<ParsedSignerInfo, VerifyError> {
    let mut outer = SliceReader::new(der_bytes)
        .map_err(|e| VerifyError::SigstoreVerificationFailed(format!("invalid SignerInfo: {e}")))?;
    outer
        .sequence(|reader| {
            let _version: u8 = reader.decode()?;
            let _sid: Any = reader.decode()?;
            let digest_alg: AlgorithmIdentifierOwned = reader.decode()?;
            let signed_attrs_any: Any = reader.decode()?;
            let expected_tag = Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(0),
            };
            if signed_attrs_any.tag() != expected_tag {
                return Err(der::Error::new(
                    der::ErrorKind::TagUnexpected {
                        expected: Some(expected_tag),
                        actual: signed_attrs_any.tag(),
                    },
                    Length::ZERO,
                ));
            }
            let sig_alg: AlgorithmIdentifierOwned = reader.decode()?;
            let sig_octets: OctetString = reader.decode()?;
            while !reader.is_finished() {
                let _: Any = reader.decode()?;
            }
            Ok(ParsedSignerInfo {
                digest_alg,
                signed_attrs_raw_value: signed_attrs_any.value().to_vec(),
                sig_alg,
                signature: sig_octets.as_bytes().to_vec(),
            })
        })
        .map_err(|e: der::Error| {
            VerifyError::SigstoreVerificationFailed(format!("invalid CMS SignerInfo DER: {e}"))
        })
}

fn verify_signed_attrs_and_encode_set(
    signed_attrs_value: &[u8],
    digest_alg_oid: ObjectIdentifier,
    tst_info_der: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    let mut reader = SliceReader::new(signed_attrs_value).map_err(|e| {
        VerifyError::SigstoreVerificationFailed(format!("invalid signedAttrs: {e}"))
    })?;
    let mut saw_content_type = false;
    let mut saw_message_digest = false;
    let expected_digest = hash_with_oid(digest_alg_oid, tst_info_der)?;

    while !reader.is_finished() {
        let attr: CmsAttribute = reader.decode().map_err(|e| {
            VerifyError::SigstoreVerificationFailed(format!("invalid CMS attribute: {e}"))
        })?;
        if attr.attr_type == OID_CMS_CONTENT_TYPE {
            if saw_content_type {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "duplicate CMS contentType attribute in signedAttrs".to_owned(),
                ));
            }
            if attr.attr_values.len() != 1 {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "CMS contentType attribute must have 1 value".to_owned(),
                ));
            }
            let ct_oid = attr
                .attr_values
                .get(0)
                .ok_or_else(|| {
                    VerifyError::SigstoreVerificationFailed("missing contentType".to_owned())
                })?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| {
                    VerifyError::SigstoreVerificationFailed("invalid contentType OID".to_owned())
                })?;
            if ct_oid != OID_ID_CT_TST_INFO {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "CMS contentType is not id-ct-TSTInfo".to_owned(),
                ));
            }
            saw_content_type = true;
        } else if attr.attr_type == OID_CMS_MESSAGE_DIGEST {
            if saw_message_digest {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "duplicate CMS messageDigest attribute in signedAttrs".to_owned(),
                ));
            }
            if attr.attr_values.len() != 1 {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "CMS messageDigest attribute must have 1 value".to_owned(),
                ));
            }
            let md = attr
                .attr_values
                .get(0)
                .ok_or_else(|| {
                    VerifyError::SigstoreVerificationFailed("missing messageDigest".to_owned())
                })?
                .decode_as::<OctetString>()
                .map_err(|_| {
                    VerifyError::SigstoreVerificationFailed("invalid messageDigest".to_owned())
                })?;
            if !bool::from(md.as_bytes().ct_eq(&expected_digest)) {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "RFC 3161 signedAttrs messageDigest mismatch".to_owned(),
                ));
            }
            saw_message_digest = true;
        }
    }

    if !saw_content_type || !saw_message_digest {
        return Err(VerifyError::SigstoreVerificationFailed(
            "RFC 3161 signedAttrs missing contentType or messageDigest".to_owned(),
        ));
    }

    // Re-encode with explicit SET tag (0x31) per RFC 5652 §5.4 for signature verification.
    let val_len = Length::try_from(signed_attrs_value.len()).map_err(|_| {
        VerifyError::SigstoreVerificationFailed("signedAttrs length overflow".to_owned())
    })?;
    let hdr = Header::new(Tag::Set, val_len);
    let mut set_der = Vec::with_capacity(signed_attrs_value.len() + 8);
    hdr.encode_to_vec(&mut set_der)
        .map_err(|e| VerifyError::SigstoreVerificationFailed(e.to_string()))?;
    set_der.extend_from_slice(signed_attrs_value);
    Ok(set_der)
}

fn verify_tsa_signer_chain(
    signer_cert: &Certificate,
    gen_time: i64,
    trust_root: &SigstoreTrustRoot,
) -> Result<(), VerifyError> {
    validate_leaf_constraints(signer_cert, OID_KP_TIME_STAMPING, "TSA")?;
    let (s, e) = cert_validity_unix(signer_cert)?;
    check_time_in_window(gen_time, Some(s), Some(e), "TSA signer cert")?;

    let signer_der = signer_cert
        .to_der()
        .map_err(|err| VerifyError::SigstoreVerificationFailed(err.to_string()))?;

    for tsa in &trust_root.tsas {
        if check_time_in_window(gen_time, tsa.valid_start, tsa.valid_end, &tsa.uri).is_err() {
            continue;
        }
        // In Sigstore trusted_root.json, tsa.chain[0] may be the TSA leaf cert itself followed by
        // its CA chain (`tsa.chain[1..]`), OR tsa.chain[0..] may be the issuing CA chain.
        if let Some(first) = tsa.chain.first() {
            let first_der = first
                .to_der()
                .map_err(|err| VerifyError::SigstoreVerificationFailed(err.to_string()))?;
            if bool::from(first_der.as_slice().ct_eq(&signer_der)) {
                if let Some(ca_tail) = tsa.chain.get(1..)
                    && !ca_tail.is_empty()
                {
                    if verify_cert_issued_by(signer_cert, &ca_tail[0], 0).is_ok()
                        && verify_ca_chain_validity(ca_tail, gen_time).is_ok()
                    {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            } else if verify_cert_issued_by(signer_cert, first, 0).is_ok()
                && verify_ca_chain_validity(&tsa.chain, gen_time).is_ok()
            {
                return Ok(());
            }
        }
    }

    Err(VerifyError::SigstoreVerificationFailed(
        "RFC 3161 TSA certificate does not chain to any trusted timestampAuthority".to_owned(),
    ))
}

/// Cryptographically verifies a single DER RFC 3161 `TimeStampToken` (or `TimeStampResp`) over
/// `artifact_signature` against `trust_root.tsas`, returning the authenticated `genTime` (Unix seconds).
#[allow(clippy::too_many_lines)]
fn verify_rfc3161_timestamp(
    raw_der: &[u8],
    artifact_signature: &[u8],
    trust_root: &SigstoreTrustRoot,
) -> Result<i64, VerifyError> {
    if trust_root.tsas.is_empty() {
        return Err(VerifyError::SigstoreVerificationFailed(
            "trust root contains no trusted timestampAuthorities".to_owned(),
        ));
    }

    let content_info = match CmsContentInfo::from_der(raw_der) {
        Ok(ci) if ci.content_type == OID_CMS_SIGNED_DATA => ci,
        _ => {
            let resp = Rfc3161TimeStampResp::from_der(raw_der).map_err(|e| {
                VerifyError::SigstoreVerificationFailed(format!("invalid RFC 3161 DER: {e}"))
            })?;
            let ci = resp.time_stamp_token.ok_or_else(|| {
                VerifyError::SigstoreVerificationFailed("TimeStampResp missing token".to_owned())
            })?;
            if ci.content_type != OID_CMS_SIGNED_DATA {
                return Err(VerifyError::SigstoreVerificationFailed(
                    "RFC 3161 token is not CMS SignedData".to_owned(),
                ));
            }
            ci
        }
    };

    if content_info.content.tag() != Tag::Sequence {
        return Err(VerifyError::SigstoreVerificationFailed(
            "CMS SignedData content is not an ASN.1 SEQUENCE".to_owned(),
        ));
    }
    let mut sd_reader = SliceReader::new(content_info.content.value())
        .map_err(|e| VerifyError::SigstoreVerificationFailed(format!("invalid SignedData: {e}")))?;
    let (tst_info_der, embedded_certs, signer_infos_raw) = (|| -> Result<_, der::Error> {
        let _version: u8 = sd_reader.decode()?;
        let _digest_algs: Any = sd_reader.decode()?;
        let encap: EncapsulatedContentInfo = sd_reader.decode()?;
        let mut certs = Vec::new();
        let mut signer_infos_any: Option<Any> = None;
        while !sd_reader.is_finished() {
            let item: Any = sd_reader.decode()?;
            if item.tag()
                == (Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber(0),
                })
            {
                let mut cert_reader = SliceReader::new(item.value())?;
                while !cert_reader.is_finished() {
                    if let Ok(c) = cert_reader.decode::<Certificate>() {
                        certs.push(c);
                    } else {
                        break;
                    }
                }
            } else if item.tag() == Tag::Set {
                signer_infos_any = Some(item);
            }
        }
        Ok((encap, certs, signer_infos_any))
    })()
    .map_err(|e: der::Error| {
        VerifyError::SigstoreVerificationFailed(format!("invalid CMS SignedData DER: {e}"))
    })
    .and_then(|(encap, certs, si_any)| {
        if encap.e_content_type != OID_ID_CT_TST_INFO {
            return Err(VerifyError::SigstoreVerificationFailed(
                "SignedData eContentType is not id-ct-TSTInfo".to_owned(),
            ));
        }
        let e_content = encap.e_content.ok_or_else(|| {
            VerifyError::SigstoreVerificationFailed("SignedData missing TSTInfo".to_owned())
        })?;
        let si = si_any.ok_or_else(|| {
            VerifyError::SigstoreVerificationFailed("SignedData missing signerInfos".to_owned())
        })?;
        Ok((e_content.as_bytes().to_vec(), certs, si.value().to_vec()))
    })?;

    let tst = parse_tst_info(&tst_info_der)?;
    let expected_sig_hash = hash_with_oid(tst.imprint.hash_algorithm.oid, artifact_signature)?;
    if !bool::from(
        tst.imprint
            .hashed_message
            .as_bytes()
            .ct_eq(&expected_sig_hash),
    ) {
        return Err(VerifyError::SigstoreVerificationFailed(
            "RFC 3161 TSTInfo messageImprint does not match artifact signature".to_owned(),
        ));
    }

    // Collect candidate TSA signer certs: embedded CMS certs + trusted TSA leaf certs.
    let mut candidate_signers: Vec<Certificate> = embedded_certs;
    for tsa in &trust_root.tsas {
        if let Some(leaf) = tsa.chain.first() {
            candidate_signers.push(leaf.clone());
        }
    }

    let mut signer_reader = SliceReader::new(&signer_infos_raw).map_err(|e| {
        VerifyError::SigstoreVerificationFailed(format!("invalid signerInfos: {e}"))
    })?;
    while !signer_reader.is_finished() {
        let si_any: Any = signer_reader.decode().map_err(|e| {
            VerifyError::SigstoreVerificationFailed(format!("invalid SignerInfo entry: {e}"))
        })?;
        let si_der = si_any
            .to_der()
            .map_err(|e| VerifyError::SigstoreVerificationFailed(e.to_string()))?;
        let si = parse_signer_info(&si_der)?;
        let signed_attrs_set = verify_signed_attrs_and_encode_set(
            &si.signed_attrs_raw_value,
            si.digest_alg.oid,
            &tst_info_der,
        )?;

        for cand in &candidate_signers {
            let Ok(pk) =
                ParsedPublicKey::from_spki(cand.tbs_certificate().subject_public_key_info())
            else {
                continue;
            };
            // Sigstore TSA SignerInfo may encode either ecdsa-with-SHA* or generic id-ecPublicKey.
            let alg_ok = pk.matches_sig_alg(si.sig_alg.oid) || si.sig_alg.oid == OID_EC_PUBLIC_KEY;
            if !alg_ok {
                continue;
            }
            if pk
                .verify_signature(&signed_attrs_set, &si.signature)
                .is_ok()
                && verify_tsa_signer_chain(cand, tst.gen_time, trust_root).is_ok()
            {
                return Ok(tst.gen_time);
            }
        }
    }

    Err(VerifyError::SigstoreVerificationFailed(
        "RFC 3161 timestamp signature failed verification against trusted TSAs".to_owned(),
    ))
}

fn verify_rekor_v1_set(
    entry: &TlogEntryJson,
    integrated_time: i64,
    tlog: &ParsedTlog,
) -> Result<i64, VerifyError> {
    if integrated_time <= 0 {
        return Err(VerifyError::RekorProofFailed(
            "Rekor v1 integratedTime must be positive".to_owned(),
        ));
    }
    let promise = entry.inclusion_promise.as_ref().ok_or_else(|| {
        VerifyError::RekorProofFailed(
            "missing inclusionPromise.signedEntryTimestamp (SET) and RFC 3161 TSA timestamp"
                .to_owned(),
        )
    })?;
    let set_sig = Base64::decode_vec(&promise.signed_entry_timestamp).map_err(|_| {
        VerifyError::RekorProofFailed("invalid signedEntryTimestamp base64".to_owned())
    })?;

    // Exact Rekor v1 RFC 8785 canonical JSON payload signed by tlog.public_key.
    let canonical_payload = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        entry.canonicalized_body,
        integrated_time,
        hex::encode(tlog.key_id),
        entry.log_index
    );
    tlog.public_key
        .verify_signature(canonical_payload.as_bytes(), &set_sig)
        .map_err(|_| {
            VerifyError::RekorProofFailed(
                "Rekor v1 inclusionPromise.signedEntryTimestamp signature invalid".to_owned(),
            )
        })?;
    Ok(integrated_time)
}

fn pem_to_der(pem_bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let pem_str = core::str::from_utf8(pem_bytes).map_err(|_| {
        VerifyError::RekorProofFailed("Rekor publicKey PEM is not valid UTF-8".to_owned())
    })?;
    let mut b64 = String::new();
    let mut state = 0_u8; // 0 = before BEGIN, 1 = inside body, 2 = after END
    for line in pem_str.lines() {
        let t = line.trim();
        match state {
            0 => {
                if t.is_empty() {
                    continue;
                }
                if t == "-----BEGIN CERTIFICATE-----" {
                    state = 1;
                } else {
                    return Err(VerifyError::RekorProofFailed(
                        "unexpected prefix before PEM BEGIN CERTIFICATE".to_owned(),
                    ));
                }
            }
            1 => {
                if t == "-----END CERTIFICATE-----" {
                    state = 2;
                } else {
                    b64.push_str(t);
                }
            }
            _ => {
                if !t.is_empty() {
                    return Err(VerifyError::RekorProofFailed(
                        "unexpected trailing content after PEM END CERTIFICATE".to_owned(),
                    ));
                }
            }
        }
    }
    if state != 2 || b64.is_empty() {
        return Err(VerifyError::RekorProofFailed(
            "truncated or empty PEM certificate in Rekor hashedrekord".to_owned(),
        ));
    }
    Base64::decode_vec(&b64).map_err(|_| {
        VerifyError::RekorProofFailed("invalid base64 in Rekor PEM certificate".to_owned())
    })
}

fn verify_hashedrekord_v002(
    v2: &serde_json::Value,
    artifact_sha256: &[u8; 32],
    expected_sig: &[u8],
    expected_leaf_cert_der: &[u8],
) -> Result<(), VerifyError> {
    let alg = v2
        .pointer("/data/algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if alg != "SHA2_256" {
        return Err(VerifyError::RekorProofFailed(format!(
            "unsupported hashedRekordV002 hash algorithm '{alg}'"
        )));
    }
    let digest_b64 = v2
        .pointer("/data/digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorProofFailed("hashedRekordV002 missing data.digest".to_owned())
        })?;
    let digest_bytes = Base64::decode_vec(digest_b64).map_err(|_| {
        VerifyError::RekorProofFailed("hashedRekordV002 invalid digest base64".to_owned())
    })?;
    if digest_bytes.len() != 32 || !bool::from(digest_bytes.as_slice().ct_eq(artifact_sha256)) {
        return Err(VerifyError::RekorProofFailed(
            "hashedRekordV002 data.digest does not match artifact SHA-256".to_owned(),
        ));
    }

    let sig_b64 = v2
        .pointer("/signature/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorProofFailed("hashedRekordV002 missing signature.content".to_owned())
        })?;
    let sig_bytes = Base64::decode_vec(sig_b64).map_err(|_| {
        VerifyError::RekorProofFailed("hashedRekordV002 invalid signature base64".to_owned())
    })?;
    if !bool::from(sig_bytes.as_slice().ct_eq(expected_sig)) {
        return Err(VerifyError::RekorProofFailed(
            "hashedRekordV002 signature does not match bundle messageSignature".to_owned(),
        ));
    }

    let cert_b64 = v2
        .pointer("/signature/verifier/x509Certificate/rawBytes")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorProofFailed(
                "hashedRekordV002 missing verifier x509Certificate".to_owned(),
            )
        })?;
    let cert_der = Base64::decode_vec(cert_b64).map_err(|_| {
        VerifyError::RekorProofFailed("hashedRekordV002 invalid cert base64".to_owned())
    })?;
    if !bool::from(cert_der.as_slice().ct_eq(expected_leaf_cert_der)) {
        return Err(VerifyError::RekorProofFailed(
            "hashedRekordV002 certificate does not match bundle leaf cert".to_owned(),
        ));
    }
    Ok(())
}

fn verify_hashedrekord_v001(
    spec: &serde_json::Value,
    artifact_sha256: &[u8; 32],
    expected_sig: &[u8],
    expected_leaf_cert_der: &[u8],
) -> Result<(), VerifyError> {
    let alg = spec
        .pointer("/data/hash/algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if alg != "sha256" {
        return Err(VerifyError::RekorProofFailed(format!(
            "unsupported hashedrekord hash algorithm '{alg}'"
        )));
    }
    let expected_hex = hex::encode(artifact_sha256);
    let actual_hex = spec
        .pointer("/data/hash/value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorProofFailed("hashedrekord missing data.hash.value".to_owned())
        })?;
    if !bool::from(actual_hex.as_bytes().ct_eq(expected_hex.as_bytes())) {
        return Err(VerifyError::RekorProofFailed(
            "hashedrekord data.hash.value does not match artifact SHA-256".to_owned(),
        ));
    }

    let sig_b64 = spec
        .pointer("/signature/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorProofFailed("hashedrekord missing signature.content".to_owned())
        })?;
    let sig_bytes = Base64::decode_vec(sig_b64).map_err(|_| {
        VerifyError::RekorProofFailed("hashedrekord invalid signature base64".to_owned())
    })?;
    if !bool::from(sig_bytes.as_slice().ct_eq(expected_sig)) {
        return Err(VerifyError::RekorProofFailed(
            "hashedrekord signature does not match bundle messageSignature".to_owned(),
        ));
    }

    let pk_b64 = spec
        .pointer("/signature/publicKey/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::RekorProofFailed("hashedrekord missing publicKey.content".to_owned())
        })?;
    let pk_raw = Base64::decode_vec(pk_b64).map_err(|_| {
        VerifyError::RekorProofFailed("hashedrekord invalid publicKey base64".to_owned())
    })?;
    let cert_der = if pk_raw.starts_with(b"-----BEGIN CERTIFICATE-----") {
        pem_to_der(&pk_raw)?
    } else {
        pk_raw
    };
    if !bool::from(cert_der.as_slice().ct_eq(expected_leaf_cert_der)) {
        return Err(VerifyError::RekorProofFailed(
            "hashedrekord certificate does not match bundle leaf cert".to_owned(),
        ));
    }
    Ok(())
}

/// Validates Rekor `canonicalizedBody`, strictly binding `expected_version` (`0.0.1` vs `0.0.2`)
/// to `apiVersion` and the exact corresponding schema.
fn verify_hashedrekord_body(
    body_bytes: &[u8],
    expected_version: &str,
    artifact_sha256: &[u8; 32],
    expected_sig: &[u8],
    expected_leaf_cert_der: &[u8],
) -> Result<(), VerifyError> {
    crate::reject_duplicate_json_keys(body_bytes).map_err(|e| {
        VerifyError::RekorProofFailed(format!("invalid canonicalizedBody JSON: {e}"))
    })?;
    let val: serde_json::Value = serde_json::from_slice(body_bytes).map_err(|e| {
        VerifyError::RekorProofFailed(format!("invalid canonicalizedBody JSON: {e}"))
    })?;

    let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind != "hashedrekord" {
        return Err(VerifyError::RekorProofFailed(format!(
            "unsupported Rekor entry kind '{kind}' (expected 'hashedrekord')"
        )));
    }
    let api_version = val.get("apiVersion").and_then(|v| v.as_str()).unwrap_or("");
    if api_version != expected_version {
        return Err(VerifyError::RekorProofFailed(format!(
            "Rekor body apiVersion '{api_version}' != kindVersion.version '{expected_version}'"
        )));
    }
    let spec = val
        .get("spec")
        .ok_or_else(|| VerifyError::RekorProofFailed("Rekor entry missing spec".to_owned()))?;

    match expected_version {
        "0.0.2" => {
            let v2 = spec.get("hashedRekordV002").ok_or_else(|| {
                VerifyError::RekorProofFailed(
                    "v0.0.2 body missing spec.hashedRekordV002".to_owned(),
                )
            })?;
            verify_hashedrekord_v002(v2, artifact_sha256, expected_sig, expected_leaf_cert_der)
        }
        "0.0.1" => {
            verify_hashedrekord_v001(spec, artifact_sha256, expected_sig, expected_leaf_cert_der)
        }
        other => Err(VerifyError::RekorProofFailed(format!(
            "unsupported hashedrekord version '{other}'"
        ))),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn verify_tlog_entry(
    entry: &TlogEntryJson,
    actual_sha256: &[u8; 32],
    sig_bytes: &[u8],
    leaf_cert: &Certificate,
    leaf_cert_der: &[u8],
    identity: &FulcioIdentity,
    verified_tsa_time: Option<i64>,
    trust_root: &SigstoreTrustRoot,
) -> Result<VerifiedSigstoreAttestation, VerifyError> {
    let entry_log_id = Base64::decode_vec(&entry.log_id.key_id)
        .ok()
        .filter(|v| v.len() == 32)
        .ok_or_else(|| VerifyError::RekorProofFailed("invalid tlog entry logId".to_owned()))?;
    let tlog = trust_root
        .tlogs
        .iter()
        .find(|t| bool::from(t.key_id.as_slice().ct_eq(entry_log_id.as_slice())))
        .ok_or_else(|| {
            VerifyError::RekorProofFailed(
                "tlog entry logId not found in trusted_root.json".to_owned(),
            )
        })?;

    if entry.kind_version.kind != "hashedrekord" {
        return Err(VerifyError::RekorProofFailed(format!(
            "unsupported tlog kind '{}'",
            entry.kind_version.kind
        )));
    }

    let body_bytes = Base64::decode_vec(&entry.canonicalized_body).map_err(|_| {
        VerifyError::RekorProofFailed("invalid canonicalizedBody base64".to_owned())
    })?;
    verify_hashedrekord_body(
        &body_bytes,
        &entry.kind_version.version,
        actual_sha256,
        sig_bytes,
        leaf_cert_der,
    )?;

    let proof = entry.inclusion_proof.as_ref().ok_or_else(|| {
        VerifyError::RekorProofFailed(
            "Rekor entry missing Merkle inclusionProof (required for Rekor v2)".to_owned(),
        )
    })?;
    if proof.log_index != entry.log_index {
        return Err(VerifyError::RekorProofFailed(
            "inclusionProof.logIndex does not match entry.logIndex".to_owned(),
        ));
    }
    if proof.hashes.len() > MAX_MERKLE_PROOF_HASHES {
        return Err(VerifyError::RekorProofFailed(
            "inclusionProof.hashes exceeds maximum Merkle tree depth".to_owned(),
        ));
    }
    let root_hash_vec = Base64::decode_vec(&proof.root_hash)
        .ok()
        .filter(|v| v.len() == 32)
        .ok_or_else(|| {
            VerifyError::RekorProofFailed("invalid inclusionProof.rootHash".to_owned())
        })?;
    let mut root_hash = [0_u8; 32];
    root_hash.copy_from_slice(&root_hash_vec);

    let mut hashes = Vec::with_capacity(proof.hashes.len());
    for h_b64 in &proof.hashes {
        let h_vec = Base64::decode_vec(h_b64)
            .ok()
            .filter(|v| v.len() == 32)
            .ok_or_else(|| {
                VerifyError::RekorProofFailed(
                    "invalid 32-byte hash in inclusionProof.hashes".to_owned(),
                )
            })?;
        let mut arr = [0_u8; 32];
        arr.copy_from_slice(&h_vec);
        hashes.push(arr);
    }

    verify_merkle_inclusion_proof(
        &body_bytes,
        proof.log_index,
        proof.tree_size,
        &hashes,
        &root_hash,
    )?;
    verify_c2sp_checkpoint(
        &proof.checkpoint.envelope,
        proof.tree_size,
        &root_hash,
        tlog,
    )?;

    // Determine cryptographically authenticated signing timestamp:
    // NEVER trust unsigned `entry.integrated_time`! Require either:
    //   (a) a verified RFC 3161 TSA timestamp (Rekor v2 standard), OR
    //   (b) a verified Rekor v1 `inclusionPromise.signedEntryTimestamp` (SET).
    let verified_timestamp = if let Some(tsa_ts) = verified_tsa_time {
        tsa_ts
    } else if let Some(raw_ts) = entry.integrated_time {
        verify_rekor_v1_set(entry, raw_ts, tlog)?
    } else {
        return Err(VerifyError::RekorProofFailed(
            "no authenticated signing timestamp (neither RFC 3161 TSA nor Rekor v1 SET present)"
                .to_owned(),
        ));
    };

    check_time_in_window(
        verified_timestamp,
        tlog.valid_start,
        tlog.valid_end,
        &tlog.base_url,
    )?;
    verify_leaf_against_cas(
        leaf_cert,
        verified_timestamp,
        &trust_root.cas,
        OID_KP_CODE_SIGNING,
        "Fulcio",
    )?;

    Ok(VerifiedSigstoreAttestation {
        oidc_issuer: identity.oidc_issuer.clone(),
        san_uri: identity.san_uri.clone(),
        source_repo_digest: identity.source_repo_digest.clone(),
        tlog_base_url: tlog.base_url.clone(),
        log_index: proof.log_index,
        tree_size: proof.tree_size,
        verified_timestamp,
        root_hash_hex: hex::encode(root_hash),
    })
}

/// Cryptographically verifies a Sigstore Bundle (`v0.3`/`v0.2`/`v0.1`) over `artifact_bytes`
/// against `trust_root` (Fulcio CA chain + RFC 3161 TSA / Rekor v1 SET authenticated timestamp +
/// Rekor v2/v1 Merkle inclusion proof + C2SP Signed Note checkpoint) and `policy`.
#[allow(clippy::too_many_lines)]
pub fn verify_sigstore_bundle(
    artifact_bytes: &[u8],
    bundle_json: &[u8],
    trust_root: &SigstoreTrustRoot,
    policy: &SigstorePolicy,
) -> Result<VerifiedSigstoreAttestation, VerifyError> {
    validate_oidc_issuer(&policy.oidc_issuer)?;
    validate_san_prefix(&policy.san_prefix)?;
    if bundle_json.len() > MAX_BUNDLE_JSON_LEN {
        return Err(VerifyError::InputTooLarge("sigstore bundle"));
    }
    crate::reject_duplicate_json_keys(bundle_json)?;
    let bundle: SigstoreBundleJson =
        serde_json::from_slice(bundle_json).map_err(|e| VerifyError::InvalidJson(e.to_string()))?;

    if !bundle
        .media_type
        .starts_with("application/vnd.dev.sigstore.bundle")
    {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "unsupported Sigstore bundle mediaType '{}'",
            bundle.media_type
        )));
    }

    if bundle.message_signature.message_digest.algorithm != "SHA2_256" {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "unsupported messageDigest algorithm '{}'",
            bundle.message_signature.message_digest.algorithm
        )));
    }
    let declared_digest = Base64::decode_vec(&bundle.message_signature.message_digest.digest)
        .map_err(|_| {
            VerifyError::SigstoreVerificationFailed("invalid messageDigest base64".to_owned())
        })?;
    let actual_sha256: [u8; 32] = Sha256::digest(artifact_bytes).into();
    if declared_digest.len() != 32 || !bool::from(declared_digest.as_slice().ct_eq(&actual_sha256))
    {
        return Err(VerifyError::SigstoreVerificationFailed(
            "artifact SHA-256 does not match Sigstore messageDigest".to_owned(),
        ));
    }

    let leaf_b64 = bundle
        .verification_material
        .certificate
        .as_ref()
        .map(|c| c.raw_bytes.as_str())
        .or_else(|| {
            bundle
                .verification_material
                .x509_certificate_chain
                .as_ref()
                .and_then(|chain| chain.certificates.first())
                .map(|c| c.raw_bytes.as_str())
        })
        .ok_or_else(|| {
            VerifyError::SigstoreVerificationFailed(
                "Sigstore bundle missing Fulcio leaf X.509 certificate".to_owned(),
            )
        })?;
    let leaf_cert_der = Base64::decode_vec(leaf_b64).map_err(|_| {
        VerifyError::SigstoreVerificationFailed("invalid leaf certificate base64".to_owned())
    })?;
    let leaf_cert = Certificate::from_der(&leaf_cert_der).map_err(|e| {
        VerifyError::SigstoreVerificationFailed(format!("invalid leaf certificate DER: {e}"))
    })?;

    let sig_bytes = Base64::decode_vec(&bundle.message_signature.signature).map_err(|_| {
        VerifyError::SigstoreVerificationFailed("invalid messageSignature base64".to_owned())
    })?;
    let leaf_pk =
        ParsedPublicKey::from_spki(leaf_cert.tbs_certificate().subject_public_key_info())?;
    leaf_pk.verify_signature(artifact_bytes, &sig_bytes)?;

    let identity = extract_fulcio_identity(&leaf_cert)?;
    if identity.oidc_issuer != policy.oidc_issuer {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "OIDC issuer '{}' != expected '{}'",
            identity.oidc_issuer, policy.oidc_issuer
        )));
    }
    if !identity.san_uri.starts_with(&policy.san_prefix) {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "SAN URI '{}' does not match expected prefix '{}'",
            identity.san_uri, policy.san_prefix
        )));
    }
    if identity.san_uri != policy.san_exact {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "SAN URI '{}' != expected exact tag URI '{}'",
            identity.san_uri, policy.san_exact
        )));
    }
    let Some(ref actual_commit) = identity.source_repo_digest else {
        return Err(VerifyError::SigstoreVerificationFailed(
            "Fulcio leaf cert missing Source Repository Digest (1.3.6.1.4.1.57264.1.13)".to_owned(),
        ));
    };
    if !bool::from(actual_commit.as_bytes().ct_eq(policy.git_commit.as_bytes())) {
        return Err(VerifyError::SigstoreVerificationFailed(format!(
            "Fulcio git commit '{actual_commit}' != manifest git_commit '{}'",
            policy.git_commit
        )));
    }

    // Verify any RFC 3161 TSA timestamp(s) over `sig_bytes` against trusted TSAs.
    let mut verified_tsa_time: Option<i64> = None;
    if let Some(ref tvd) = bundle.verification_material.timestamp_verification_data {
        for ts in &tvd.rfc3161_timestamps {
            let raw_ts = Base64::decode_vec(&ts.signed_timestamp).map_err(|_| {
                VerifyError::SigstoreVerificationFailed(
                    "invalid base64 in rfc3161Timestamps".to_owned(),
                )
            })?;
            if let Ok(gen_time) = verify_rfc3161_timestamp(&raw_ts, &sig_bytes, trust_root) {
                verified_tsa_time = Some(gen_time);
                break;
            }
        }
    }

    if bundle.verification_material.tlog_entries.is_empty() {
        return Err(VerifyError::RekorProofFailed(
            "Sigstore bundle contains zero Rekor transparency log entries".to_owned(),
        ));
    }

    let mut last_tlog_err = VerifyError::RekorProofFailed("no matching Rekor log entry".to_owned());
    for entry in &bundle.verification_material.tlog_entries {
        match verify_tlog_entry(
            entry,
            &actual_sha256,
            &sig_bytes,
            &leaf_cert,
            &leaf_cert_der,
            &identity,
            verified_tsa_time,
            trust_root,
        ) {
            Ok(att) => return Ok(att),
            Err(e) => last_tlog_err = e,
        }
    }

    Err(last_tlog_err)
}

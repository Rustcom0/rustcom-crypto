#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::de::DeserializeSeed;

pub mod error;
pub mod manifest;
pub mod rebuild;
pub mod sigstore;
pub mod site_audit;
pub mod skl_verify;

const MAX_JSON_DEPTH: usize = 64;

/// Rejects duplicate keys anywhere inside a JSON document (including Unicode-escaped duplicates
/// such as `"\u0073eq"` vs `"seq"`) as well as excessive nesting depth and trailing garbage,
/// defeating last-key-wins parser differentials across verifiers.
pub(crate) fn reject_duplicate_json_keys(raw: &[u8]) -> Result<(), VerifyError> {
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

    let mut de = serde_json::Deserializer::from_slice(raw);
    NoDupValue { depth: 0 }
        .deserialize(&mut de)
        .map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
    de.end()
        .map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
    Ok(())
}

pub use error::VerifyError;
pub use manifest::{
    MAX_MANIFEST_ARTIFACTS, MAX_MANIFEST_JSON_LEN, ManifestArtifact, RELEASE_MANIFEST_SCHEMA_V1,
    ReleaseManifestV1, ToolchainVersions, compute_sha256_hex, compute_sri_sha384,
    hash_manifest_artifact, is_lowercase_hex, is_valid_release_version, is_valid_sha256_digest,
};
pub use rebuild::{
    RebuildReport, build_docker_rebuild_args, run_deterministic_rebuild, verify_rebuilt_directory,
};
pub use sigstore::{
    DEFAULT_GITHUB_OIDC_ISSUER, DEFAULT_SOVRET_SAN_PREFIX,
    EMBEDDED_SIGSTORE_PUBLIC_GOOD_TRUST_ROOT, SigstorePolicy, SigstoreTrustRoot,
    VerifiedSigstoreAttestation, parse_rfc3339_utc_unix, verify_merkle_inclusion_proof,
    verify_sigstore_bundle,
};
pub use site_audit::{
    HeaderMap, MAX_AUDIT_BODY_LEN, SiteAuditReport, VerifiedScriptTag, audit_csp_header,
    audit_csp_headers, audit_html_scripts, audit_live_site, audit_page_content_type,
    extract_origin, fetch_bounded, verify_served_artifact,
};
pub use skl_verify::{
    MAX_CHECKPOINT_JSON_LEN, MAX_SKL_JSON_LEN, SklCheckpointJson, SklDocumentJson, SklEntryJson,
    parse_checkpoint_json, skl_entry_to_json, verify_skl_document,
};

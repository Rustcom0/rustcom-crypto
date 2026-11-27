use std::collections::BTreeSet;

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

use crate::VerifyError;

/// Current canonical `release-manifest.json` schema version (`1`).
pub const RELEASE_MANIFEST_SCHEMA_V1: u32 = 1;
/// Upper bound on manifest JSON size (`1 MiB`).
pub const MAX_MANIFEST_JSON_LEN: usize = 1024 * 1024;
/// Maximum artifacts declared in a single release manifest (`64`).
pub const MAX_MANIFEST_ARTIFACTS: usize = 64;

/// Pinned toolchain metadata embedded in `release-manifest.json` for reproducible rebuilds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainVersions {
    pub rustc: String,
    pub wasm_bindgen_cli: String,
    pub binaryen: String,
}

/// Single immutable release artifact (JS glue or WASM binary) with dual SHA-256 + SRI SHA-384 hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestArtifact {
    pub path: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub sri_sha384: String,
}

/// Canonical `release-manifest.json` served at `/.well-known/sovret-manifest.json` and signed
/// via Sigstore Cosign OIDC -> Rekor v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    pub schema_version: u32,
    pub release_version: String,
    pub git_commit: String,
    pub source_date_epoch: u64,
    pub builder_image_digest: String,
    pub toolchain: ToolchainVersions,
    pub artifacts: Vec<ManifestArtifact>,
}

/// Computes lowercase hex `SHA-256` (`64` chars) of `bytes`.
#[must_use]
pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Computes standard Subresource Integrity `sha384-<64-char base64>` of `bytes`.
#[must_use]
pub fn compute_sri_sha384(bytes: &[u8]) -> String {
    let digest = Sha384::digest(bytes);
    let b64 = Base64::encode_string(&digest);
    format!("sha384-{b64}")
}

/// Checks whether `s` is exact `N` lowercase hexadecimal ASCII characters.
#[must_use]
pub fn is_lowercase_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Checks whether `ver` is a safe semver string (`X.Y.Z` with optional `-prerelease`).
#[must_use]
pub fn is_valid_release_version(ver: &str) -> bool {
    if ver.is_empty() || ver.len() > 64 {
        return false;
    }
    let (core_part, pre_part) = match ver.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (ver, None),
    };
    let mut parts = core_part.split('.');
    let valid_core = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c), None) => [a, b, c]
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|ch| ch.is_ascii_digit())),
        _ => false,
    };
    if !valid_core {
        return false;
    }
    if let Some(pre) = pre_part {
        return !pre.is_empty()
            && pre.split('.').all(|ident| {
                !ident.is_empty()
                    && ident
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
    }
    true
}

/// Checks whether `digest` is a valid OCI SHA-256 digest (`sha256:<64 lowercase hex>`).
#[must_use]
pub fn is_valid_sha256_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex_part| is_lowercase_hex(hex_part, 64))
}

/// Validates an immutable versioned artifact path (must start with `/assets/v<release_version>/`,
/// contain only clean non-dot path segments with safe characters, and no `..`, `.`, `//`, `?`, or `#`).
fn validate_artifact_path(path: &str, release_version: &str) -> Result<(), VerifyError> {
    let expected_prefix = format!("/assets/v{release_version}/");
    if !path.starts_with(&expected_prefix) {
        return Err(VerifyError::InvalidManifest(format!(
            "artifact path '{path}' must start with '{expected_prefix}'"
        )));
    }
    if path.contains("..") || path.contains("//") || path.contains('?') || path.contains('#') {
        return Err(VerifyError::InvalidManifest(format!(
            "artifact path '{path}' contains forbidden traversal or query characters"
        )));
    }
    let file_part = &path[expected_prefix.len()..];
    if file_part.is_empty() {
        return Err(VerifyError::InvalidManifest(format!(
            "artifact path '{path}' is missing a filename"
        )));
    }
    for segment in file_part.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('.')
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(VerifyError::InvalidManifest(format!(
                "artifact path '{path}' contains invalid path segment '{segment}'"
            )));
        }
    }
    Ok(())
}

impl ReleaseManifestV1 {
    /// Parses and structurally validates a `release-manifest.json` document, rejecting
    /// duplicate JSON object keys and unknown fields.
    pub fn parse_and_validate(raw_json: &[u8]) -> Result<Self, VerifyError> {
        if raw_json.len() > MAX_MANIFEST_JSON_LEN {
            return Err(VerifyError::InputTooLarge("release-manifest.json"));
        }
        crate::reject_duplicate_json_keys(raw_json)?;
        let manifest: Self = serde_json::from_slice(raw_json)
            .map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates all structural, path, digest, and SRI invariants of this manifest.
    pub fn validate(&self) -> Result<(), VerifyError> {
        if self.schema_version != RELEASE_MANIFEST_SCHEMA_V1 {
            return Err(VerifyError::InvalidManifest(format!(
                "unsupported schema_version {}",
                self.schema_version
            )));
        }
        if !is_valid_release_version(&self.release_version) {
            return Err(VerifyError::InvalidManifest(format!(
                "invalid release_version '{}'",
                self.release_version
            )));
        }
        if !is_lowercase_hex(&self.git_commit, 40) {
            return Err(VerifyError::InvalidManifest(
                "git_commit must be a 40-character lowercase hex SHA-1".to_owned(),
            ));
        }
        if self.source_date_epoch == 0 {
            return Err(VerifyError::InvalidManifest(
                "source_date_epoch must be non-zero".to_owned(),
            ));
        }
        if !is_valid_sha256_digest(&self.builder_image_digest) {
            return Err(VerifyError::InvalidManifest(
                "builder_image_digest must be sha256:<64-lowercase-hex>".to_owned(),
            ));
        }
        if self.toolchain.rustc.is_empty()
            || self.toolchain.wasm_bindgen_cli.is_empty()
            || self.toolchain.binaryen.is_empty()
        {
            return Err(VerifyError::InvalidManifest(
                "toolchain version fields must be non-empty".to_owned(),
            ));
        }
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_MANIFEST_ARTIFACTS {
            return Err(VerifyError::InvalidManifest(format!(
                "artifact count {} outside 1..={MAX_MANIFEST_ARTIFACTS}",
                self.artifacts.len()
            )));
        }

        let mut seen_paths = BTreeSet::new();
        for art in &self.artifacts {
            validate_artifact_path(&art.path, &self.release_version)?;
            if !seen_paths.insert(art.path.as_str()) {
                return Err(VerifyError::InvalidManifest(format!(
                    "duplicate artifact path '{}'",
                    art.path
                )));
            }
            if art.size_bytes == 0 {
                return Err(VerifyError::InvalidManifest(format!(
                    "artifact '{}' has zero size_bytes",
                    art.path
                )));
            }
            if !is_lowercase_hex(&art.sha256, 64) {
                return Err(VerifyError::InvalidManifest(format!(
                    "artifact '{}' has invalid sha256 hex",
                    art.path
                )));
            }
            let sri_b64 = art.sri_sha384.strip_prefix("sha384-").ok_or_else(|| {
                VerifyError::InvalidManifest(format!(
                    "artifact '{}' sri_sha384 must start with 'sha384-'",
                    art.path
                ))
            })?;
            let decoded = Base64::decode_vec(sri_b64).map_err(|_| {
                VerifyError::InvalidManifest(format!(
                    "artifact '{}' has invalid base64 in sri_sha384",
                    art.path
                ))
            })?;
            if decoded.len() != 48 {
                return Err(VerifyError::InvalidManifest(format!(
                    "artifact '{}' sri_sha384 must decode to 48 bytes (SHA-384)",
                    art.path
                )));
            }
            if !matches!(
                art.media_type.as_str(),
                "text/javascript" | "application/javascript" | "application/wasm" | "text/css"
            ) {
                return Err(VerifyError::InvalidManifest(format!(
                    "artifact '{}' has unsupported media_type '{}'",
                    art.path, art.media_type
                )));
            }
        }
        Ok(())
    }

    /// Looks up a declared artifact by exact immutable URL path.
    #[must_use]
    pub fn find_artifact(&self, path: &str) -> Option<&ManifestArtifact> {
        self.artifacts.iter().find(|a| a.path == path)
    }

    /// Verifies `bytes` against `artifact`'s `size_bytes`, `sha256`, and `sri_sha384` in constant time.
    pub fn verify_artifact_bytes(
        artifact: &ManifestArtifact,
        bytes: &[u8],
    ) -> Result<(), VerifyError> {
        let actual_len =
            u64::try_from(bytes.len()).map_err(|_| VerifyError::ArtifactHashMismatch {
                path: artifact.path.clone(),
                reason: "artifact size overflow".to_owned(),
            })?;
        if actual_len != artifact.size_bytes {
            return Err(VerifyError::ArtifactHashMismatch {
                path: artifact.path.clone(),
                reason: format!("expected {} bytes, got {actual_len}", artifact.size_bytes),
            });
        }

        let actual_sha256 = compute_sha256_hex(bytes);
        if !bool::from(actual_sha256.as_bytes().ct_eq(artifact.sha256.as_bytes())) {
            return Err(VerifyError::ArtifactHashMismatch {
                path: artifact.path.clone(),
                reason: format!(
                    "sha256 mismatch (expected {}, got {actual_sha256})",
                    artifact.sha256
                ),
            });
        }

        let actual_sri = compute_sri_sha384(bytes);
        if !bool::from(actual_sri.as_bytes().ct_eq(artifact.sri_sha384.as_bytes())) {
            return Err(VerifyError::ArtifactHashMismatch {
                path: artifact.path.clone(),
                reason: format!(
                    "sri_sha384 mismatch (expected {}, got {actual_sri})",
                    artifact.sri_sha384
                ),
            });
        }
        Ok(())
    }

    /// Constructs a canonical, validated `ReleaseManifestV1` from local built artifact files.
    pub fn build_from_artifacts(
        release_version: String,
        git_commit: String,
        source_date_epoch: u64,
        builder_image_digest: String,
        toolchain: ToolchainVersions,
        mut artifacts: Vec<ManifestArtifact>,
    ) -> Result<Self, VerifyError> {
        artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        let manifest = Self {
            schema_version: RELEASE_MANIFEST_SCHEMA_V1,
            release_version,
            git_commit,
            source_date_epoch,
            builder_image_digest,
            toolchain,
            artifacts,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Encodes a deterministic, pretty-printed canonical JSON manifest with trailing newline.
    pub fn to_canonical_json(&self) -> Result<String, VerifyError> {
        self.validate()?;
        let mut s = serde_json::to_string_pretty(self)
            .map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
        s.push('\n');
        Ok(s)
    }
}

/// Builds a [`ManifestArtifact`] entry by hashing `bytes`.
#[must_use]
pub fn hash_manifest_artifact(path: String, media_type: String, bytes: &[u8]) -> ManifestArtifact {
    ManifestArtifact {
        path,
        media_type,
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: compute_sha256_hex(bytes),
        sri_sha384: compute_sri_sha384(bytes),
    }
}

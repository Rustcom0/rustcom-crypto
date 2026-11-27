use core::fmt;

/// Verification errors returned by `sovret-verify`.
///
/// Errors describe the exact failed verification invariant without exposing secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Input exceeded safety length bounds.
    InputTooLarge(&'static str),
    /// JSON parsing failed.
    InvalidJson(String),
    /// Manifest schema, version, git commit, digest, path, or SRI field was invalid.
    InvalidManifest(String),
    /// Artifact bytes did not match expected `size_bytes`, `sha256`, or `sri_sha384`.
    ArtifactHashMismatch { path: String, reason: String },
    /// Sigstore trust root JSON or key encoding was invalid.
    InvalidTrustRoot(String),
    /// Sigstore bundle framing, certificate, policy, or signature check failed.
    SigstoreVerificationFailed(String),
    /// Rekor Merkle inclusion proof or C2SP signed checkpoint verification failed.
    RekorProofFailed(String),
    /// HTTP `Content-Security-Policy` header failed strict JS-Proof rules.
    InvalidCsp(String),
    /// HTML `<script>` or inline handler audit failed (inline script, unlisted script, bad SRI).
    HtmlScriptViolation(String),
    /// Served HTTP header or asset policy violation (content-type, cache-control, status).
    ServedAssetViolation(String),
    /// `/.well-known/sovret-skl.json` parsing or cryptographic chain verification failed.
    SklVerificationFailed(String),
    /// Deterministic Docker `--rebuild` execution or output comparison failed.
    RebuildVerificationFailed(String),
    /// Network or filesystem I/O error.
    Io(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge(what) => write!(f, "{what} exceeded safety size bound"),
            Self::InvalidJson(msg) => write!(f, "invalid JSON: {msg}"),
            Self::InvalidManifest(msg) => write!(f, "invalid release manifest: {msg}"),
            Self::ArtifactHashMismatch { path, reason } => {
                write!(f, "artifact hash mismatch for {path}: {reason}")
            }
            Self::InvalidTrustRoot(msg) => write!(f, "invalid Sigstore trust root: {msg}"),
            Self::SigstoreVerificationFailed(msg) => {
                write!(f, "Sigstore verification failed: {msg}")
            }
            Self::RekorProofFailed(msg) => write!(f, "Rekor v2 proof verification failed: {msg}"),
            Self::InvalidCsp(msg) => write!(f, "CSP policy violation: {msg}"),
            Self::HtmlScriptViolation(msg) => write!(f, "HTML script audit violation: {msg}"),
            Self::ServedAssetViolation(msg) => write!(f, "served asset violation: {msg}"),
            Self::SklVerificationFailed(msg) => write!(f, "SKL verification failed: {msg}"),
            Self::RebuildVerificationFailed(msg) => {
                write!(f, "deterministic rebuild verification failed: {msg}")
            }
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

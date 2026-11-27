#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sovret_crypto_core::VaultRole;
use sovret_verify::{
    DEFAULT_GITHUB_OIDC_ISSUER, DEFAULT_SOVRET_SAN_PREFIX, MAX_AUDIT_BODY_LEN,
    MAX_CHECKPOINT_JSON_LEN, MAX_MANIFEST_JSON_LEN, MAX_SKL_JSON_LEN, ReleaseManifestV1,
    SigstorePolicy, SigstoreTrustRoot, ToolchainVersions, VerifyError, audit_live_site,
    compute_sha256_hex, extract_origin, fetch_bounded, hash_manifest_artifact,
    parse_checkpoint_json, run_deterministic_rebuild, verify_sigstore_bundle, verify_skl_document,
};

const MAX_BUNDLE_FILE_LEN: usize = 4 * 1024 * 1024;
const MAX_TRUST_ROOT_FILE_LEN: usize = 2 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "sovret-verify",
    version,
    about = "Independent JS-Proof, Sigstore Rekor v2, SKL, and deterministic WASM rebuild verifier"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Emit a canonical, validated `release-manifest.json` from deterministic build outputs.
    BuildManifest(BuildManifestArgs),
    /// Verify a `release-manifest.json` against a Sigstore Bundle (Fulcio + Rekor v2 + TSA).
    Manifest(ManifestArgs),
    /// Verify a store's append-only `/.well-known/sovret-skl.json` Ed25519 Signed Key List.
    Skl(SklArgs),
    /// Rebuild WASM artifacts from `git_commit` inside the pinned Docker builder and compare hashes.
    Rebuild(RebuildArgs),
    /// End-to-end live site audit: Sigstore Rekor v2 manifest + CSP + HTML scripts + WASM + SKL (+ optional --rebuild).
    Site(SiteArgs),
}

#[derive(clap::Args)]
struct BuildManifestArgs {
    #[arg(long)]
    version: String,
    #[arg(long)]
    git_commit: String,
    #[arg(long)]
    source_date_epoch: u64,
    #[arg(long)]
    builder_digest: String,
    #[arg(long)]
    rustc_version: String,
    #[arg(long)]
    wasm_bindgen_version: String,
    #[arg(long)]
    binaryen_version: String,
    /// Artifact specs formatted as `<url_path>=<media_type>=<local_file>` (repeatable).
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<String>,
    #[arg(long)]
    out: PathBuf,
}

#[derive(clap::Args)]
struct ManifestArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
    /// Override the embedded Sigstore Public Good trust root (REQUIRES --unsafe-custom-trust-root).
    #[arg(long)]
    trust_root: Option<PathBuf>,
    /// Explicitly acknowledge replacing the embedded Sigstore Public Good trust root.
    #[arg(long, default_value_t = false)]
    unsafe_custom_trust_root: bool,
    #[arg(long, default_value = DEFAULT_GITHUB_OIDC_ISSUER)]
    expected_issuer: String,
    #[arg(long, default_value = DEFAULT_SOVRET_SAN_PREFIX)]
    expected_san_prefix: String,
}

#[derive(clap::Args)]
struct SklArgs {
    /// Local JSON path or `https://...` URL for `sovret-skl.json`.
    #[arg(long)]
    skl: String,
    #[arg(long)]
    tenant_id: String,
    #[arg(long)]
    pinned_checkpoint: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    allow_insecure_http: bool,
}

#[derive(clap::Args)]
struct RebuildArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    repo_dir: PathBuf,
    #[arg(long)]
    builder_image: String,
    #[arg(long)]
    work_dir: PathBuf,
    #[arg(long, default_value_t = false)]
    allow_network: bool,
}

#[derive(clap::Args)]
#[allow(clippy::struct_excessive_bools)]
struct SiteArgs {
    #[arg(long)]
    url: String,
    #[arg(long)]
    tenant_id: Option<String>,
    #[arg(long)]
    pinned_checkpoint: Option<PathBuf>,
    /// Override the embedded Sigstore Public Good trust root (REQUIRES --unsafe-custom-trust-root).
    #[arg(long)]
    trust_root: Option<PathBuf>,
    /// Explicitly acknowledge replacing the embedded Sigstore Public Good trust root.
    #[arg(long, default_value_t = false)]
    unsafe_custom_trust_root: bool,
    #[arg(long, default_value = DEFAULT_GITHUB_OIDC_ISSUER)]
    expected_issuer: String,
    #[arg(long, default_value = DEFAULT_SOVRET_SAN_PREFIX)]
    expected_san_prefix: String,
    #[arg(long, default_value_t = false)]
    allow_insecure_http: bool,
    #[arg(long, default_value_t = false)]
    skip_immutable_cache_check: bool,
    /// Optional deterministic Docker `--rebuild` cross-check against local repo checkout.
    #[arg(long, default_value_t = false)]
    rebuild: bool,
    #[arg(long)]
    repo_dir: Option<PathBuf>,
    #[arg(long)]
    builder_image: Option<String>,
    #[arg(long)]
    work_dir: Option<PathBuf>,
}

/// Reads a local file with an explicit upper bound to prevent unbounded memory allocation.
fn read_file_bounded(
    path: &Path,
    max_len: usize,
    label: &'static str,
) -> Result<Vec<u8>, VerifyError> {
    let file = File::open(path).map_err(|e| VerifyError::Io(format!("{}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take((max_len as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| VerifyError::Io(format!("{}: {e}", path.display())))?;
    if bytes.len() > max_len {
        return Err(VerifyError::InputTooLarge(label));
    }
    Ok(bytes)
}

/// Escapes ASCII control / ANSI escape sequences before printing untrusted remote strings to a terminal.
fn sanitize_terminal_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_control() {
            for esc in ch.escape_default() {
                out.push(esc);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn load_trust_root(
    path: Option<&Path>,
    allow_unsafe_custom: bool,
) -> Result<SigstoreTrustRoot, VerifyError> {
    if let Some(p) = path {
        if !allow_unsafe_custom {
            return Err(VerifyError::InvalidTrustRoot(
                "--trust-root replaces the embedded Sigstore Public Good trust root and requires --unsafe-custom-trust-root"
                    .to_owned(),
            ));
        }
        let bytes = read_file_bounded(p, MAX_TRUST_ROOT_FILE_LEN, "trusted_root.json")?;
        let fingerprint = compute_sha256_hex(&bytes);
        eprintln!(
            "WARNING: using custom Sigstore trust root '{}' (sha256={fingerprint}) instead of embedded Public Good root",
            sanitize_terminal_str(&p.display().to_string())
        );
        SigstoreTrustRoot::from_json_bytes(&bytes)
    } else {
        if allow_unsafe_custom {
            return Err(VerifyError::InvalidTrustRoot(
                "--unsafe-custom-trust-root requires --trust-root <PATH>".to_owned(),
            ));
        }
        SigstoreTrustRoot::public_good()
    }
}

fn cmd_build_manifest(args: BuildManifestArgs) -> Result<(), VerifyError> {
    let mut parsed_artifacts = Vec::with_capacity(args.artifacts.len());
    for spec in args.artifacts {
        let mut parts = spec.splitn(3, '=');
        let (Some(url_path), Some(media_type), Some(file_path)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(VerifyError::InvalidManifest(format!(
                "invalid --artifact spec '{spec}' (expected path=media_type=file)"
            )));
        };
        let bytes = read_file_bounded(Path::new(file_path), MAX_AUDIT_BODY_LEN, "artifact file")?;
        parsed_artifacts.push(hash_manifest_artifact(
            url_path.to_owned(),
            media_type.to_owned(),
            &bytes,
        ));
    }
    let manifest = ReleaseManifestV1::build_from_artifacts(
        args.version,
        args.git_commit,
        args.source_date_epoch,
        args.builder_digest,
        ToolchainVersions {
            rustc: args.rustc_version,
            wasm_bindgen_cli: args.wasm_bindgen_version,
            binaryen: args.binaryen_version,
        },
        parsed_artifacts,
    )?;
    let json = manifest.to_canonical_json()?;
    fs::write(&args.out, json.as_bytes())
        .map_err(|e| VerifyError::Io(format!("writing {}: {e}", args.out.display())))?;
    println!(
        "OK: wrote canonical release-manifest.json ({} artifacts) to {}",
        manifest.artifacts.len(),
        args.out.display()
    );
    Ok(())
}

fn cmd_manifest(args: &ManifestArgs) -> Result<(), VerifyError> {
    let manifest_bytes = read_file_bounded(
        &args.manifest,
        MAX_MANIFEST_JSON_LEN,
        "release-manifest.json",
    )?;
    let parsed = ReleaseManifestV1::parse_and_validate(&manifest_bytes)?;
    let bundle_bytes = read_file_bounded(&args.bundle, MAX_BUNDLE_FILE_LEN, "sigstore bundle")?;
    let tr = load_trust_root(args.trust_root.as_deref(), args.unsafe_custom_trust_root)?;
    let policy = SigstorePolicy::for_manifest(
        args.expected_issuer.clone(),
        args.expected_san_prefix.clone(),
        &parsed,
    )?;
    let att = verify_sigstore_bundle(&manifest_bytes, &bundle_bytes, &tr, &policy)?;
    println!(
        "OK: manifest v{} ({}) verified via {} (log_index={}, tree_size={}, ts={}, san={})",
        sanitize_terminal_str(&parsed.release_version),
        sanitize_terminal_str(&parsed.git_commit),
        sanitize_terminal_str(&att.tlog_base_url),
        att.log_index,
        att.tree_size,
        att.verified_timestamp,
        sanitize_terminal_str(&att.san_uri)
    );
    Ok(())
}

fn cmd_skl(args: &SklArgs) -> Result<(), VerifyError> {
    let skl_bytes = if args.skl.starts_with("https://") || args.skl.starts_with("http://") {
        let (_headers, body) = fetch_bounded(&args.skl, args.allow_insecure_http)?;
        body
    } else {
        read_file_bounded(Path::new(&args.skl), MAX_SKL_JSON_LEN, "sovret-skl.json")?
    };
    let cp = match args.pinned_checkpoint {
        Some(ref p) => {
            let raw = read_file_bounded(p, MAX_CHECKPOINT_JSON_LEN, "SKL checkpoint")?;
            Some(parse_checkpoint_json(&raw)?)
        }
        None => None,
    };
    let verified = verify_skl_document(&args.tenant_id, &skl_bytes, cp.as_ref())?;
    println!(
        "OK: SKL verified (latest_seq={}, tip_hash={}, identity_pk={}, org_master_ver={:?})",
        verified.latest_seq(),
        hex::encode(verified.latest_entry_hash()),
        hex::encode(verified.current_identity_pk().to_bytes()),
        verified.active_key(VaultRole::OrgMaster).map(|(v, _)| v),
    );
    Ok(())
}

fn cmd_rebuild(args: &RebuildArgs) -> Result<(), VerifyError> {
    let manifest_bytes = read_file_bounded(
        &args.manifest,
        MAX_MANIFEST_JSON_LEN,
        "release-manifest.json",
    )?;
    let parsed = ReleaseManifestV1::parse_and_validate(&manifest_bytes)?;
    let report = run_deterministic_rebuild(
        &parsed,
        &args.repo_dir,
        &args.builder_image,
        &args.work_dir,
        args.allow_network,
    )?;
    println!(
        "OK: deterministic Docker rebuild of {} verified ({} artifacts match byte-for-byte)",
        sanitize_terminal_str(&report.git_commit),
        report.verified_artifacts
    );
    Ok(())
}

fn cmd_site(args: &SiteArgs) -> Result<(), VerifyError> {
    let origin = extract_origin(&args.url)?;
    let manifest_url = format!("{origin}/.well-known/sovret-manifest.json");
    let bundle_url = format!("{origin}/.well-known/sovret-manifest.sigstore.json");

    let (_m_hdrs, manifest_bytes) = fetch_bounded(&manifest_url, args.allow_insecure_http)?;
    let (_b_hdrs, bundle_bytes) = fetch_bounded(&bundle_url, args.allow_insecure_http)?;
    let manifest = ReleaseManifestV1::parse_and_validate(&manifest_bytes)?;

    let tr = load_trust_root(args.trust_root.as_deref(), args.unsafe_custom_trust_root)?;
    let policy = SigstorePolicy::for_manifest(
        args.expected_issuer.clone(),
        args.expected_san_prefix.clone(),
        &manifest,
    )?;
    let att = verify_sigstore_bundle(&manifest_bytes, &bundle_bytes, &tr, &policy)?;
    let site_report = audit_live_site(
        &args.url,
        &manifest,
        args.allow_insecure_http,
        !args.skip_immutable_cache_check,
    )?;

    if let Some(ref tid) = args.tenant_id {
        let skl_url = format!("{origin}/.well-known/sovret-skl.json");
        let (_s_hdrs, skl_bytes) = fetch_bounded(&skl_url, args.allow_insecure_http)?;
        let cp = match args.pinned_checkpoint {
            Some(ref p) => {
                let raw = read_file_bounded(p, MAX_CHECKPOINT_JSON_LEN, "SKL checkpoint")?;
                Some(parse_checkpoint_json(&raw)?)
            }
            None => None,
        };
        let skl = verify_skl_document(tid, &skl_bytes, cp.as_ref())?;
        println!(
            "OK: SKL chain verified (latest_seq={}, tip_hash={})",
            skl.latest_seq(),
            hex::encode(skl.latest_entry_hash())
        );
    }

    if args.rebuild {
        let repo = args.repo_dir.as_deref().ok_or_else(|| {
            VerifyError::RebuildVerificationFailed("--rebuild requires --repo-dir".to_owned())
        })?;
        let img = args.builder_image.as_deref().ok_or_else(|| {
            VerifyError::RebuildVerificationFailed("--rebuild requires --builder-image".to_owned())
        })?;
        let work = args.work_dir.as_deref().ok_or_else(|| {
            VerifyError::RebuildVerificationFailed("--rebuild requires --work-dir".to_owned())
        })?;
        let rep = run_deterministic_rebuild(&manifest, repo, img, work, false)?;
        println!(
            "OK: deterministic rebuild matched ({} artifacts)",
            rep.verified_artifacts
        );
    }

    println!(
        "OK: JS-Proof site audit PASSED for {} (manifest v{}, Rekor log_index={}, ts={}, scripts={}, assets={})",
        sanitize_terminal_str(&site_report.page_url),
        sanitize_terminal_str(&manifest.release_version),
        att.log_index,
        att.verified_timestamp,
        site_report.scripts_verified.len(),
        site_report.artifacts_verified
    );
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Commands::BuildManifest(args) => cmd_build_manifest(args),
        Commands::Manifest(args) => cmd_manifest(&args),
        Commands::Skl(args) => cmd_skl(&args),
        Commands::Rebuild(args) => cmd_rebuild(&args),
        Commands::Site(args) => cmd_site(&args),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!(
                "VERIFICATION FAILED: {}",
                sanitize_terminal_str(&err.to_string())
            );
            ExitCode::FAILURE
        }
    }
}

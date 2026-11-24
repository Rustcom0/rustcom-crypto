use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use subtle::ConstantTimeEq;

use crate::VerifyError;
use crate::manifest::{ReleaseManifestV1, is_lowercase_hex, is_valid_sha256_digest};
use crate::site_audit::MAX_AUDIT_BODY_LEN;

const MAX_REBUILD_WALK_DEPTH: usize = 16;
const MAX_REBUILD_ENTRIES: usize = 1024;

/// Result of a deterministic Docker `--rebuild` verification against a [`ReleaseManifestV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildReport {
    pub git_commit: String,
    pub builder_image: String,
    pub verified_artifacts: usize,
}

fn validate_builder_image_ref(
    builder_image_ref: &str,
    expected_digest: &str,
) -> Result<(), VerifyError> {
    if builder_image_ref.is_empty()
        || builder_image_ref.starts_with('-')
        || builder_image_ref
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(VerifyError::RebuildVerificationFailed(
            "invalid builder image reference".to_owned(),
        ));
    }
    let Some((repo_part, digest_part)) = builder_image_ref.split_once('@') else {
        return Err(VerifyError::RebuildVerificationFailed(
            "builder image reference must be digest-pinned (<image>@sha256:<64-hex>)".to_owned(),
        ));
    };
    if repo_part.is_empty()
        || !repo_part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
    {
        return Err(VerifyError::RebuildVerificationFailed(
            "builder image repository name contains forbidden characters".to_owned(),
        ));
    }
    if !is_valid_sha256_digest(digest_part) {
        return Err(VerifyError::RebuildVerificationFailed(
            "builder image digest must be sha256:<64-lowercase-hex>".to_owned(),
        ));
    }
    if !bool::from(digest_part.as_bytes().ct_eq(expected_digest.as_bytes())) {
        return Err(VerifyError::RebuildVerificationFailed(format!(
            "builder image digest '{digest_part}' does not match manifest builder_image_digest '{expected_digest}'"
        )));
    }
    Ok(())
}

fn validate_bind_mount_path<'a>(path: &'a Path, label: &str) -> Result<&'a str, VerifyError> {
    let s = path
        .to_str()
        .ok_or_else(|| VerifyError::RebuildVerificationFailed(format!("non-UTF-8 {label} path")))?;
    if s.is_empty() || s.starts_with('-') {
        return Err(VerifyError::RebuildVerificationFailed(format!(
            "{label} path contains forbidden bind-mount characters"
        )));
    }
    // On Windows, permit only an ASCII drive-letter prefix (`^[A-Za-z]:[\\/]`) so paths such as
    // `C:\Users\...` work with Docker Desktop while still forbidding colons anywhere else.
    let tail = {
        #[cfg(windows)]
        {
            let b = s.as_bytes();
            if b.len() >= 3
                && b[0].is_ascii_alphabetic()
                && b[1] == b':'
                && matches!(b[2], b'\\' | b'/')
            {
                &s[2..]
            } else {
                s
            }
        }
        #[cfg(not(windows))]
        {
            s
        }
    };
    if tail
        .bytes()
        .any(|b| matches!(b, b',' | b':' | b'"' | b'\0' | b'\r' | b'\n'))
    {
        return Err(VerifyError::RebuildVerificationFailed(format!(
            "{label} path contains forbidden bind-mount characters"
        )));
    }
    Ok(s)
}

/// Builds the fixed `docker run` argument vector (zero shell interpolation) for a deterministic
/// offline rebuild of `manifest` from `source_dir` into `output_dir`.
pub fn build_docker_rebuild_args(
    manifest: &ReleaseManifestV1,
    builder_image_ref: &str,
    source_dir: &Path,
    output_dir: &Path,
    allow_network: bool,
) -> Result<Vec<String>, VerifyError> {
    manifest.validate()?;
    if !is_lowercase_hex(&manifest.git_commit, 40) {
        return Err(VerifyError::RebuildVerificationFailed(
            "invalid git_commit in manifest".to_owned(),
        ));
    }
    if !is_valid_sha256_digest(&manifest.builder_image_digest) {
        return Err(VerifyError::RebuildVerificationFailed(
            "invalid builder_image_digest in manifest".to_owned(),
        ));
    }
    validate_builder_image_ref(builder_image_ref, &manifest.builder_image_digest)?;

    let src_str = validate_bind_mount_path(source_dir, "source directory")?;
    let out_str = validate_bind_mount_path(output_dir, "output directory")?;

    let mut args = vec!["run".to_owned(), "--rm".to_owned()];
    if !allow_network {
        args.push("--network=none".to_owned());
    }
    args.extend([
        "-e".to_owned(),
        format!("SOURCE_DATE_EPOCH={}", manifest.source_date_epoch),
        "-e".to_owned(),
        format!("RELEASE_VERSION={}", manifest.release_version),
        "-e".to_owned(),
        format!("GIT_COMMIT={}", manifest.git_commit),
        "-e".to_owned(),
        format!("BUILDER_IMAGE_DIGEST={}", manifest.builder_image_digest),
        "--mount".to_owned(),
        format!("type=bind,source={src_str},target=/src,readonly"),
        "--mount".to_owned(),
        format!("type=bind,source={out_str},target=/out"),
        builder_image_ref.to_owned(),
    ]);
    Ok(args)
}

fn read_rebuilt_artifact_bounded(
    candidate: &Path,
    artifact_path: &str,
    expected_size: u64,
) -> Result<Vec<u8>, VerifyError> {
    let max_body = u64::try_from(MAX_AUDIT_BODY_LEN).unwrap_or(u64::MAX);
    if expected_size > max_body {
        return Err(VerifyError::InputTooLarge("rebuilt artifact"));
    }
    let meta = fs::symlink_metadata(candidate).map_err(|e| {
        VerifyError::RebuildVerificationFailed(format!(
            "missing rebuilt artifact '{}': {e}",
            candidate.display()
        ))
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(VerifyError::RebuildVerificationFailed(format!(
            "rebuilt artifact '{}' must be a regular non-symlink file",
            candidate.display()
        )));
    }
    let actual_meta_len = meta.len();
    if actual_meta_len > max_body {
        return Err(VerifyError::InputTooLarge("rebuilt artifact"));
    }
    if actual_meta_len != expected_size {
        return Err(VerifyError::ArtifactHashMismatch {
            path: artifact_path.to_owned(),
            reason: format!("expected {expected_size} bytes, got {actual_meta_len}"),
        });
    }

    let file = File::open(candidate).map_err(|e| {
        VerifyError::RebuildVerificationFailed(format!(
            "opening rebuilt artifact '{}': {e}",
            candidate.display()
        ))
    })?;
    let cap = usize::try_from(expected_size)
        .map_err(|_| VerifyError::InputTooLarge("rebuilt artifact"))?;
    let mut bytes = Vec::with_capacity(cap);
    file.take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| {
            VerifyError::RebuildVerificationFailed(format!(
                "reading rebuilt artifact '{}': {e}",
                candidate.display()
            ))
        })?;
    Ok(bytes)
}

fn audit_rebuilt_tree(
    dir: &Path,
    rel_prefix: &str,
    depth: usize,
    seen_entries: &mut usize,
    expected_rel_paths: &BTreeSet<String>,
    expected_dirs: &BTreeSet<String>,
) -> Result<(), VerifyError> {
    if depth > MAX_REBUILD_WALK_DEPTH {
        return Err(VerifyError::RebuildVerificationFailed(
            "rebuilt directory exceeded maximum nesting depth".to_owned(),
        ));
    }
    let entries = fs::read_dir(dir).map_err(|e| VerifyError::Io(e.to_string()))?;
    for entry_res in entries {
        *seen_entries += 1;
        if *seen_entries > MAX_REBUILD_ENTRIES {
            return Err(VerifyError::RebuildVerificationFailed(
                "rebuilt directory exceeded maximum entry count".to_owned(),
            ));
        }
        let entry = entry_res.map_err(|e| VerifyError::Io(e.to_string()))?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                VerifyError::RebuildVerificationFailed(
                    "non-UTF-8 entry encountered in rebuilt directory".to_owned(),
                )
            })?;
        let rel_path = if rel_prefix.is_empty() {
            name
        } else {
            format!("{rel_prefix}/{name}")
        };
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| VerifyError::Io(e.to_string()))?;
        let ftype = meta.file_type();
        if ftype.is_symlink() {
            return Err(VerifyError::RebuildVerificationFailed(format!(
                "forbidden symlink '{rel_path}' emitted in rebuilt directory"
            )));
        }
        if ftype.is_dir() {
            if !expected_dirs.contains(&rel_path) {
                return Err(VerifyError::RebuildVerificationFailed(format!(
                    "unexpected extra directory '{rel_path}' emitted in rebuilt directory"
                )));
            }
            audit_rebuilt_tree(
                &path,
                &rel_path,
                depth + 1,
                seen_entries,
                expected_rel_paths,
                expected_dirs,
            )?;
        } else if ftype.is_file() {
            if rel_path == "release-manifest.json" || expected_rel_paths.contains(&rel_path) {
                continue;
            }
            return Err(VerifyError::RebuildVerificationFailed(format!(
                "unexpected extra file '{rel_path}' emitted in rebuilt directory"
            )));
        } else {
            return Err(VerifyError::RebuildVerificationFailed(format!(
                "forbidden non-regular file '{rel_path}' emitted in rebuilt directory"
            )));
        }
    }
    Ok(())
}

/// Verifies every artifact file emitted inside `rebuilt_dir` against `manifest` in constant time
/// using bounded pre-checked reads, supporting nested manifest paths while recursively rejecting
/// symlinks and unexpected extra files or subdirectories.
pub fn verify_rebuilt_directory(
    manifest: &ReleaseManifestV1,
    rebuilt_dir: &Path,
) -> Result<usize, VerifyError> {
    manifest.validate()?;
    let prefix = format!("/assets/v{}/", manifest.release_version);
    let mut expected_rel_paths = BTreeSet::new();
    let mut expected_dirs = BTreeSet::new();

    for art in &manifest.artifacts {
        let rel = art.path.strip_prefix(&prefix).ok_or_else(|| {
            VerifyError::RebuildVerificationFailed(format!(
                "artifact path '{}' does not match release version prefix '{prefix}'",
                art.path
            ))
        })?;
        expected_rel_paths.insert(rel.to_owned());

        // Verify no ancestor directory along nested artifact paths is a symlink and record expected dirs.
        let segments: Vec<&str> = rel.split('/').collect();
        let mut cursor = rebuilt_dir.to_path_buf();
        let mut rel_dir = String::new();
        for &dir_seg in &segments[..segments.len().saturating_sub(1)] {
            if !rel_dir.is_empty() {
                rel_dir.push('/');
            }
            rel_dir.push_str(dir_seg);
            expected_dirs.insert(rel_dir.clone());
            cursor.push(dir_seg);
            let dir_meta = fs::symlink_metadata(&cursor).map_err(|e| {
                VerifyError::RebuildVerificationFailed(format!(
                    "missing rebuilt directory '{}': {e}",
                    cursor.display()
                ))
            })?;
            if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
                return Err(VerifyError::RebuildVerificationFailed(format!(
                    "rebuilt ancestor '{}' must be a regular non-symlink directory",
                    cursor.display()
                )));
            }
        }

        let mut candidate = rebuilt_dir.to_path_buf();
        for seg in segments {
            candidate.push(seg);
        }
        let bytes = read_rebuilt_artifact_bounded(&candidate, &art.path, art.size_bytes)?;
        ReleaseManifestV1::verify_artifact_bytes(art, &bytes)?;
    }

    // Recursively reject unexpected extra files, subdirectories, and symlinks anywhere in rebuilt_dir.
    let mut seen_entries = 0_usize;
    audit_rebuilt_tree(
        rebuilt_dir,
        "",
        0,
        &mut seen_entries,
        &expected_rel_paths,
        &expected_dirs,
    )?;

    Ok(manifest.artifacts.len())
}

/// Exports the clean git tree for `git_commit` into `export_dir` via `git archive | tar -x`
/// (zero dirty working-tree files or untracked `.cargo/config.toml` contamination).
fn export_clean_git_commit(
    repo_dir: &Path,
    git_commit: &str,
    export_dir: &Path,
) -> Result<(), VerifyError> {
    fs::create_dir_all(export_dir).map_err(|e| VerifyError::Io(e.to_string()))?;

    let mut archive_child = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["archive", "--format=tar", git_commit])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| {
            VerifyError::RebuildVerificationFailed(format!("failed to invoke git archive: {e}"))
        })?;

    let archive_stdout = archive_child.stdout.take().ok_or_else(|| {
        VerifyError::RebuildVerificationFailed("failed to capture git archive stdout".to_owned())
    })?;

    let tar_status = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(export_dir)
        .stdin(Stdio::from(archive_stdout))
        .status()
        .map_err(|e| {
            VerifyError::RebuildVerificationFailed(format!("failed to invoke tar: {e}"))
        })?;

    let git_status = archive_child.wait().map_err(|e| {
        VerifyError::RebuildVerificationFailed(format!("waiting for git archive failed: {e}"))
    })?;

    if !git_status.success() || !tar_status.success() {
        return Err(VerifyError::RebuildVerificationFailed(format!(
            "clean export of git commit '{git_commit}' failed (git={git_status}, tar={tar_status})"
        )));
    }
    Ok(())
}

/// Executes a reproducible Docker rebuild of `manifest.git_commit` from a clean `git archive`
/// export of `repo_dir` using the digest-pinned builder image (`builder_image_ref`) and verifies
/// all rebuilt artifacts match `manifest` byte-for-byte.
pub fn run_deterministic_rebuild(
    manifest: &ReleaseManifestV1,
    repo_dir: &Path,
    builder_image_ref: &str,
    work_dir: &Path,
    allow_network: bool,
) -> Result<RebuildReport, VerifyError> {
    manifest.validate()?;
    validate_builder_image_ref(builder_image_ref, &manifest.builder_image_digest)?;

    // Verify commit exists in repo and export ONLY clean tracked commit contents.
    let clean_src = work_dir.join("clean-src");
    let out_dir = work_dir.join("dist");
    if clean_src.exists() {
        fs::remove_dir_all(&clean_src).map_err(|e| VerifyError::Io(e.to_string()))?;
    }
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).map_err(|e| VerifyError::Io(e.to_string()))?;
    }
    export_clean_git_commit(repo_dir, &manifest.git_commit, &clean_src)?;
    fs::create_dir_all(&out_dir).map_err(|e| VerifyError::Io(e.to_string()))?;

    let args = build_docker_rebuild_args(
        manifest,
        builder_image_ref,
        &clean_src,
        &out_dir,
        allow_network,
    )?;
    let status = Command::new("docker").args(&args).status().map_err(|e| {
        VerifyError::RebuildVerificationFailed(format!("failed to invoke docker: {e}"))
    })?;
    if !status.success() {
        return Err(VerifyError::RebuildVerificationFailed(format!(
            "deterministic Docker build exited with status {status}"
        )));
    }

    let verified_artifacts = verify_rebuilt_directory(manifest, &out_dir)?;
    Ok(RebuildReport {
        git_commit: manifest.git_commit.clone(),
        builder_image: builder_image_ref.to_owned(),
        verified_artifacts,
    })
}

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use html5gum::{DefaultEmitter, Error as HtmlError, Token, Tokenizer};
use subtle::ConstantTimeEq;

use crate::VerifyError;
use crate::manifest::{ManifestArtifact, ReleaseManifestV1};

/// Maximum HTML or served asset size fetched/audited (`16 MiB`).
pub const MAX_AUDIT_BODY_LEN: usize = 16 * 1024 * 1024;
/// Global HTTP request timeout (`30 s`).
const HTTP_GLOBAL_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP connect timeout (`10 s`).
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const FORBIDDEN_ELEMENTS: &[&str] = &[
    "iframe",
    "object",
    "embed",
    "applet",
    "svg",
    "math",
    "portal",
    "frame",
    "frameset",
    "noscript",
    "noembed",
    "noframes",
    "xmp",
    "plaintext",
];

const URI_ATTRS: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "xlink:href",
    "data",
    "poster",
];

/// Multi-valued HTTP response header map (`lowercase-name -> Vec<value>`).
pub type HeaderMap = BTreeMap<String, Vec<String>>;

/// A verified `<script src="..." integrity="...">` tag observed in checkout HTML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedScriptTag {
    pub src_path: String,
    pub integrity: String,
}

/// Summary report returned after auditing a live checkout origin's CSP, HTML scripts, and served assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteAuditReport {
    pub page_url: String,
    pub scripts_verified: Vec<VerifiedScriptTag>,
    pub artifacts_verified: usize,
}

fn is_allowed_script_src(tokens: &[String], allow_wasm_unsafe_eval: bool) -> bool {
    if tokens.is_empty() {
        return false;
    }
    if tokens == ["'none'"] {
        return true;
    }
    let mut has_self = false;
    for tok in tokens {
        match tok.as_str() {
            "'self'" => has_self = true,
            "'wasm-unsafe-eval'" if allow_wasm_unsafe_eval => {}
            _ => return false,
        }
    }
    has_self
}

/// Parses a single CSP policy (already split on `,`) and checks syntax + duplicate directives.
fn parse_single_csp_policy(policy: &str) -> Result<BTreeMap<String, Vec<String>>, VerifyError> {
    let trimmed_policy = policy.trim();
    if trimmed_policy.is_empty() {
        return Err(VerifyError::InvalidCsp(
            "empty Content-Security-Policy policy segment".to_owned(),
        ));
    }

    let mut directives: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for raw_dir in trimmed_policy.split(';') {
        let trimmed = raw_dir.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut tokens = trimmed.split_ascii_whitespace();
        let Some(name_raw) = tokens.next() else {
            continue;
        };
        let name = name_raw.to_ascii_lowercase();
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(VerifyError::InvalidCsp(format!(
                "invalid CSP directive name '{name}'"
            )));
        }
        let values: Vec<String> = tokens.map(str::to_ascii_lowercase).collect();
        if directives.insert(name.clone(), values).is_some() {
            return Err(VerifyError::InvalidCsp(format!(
                "duplicate CSP directive '{name}' is forbidden"
            )));
        }
    }
    if directives.is_empty() {
        return Err(VerifyError::InvalidCsp(
            "Content-Security-Policy contains no directives".to_owned(),
        ));
    }
    Ok(directives)
}

/// Evaluates whether a single parsed CSP policy satisfies all strict JS-Proof allowlist invariants.
fn check_strict_csp_policy(directives: &BTreeMap<String, Vec<String>>) -> Result<(), VerifyError> {
    let script_vals = directives
        .get("script-src")
        .or_else(|| directives.get("default-src"))
        .ok_or_else(|| {
            VerifyError::InvalidCsp(
                "CSP must declare script-src (or default-src fallback)".to_owned(),
            )
        })?;
    if !is_allowed_script_src(script_vals, true) {
        return Err(VerifyError::InvalidCsp(format!(
            "script-src/default-src must be strictly 'none' or 'self' [optional 'wasm-unsafe-eval'], got '{}'",
            script_vals.join(" ")
        )));
    }

    if let Some(elem_vals) = directives.get("script-src-elem")
        && !is_allowed_script_src(elem_vals, false)
    {
        return Err(VerifyError::InvalidCsp(format!(
            "script-src-elem must be strictly 'none' or 'self', got '{}'",
            elem_vals.join(" ")
        )));
    }

    if let Some(attr_vals) = directives.get("script-src-attr")
        && attr_vals.as_slice() != ["'none'"]
    {
        return Err(VerifyError::InvalidCsp(format!(
            "script-src-attr must be strictly 'none', got '{}'",
            attr_vals.join(" ")
        )));
    }

    let obj_vals = directives
        .get("object-src")
        .or_else(|| directives.get("default-src"));
    if obj_vals.map(Vec::as_slice) != Some(&["'none'".to_owned()]) {
        return Err(VerifyError::InvalidCsp(
            "CSP effective object-src must be 'none'".to_owned(),
        ));
    }

    let base_vals = directives.get("base-uri").ok_or_else(|| {
        VerifyError::InvalidCsp("CSP must explicitly set base-uri 'none' or 'self'".to_owned())
    })?;
    if base_vals.as_slice() != ["'none'"] && base_vals.as_slice() != ["'self'"] {
        return Err(VerifyError::InvalidCsp(
            "CSP base-uri must be strictly 'none' or 'self'".to_owned(),
        ));
    }

    // Effective worker-src fallback chain per W3C CSP3: worker-src -> child-src -> script-src -> default-src.
    let worker_vals = directives
        .get("worker-src")
        .or_else(|| directives.get("child-src"))
        .or_else(|| directives.get("script-src"))
        .or_else(|| directives.get("default-src"));
    if worker_vals.map(Vec::as_slice) != Some(&["'none'".to_owned()]) {
        return Err(VerifyError::InvalidCsp(
            "CSP effective worker-src (via worker-src/child-src) must resolve to 'none'".to_owned(),
        ));
    }

    Ok(())
}

/// Strictly audits one or more HTTP `Content-Security-Policy` headers against Rustcom's
/// zero-install JS-Proof allowlist invariants.
///
/// Splits every header on `,` per W3C CSP3 §3.1, validates syntax and zero duplicate directives
/// on every policy, and requires at least one policy to satisfy ALL strict invariants
/// (in CSP3, multiple policies intersect so a strict policy cannot be weakened by another).
pub fn audit_csp_headers(headers: &[&str]) -> Result<(), VerifyError> {
    if headers.is_empty() {
        return Err(VerifyError::InvalidCsp(
            "missing Content-Security-Policy header".to_owned(),
        ));
    }
    let mut parsed_policies = Vec::new();
    for hdr in headers {
        if hdr.trim().is_empty() {
            return Err(VerifyError::InvalidCsp(
                "empty Content-Security-Policy header".to_owned(),
            ));
        }
        for policy_segment in hdr.split(',') {
            parsed_policies.push(parse_single_csp_policy(policy_segment)?);
        }
    }

    let mut last_err = VerifyError::InvalidCsp("no CSP policy satisfied JS-Proof rules".to_owned());
    for policy in &parsed_policies {
        match check_strict_csp_policy(policy) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Convenience wrapper auditing a single `Content-Security-Policy` header string.
pub fn audit_csp_header(csp: &str) -> Result<(), VerifyError> {
    audit_csp_headers(&[csp])
}

struct OpenScriptTag {
    src: Option<String>,
    integrity: Option<String>,
    script_type: Option<String>,
    body: String,
}

fn check_html_parse_error(err: HtmlError) -> Result<(), VerifyError> {
    if matches!(
        err,
        HtmlError::DuplicateAttribute
            | HtmlError::EndTagWithAttributes
            | HtmlError::EndTagWithTrailingSolidus
            | HtmlError::AbruptClosingOfEmptyComment
            | HtmlError::IncorrectlyClosedComment
            | HtmlError::NestedComment
            | HtmlError::CdataInHtmlContent
            | HtmlError::EofInCdata
            | HtmlError::EofInTag
            | HtmlError::EofInComment
            | HtmlError::EofInScriptHtmlCommentLikeText
            | HtmlError::UnexpectedSolidusInTag
    ) {
        return Err(VerifyError::HtmlScriptViolation(format!(
            "forbidden HTML5 tokenizer error (possible smuggling): {err:?}"
        )));
    }
    Ok(())
}

/// Validates that a checkout page's `Content-Type` header (or `<meta http-equiv="content-type">`)
/// is strictly `text/html` WITH an explicit `charset=utf-8` parameter, preventing browsers from
/// falling back to `windows-1252` or alternate charsets (`iso-2022-jp`/`utf-16`) and causing
/// parser differentials against the verifier's UTF-8 decoder.
pub fn audit_page_content_type(content_type: Option<&str>) -> Result<(), VerifyError> {
    let ct = content_type.ok_or_else(|| {
        VerifyError::ServedAssetViolation(
            "checkout page missing required Content-Type header".to_owned(),
        )
    })?;
    let mut parts = ct.split(';');
    let mime = parts
        .next()
        .map(|m| m.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if mime != "text/html" {
        return Err(VerifyError::ServedAssetViolation(format!(
            "checkout page Content-Type MIME '{mime}' must be strictly 'text/html'"
        )));
    }
    let mut saw_charset = false;
    for param in parts {
        let trimmed = param.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err(VerifyError::ServedAssetViolation(format!(
                "malformed Content-Type parameter '{trimmed}'"
            )));
        };
        if k.trim().eq_ignore_ascii_case("charset") {
            if saw_charset {
                return Err(VerifyError::ServedAssetViolation(
                    "duplicate charset parameter in Content-Type".to_owned(),
                ));
            }
            saw_charset = true;
            let raw_val = v.trim();
            // Accept only RFC 9110 unquoted token or balanced double-quoted string (reject single quotes).
            let val = raw_val
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(raw_val);
            if !val.eq_ignore_ascii_case("utf-8") {
                return Err(VerifyError::ServedAssetViolation(format!(
                    "checkout page charset '{val}' must be UTF-8"
                )));
            }
        }
    }
    if !saw_charset {
        return Err(VerifyError::ServedAssetViolation(
            "checkout page Content-Type must explicitly declare charset=utf-8".to_owned(),
        ));
    }
    Ok(())
}

fn finalize_script_tag(
    script: OpenScriptTag,
    manifest: &ReleaseManifestV1,
) -> Result<Option<VerifiedScriptTag>, VerifyError> {
    if let Some(src) = script.src {
        if !script.body.trim().is_empty() {
            return Err(VerifyError::HtmlScriptViolation(format!(
                "<script src=\"{src}\"> must not contain inline body content"
            )));
        }
        let artifact = manifest.find_artifact(&src).ok_or_else(|| {
            VerifyError::HtmlScriptViolation(format!(
                "unlisted <script src=\"{src}\"> not declared in release-manifest.json"
            ))
        })?;
        if !matches!(
            artifact.media_type.as_str(),
            "text/javascript" | "application/javascript"
        ) {
            return Err(VerifyError::HtmlScriptViolation(format!(
                "<script src=\"{src}\"> references non-JavaScript manifest artifact '{}'",
                artifact.media_type
            )));
        }
        let integrity = script.integrity.ok_or_else(|| {
            VerifyError::HtmlScriptViolation(format!(
                "<script src=\"{src}\"> missing required SRI integrity attribute"
            ))
        })?;
        if !bool::from(
            integrity
                .trim()
                .as_bytes()
                .ct_eq(artifact.sri_sha384.as_bytes()),
        ) {
            return Err(VerifyError::HtmlScriptViolation(format!(
                "<script src=\"{src}\"> SRI integrity mismatch"
            )));
        }
        return Ok(Some(VerifiedScriptTag {
            src_path: src,
            integrity: integrity.trim().to_owned(),
        }));
    }

    // Only inert, valid JSON / JSON-LD data blocks are permitted inline.
    let mime = script
        .script_type
        .as_deref()
        .map(|t| t.split(';').next().unwrap_or(t).trim().to_ascii_lowercase())
        .unwrap_or_default();
    if mime != "application/ld+json" && mime != "application/json" {
        return Err(VerifyError::HtmlScriptViolation(format!(
            "forbidden inline executable <script> (type='{mime}')"
        )));
    }
    if script.body.to_ascii_lowercase().contains("</script") {
        return Err(VerifyError::HtmlScriptViolation(
            "inline JSON script block contains forbidden '</script' sequence".to_owned(),
        ));
    }
    serde_json::from_str::<serde_json::Value>(&script.body).map_err(|_| {
        VerifyError::HtmlScriptViolation(format!(
            "inline <script type=\"{mime}\"> body is not valid JSON"
        ))
    })?;
    Ok(None)
}

fn audit_start_tag(
    tag: &html5gum::StartTag<()>,
    open_script: &mut Option<OpenScriptTag>,
) -> Result<(), VerifyError> {
    let tag_name = String::from_utf8_lossy(&tag.name.0).to_ascii_lowercase();
    if FORBIDDEN_ELEMENTS.contains(&tag_name.as_str()) {
        return Err(VerifyError::HtmlScriptViolation(format!(
            "forbidden active element <{tag_name}> on JS-Proof page"
        )));
    }

    for (raw_k, raw_v) in &tag.attributes {
        let attr_name = String::from_utf8_lossy(&raw_k.0).to_ascii_lowercase();
        let attr_val = String::from_utf8_lossy(&raw_v.value.0);

        if (attr_name.starts_with("on") && attr_name.len() >= 3) || attr_name == "srcdoc" {
            return Err(VerifyError::HtmlScriptViolation(format!(
                "forbidden inline handler/srcdoc attribute '{attr_name}' on <{tag_name}>"
            )));
        }
        if URI_ATTRS.contains(&attr_name.as_str()) {
            let norm: String = attr_val
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
                .collect();
            let lower_norm = norm.to_ascii_lowercase();
            if lower_norm.starts_with("javascript:")
                || lower_norm.starts_with("vbscript:")
                || lower_norm.starts_with("data:")
            {
                return Err(VerifyError::HtmlScriptViolation(format!(
                    "forbidden active URI scheme in <{tag_name} {attr_name}=...>"
                )));
            }
        }
    }

    if tag_name == "base"
        && let Some(href_v) = tag.attributes.get(b"href".as_slice())
    {
        let href_str = String::from_utf8_lossy(&href_v.value.0);
        if href_str.trim() != "/" {
            return Err(VerifyError::HtmlScriptViolation(format!(
                "forbidden <base href=\"{href_str}\"> tag"
            )));
        }
    }

    if tag_name == "meta" {
        if let Some(charset_v) = tag.attributes.get(b"charset".as_slice()) {
            let cs = String::from_utf8_lossy(&charset_v.value.0);
            if !cs.trim().eq_ignore_ascii_case("utf-8") {
                return Err(VerifyError::HtmlScriptViolation(format!(
                    "forbidden non-UTF-8 <meta charset=\"{cs}\">"
                )));
            }
        }
        if let Some(equiv_v) = tag.attributes.get(b"http-equiv".as_slice()) {
            let equiv = String::from_utf8_lossy(&equiv_v.value.0);
            if equiv.trim().eq_ignore_ascii_case("refresh") {
                return Err(VerifyError::HtmlScriptViolation(
                    "forbidden <meta http-equiv=\"refresh\"> redirect tag".to_owned(),
                ));
            }
            if equiv.trim().eq_ignore_ascii_case("content-type") {
                let content_str = tag
                    .attributes
                    .get(b"content".as_slice())
                    .map(|v| String::from_utf8_lossy(&v.value.0).into_owned());
                audit_page_content_type(content_str.as_deref()).map_err(|e| {
                    VerifyError::HtmlScriptViolation(format!(
                        "forbidden <meta http-equiv=\"content-type\">: {e}"
                    ))
                })?;
            }
        }
    }

    if tag_name == "script" {
        if tag.self_closing {
            return Err(VerifyError::HtmlScriptViolation(
                "self-closing <script/> syntax is forbidden".to_owned(),
            ));
        }
        let src = tag
            .attributes
            .get(b"src".as_slice())
            .map(|v| String::from_utf8_lossy(&v.value.0).into_owned());
        let integrity = tag
            .attributes
            .get(b"integrity".as_slice())
            .map(|v| String::from_utf8_lossy(&v.value.0).into_owned());
        let script_type = tag
            .attributes
            .get(b"type".as_slice())
            .map(|v| String::from_utf8_lossy(&v.value.0).into_owned());
        *open_script = Some(OpenScriptTag {
            src,
            integrity,
            script_type,
            body: String::new(),
        });
    }
    Ok(())
}

/// Strictly audits checkout HTML against `manifest` using a spec-compliant WHATWG HTML5
/// tokenizer (`html5gum` with RCDATA/RAWTEXT/ScriptData state switching and entity decoding):
/// - Fails closed on smuggling-relevant HTML5 parse errors (duplicate attrs, abrupt/bang
///   comments `<!-->`/`--!>`, non-minimal end tags `</script/>`, EOF in tag/comment).
/// - Forbids dangerous active elements (`<iframe>`, `<object>`, `<embed>`, `<applet>`, `<svg>`,
///   `<math>`, `<portal>`, `<frame>`, `<frameset>`).
/// - Rejects ALL inline `on*=` event handlers, `srcdoc`, and `javascript:`/`vbscript:`/`data:`
///   URI schemes (post-entity-decoding) on URI attributes (`href`, `src`, `action`, `formaction`,
///   `xlink:href`, `data`, `poster`).
/// - Rejects `<base href=...>` pointing outside `/` and `<meta http-equiv="refresh">`.
/// - Enforces ZERO unlisted `<script src="...">` URLs, constant-time SRI match, empty src body,
///   and strict `serde_json` validation on inline `application/json` / `application/ld+json` blocks.
pub fn audit_html_scripts(
    html: &str,
    manifest: &ReleaseManifestV1,
) -> Result<Vec<VerifiedScriptTag>, VerifyError> {
    if html.len() > MAX_AUDIT_BODY_LEN {
        return Err(VerifyError::InputTooLarge("checkout HTML"));
    }
    manifest.validate()?;

    let mut emitter: DefaultEmitter<()> = DefaultEmitter::new_with_span();
    emitter.naively_switch_states(true);
    let tokenizer = Tokenizer::new_with_emitter(html, emitter);

    let mut verified_scripts = Vec::new();
    let mut open_script: Option<OpenScriptTag> = None;

    for token_res in tokenizer {
        let token = token_res.map_err(|e| {
            VerifyError::HtmlScriptViolation(format!("HTML5 tokenization failed: {e}"))
        })?;

        match token {
            Token::Error(err) => check_html_parse_error(err.value)?,
            Token::String(text) => {
                if let Some(ref mut script) = open_script {
                    let chunk = core::str::from_utf8(&text.value.0).map_err(|_| {
                        VerifyError::HtmlScriptViolation(
                            "non-UTF-8 content inside <script>".to_owned(),
                        )
                    })?;
                    script.body.push_str(chunk);
                }
            }
            Token::StartTag(tag) => audit_start_tag(&tag, &mut open_script)?,
            Token::EndTag(tag) => {
                let tag_name = String::from_utf8_lossy(&tag.name.0).to_ascii_lowercase();
                if tag_name == "script"
                    && let Some(script) = open_script.take()
                    && let Some(verified) = finalize_script_tag(script, manifest)?
                {
                    verified_scripts.push(verified);
                }
            }
            Token::Comment(_) | Token::Doctype(_) | Token::ProcessingInstruction(_) => {}
        }
    }

    if open_script.is_some() {
        return Err(VerifyError::HtmlScriptViolation(
            "unterminated <script> element at EOF".to_owned(),
        ));
    }

    Ok(verified_scripts)
}

/// Validates a served JS/WASM artifact's HTTP headers (`Content-Type`, `Cache-Control`) and
/// verifies its exact `size_bytes`, `sha256`, and `sri_sha384` in constant time.
pub fn verify_served_artifact(
    artifact: &ManifestArtifact,
    content_type: Option<&str>,
    cache_control: Option<&str>,
    body: &[u8],
    require_immutable_cache: bool,
) -> Result<(), VerifyError> {
    if let Some(ct) = content_type {
        let mime = ct
            .split(';')
            .next()
            .unwrap_or(ct)
            .trim()
            .to_ascii_lowercase();
        let expected_ok = match artifact.media_type.as_str() {
            "application/wasm" => mime == "application/wasm",
            "text/javascript" | "application/javascript" => {
                mime == "text/javascript" || mime == "application/javascript"
            }
            other => mime == other,
        };
        if !expected_ok {
            return Err(VerifyError::ServedAssetViolation(format!(
                "artifact '{}' served with unexpected Content-Type '{ct}' (expected '{}')",
                artifact.path, artifact.media_type
            )));
        }
    } else {
        return Err(VerifyError::ServedAssetViolation(format!(
            "artifact '{}' missing Content-Type header",
            artifact.path
        )));
    }

    if require_immutable_cache {
        let has_immutable = cache_control.is_some_and(|cc| {
            cc.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("immutable"))
        });
        if !has_immutable {
            return Err(VerifyError::ServedAssetViolation(format!(
                "artifact '{}' missing immutable Cache-Control directive",
                artifact.path
            )));
        }
    }

    ReleaseManifestV1::verify_artifact_bytes(artifact, body)
}

/// Fetches a bounded HTTP response (`<= MAX_AUDIT_BODY_LEN`) via pure-Rust `ureq` (`rustls`)
/// with redirects disabled (`max_redirects = 0`) and strict timeouts to prevent HTTPS->HTTP
/// downgrade, SSRF redirects, or cross-origin confusion.
pub fn fetch_bounded(
    url: &str,
    allow_insecure_http: bool,
) -> Result<(HeaderMap, Vec<u8>), VerifyError> {
    let _origin = extract_origin(url)?;
    if !(url.starts_with("https://") || allow_insecure_http && url.starts_with("http://")) {
        return Err(VerifyError::ServedAssetViolation(format!(
            "refusing non-HTTPS URL '{url}' (pass --allow-insecure-http only for localhost testing)"
        )));
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(HTTP_GLOBAL_TIMEOUT))
        .timeout_connect(Some(HTTP_CONNECT_TIMEOUT))
        .build()
        .into();

    let resp = agent
        .get(url)
        .call()
        .map_err(|e| VerifyError::Io(format!("GET {url} failed: {e}")))?;

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(VerifyError::ServedAssetViolation(format!(
            "GET {url} returned non-2xx HTTP status {status} (redirects are forbidden)"
        )));
    }

    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in resp.headers() {
        if let Ok(val_str) = v.to_str() {
            headers
                .entry(k.as_str().to_ascii_lowercase())
                .or_default()
                .push(val_str.to_owned());
        }
    }

    let mut reader = resp
        .into_body()
        .into_reader()
        .take((MAX_AUDIT_BODY_LEN as u64) + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| VerifyError::Io(format!("reading body from {url} failed: {e}")))?;
    if bytes.len() > MAX_AUDIT_BODY_LEN {
        return Err(VerifyError::InputTooLarge("HTTP response body"));
    }

    Ok((headers, bytes))
}

fn validate_authority(authority: &str) -> Result<(), VerifyError> {
    if authority.is_empty()
        || authority.len() > 255
        || authority.bytes().any(|b| {
            b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'@' | b'?' | b'#' | b'\\' | b'/')
        })
    {
        return Err(VerifyError::ServedAssetViolation(
            "invalid URL authority".to_owned(),
        ));
    }

    let (host, port_opt) = if let Some(rest) = authority.strip_prefix('[') {
        let (ipv6, after) = rest.split_once(']').ok_or_else(|| {
            VerifyError::ServedAssetViolation("unclosed IPv6 literal in URL".to_owned())
        })?;
        if ipv6.is_empty()
            || !ipv6
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(VerifyError::ServedAssetViolation(
                "invalid IPv6 literal in URL".to_owned(),
            ));
        }
        let port_opt = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            Some(p)
        } else {
            return Err(VerifyError::ServedAssetViolation(
                "unexpected characters after IPv6 host".to_owned(),
            ));
        };
        (ipv6, port_opt)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h, Some(p))
    } else {
        (authority, None)
    };

    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(VerifyError::ServedAssetViolation(
            "invalid hostname in URL".to_owned(),
        ));
    }

    if let Some(port_str) = port_opt {
        let port: u16 = port_str
            .parse()
            .map_err(|_| VerifyError::ServedAssetViolation("invalid port in URL".to_owned()))?;
        if port == 0 {
            return Err(VerifyError::ServedAssetViolation(
                "port 0 is invalid in URL".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Strictly extracts `scheme://host[:port]` origin from an `https://` or `http://` URL.
pub fn extract_origin(url: &str) -> Result<String, VerifyError> {
    if url
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return Err(VerifyError::ServedAssetViolation(
            "URL contains forbidden whitespace, control, or backslash characters".to_owned(),
        ));
    }
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        VerifyError::ServedAssetViolation("invalid URL (missing scheme)".to_owned())
    })?;
    if scheme != "https" && scheme != "http" {
        return Err(VerifyError::ServedAssetViolation(format!(
            "unsupported URL scheme '{scheme}' (expected https or http)"
        )));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    validate_authority(authority)?;
    Ok(format!("{scheme}://{authority}"))
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    context: &str,
) -> Result<Option<&'a str>, VerifyError> {
    match headers.get(name).map(Vec::as_slice) {
        None | Some([]) => Ok(None),
        Some([only]) => Ok(Some(only.as_str())),
        Some(_) => Err(VerifyError::ServedAssetViolation(format!(
            "{context} sent duplicate '{name}' HTTP headers"
        ))),
    }
}

/// Performs a live JS-Proof audit against `page_url` using an already Sigstore-verified
/// `manifest`: checks HTTP CSP headers, checkout HTML `<script>` tags + SRI, and downloads &
/// hashes every declared manifest artifact from the live origin.
pub fn audit_live_site(
    page_url: &str,
    manifest: &ReleaseManifestV1,
    allow_insecure_http: bool,
    require_immutable_cache: bool,
) -> Result<SiteAuditReport, VerifyError> {
    manifest.validate()?;
    let origin = extract_origin(page_url)?;
    let (page_headers, page_bytes) = fetch_bounded(page_url, allow_insecure_http)?;

    let page_ct = single_header(&page_headers, "content-type", "checkout page")?;
    audit_page_content_type(page_ct)?;

    let csp_values: Vec<&str> = page_headers
        .get("content-security-policy")
        .map(|vals| vals.iter().map(String::as_str).collect())
        .unwrap_or_default();
    audit_csp_headers(&csp_values)?;

    let html = String::from_utf8(page_bytes).map_err(|_| {
        VerifyError::HtmlScriptViolation("checkout HTML response is not valid UTF-8".to_owned())
    })?;
    let scripts_verified = audit_html_scripts(&html, manifest)?;

    for artifact in &manifest.artifacts {
        let asset_url = format!("{origin}{}", artifact.path);
        let (headers, body) = fetch_bounded(&asset_url, allow_insecure_http)?;
        let ct = single_header(&headers, "content-type", &artifact.path)?;
        let cc_joined = headers.get("cache-control").map(|v| v.join(", "));
        verify_served_artifact(
            artifact,
            ct,
            cc_joined.as_deref(),
            &body,
            require_immutable_cache,
        )?;
    }

    Ok(SiteAuditReport {
        page_url: page_url.to_owned(),
        scripts_verified,
        artifacts_verified: manifest.artifacts.len(),
    })
}

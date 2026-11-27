#!/usr/bin/env bash
set -euo pipefail

# Deterministic dual-path (/build-a vs /build-b) WASM builder & manifest generator.
# Fails hard if even 1 bit differs between two independent workspace paths.

SRC_DIR="${SRC_DIR:-/src}"
OUT_DIR="${OUT_DIR:-/out}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
RELEASE_VERSION="${RELEASE_VERSION:-0.1.0}"
GIT_COMMIT="${GIT_COMMIT:-0000000000000000000000000000000000000000}"
BUILDER_IMAGE_DIGEST="${BUILDER_IMAGE_DIGEST:-sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b}"
RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
WASM_BINDGEN_VER="${WASM_BINDGEN_VERSION:-$(wasm-bindgen --version | awk '{print $2}')}"
BINARYEN_VER="${BINARYEN_VERSION:-version_133}"

# Strict input validation (defense-in-depth against path traversal or malformed JSON metadata).
[[ "${SOURCE_DATE_EPOCH}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: SOURCE_DATE_EPOCH must be positive integer" >&2; exit 1; }
[[ "${RELEASE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] || { echo "ERROR: invalid RELEASE_VERSION" >&2; exit 1; }
[[ "${GIT_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || { echo "ERROR: GIT_COMMIT must be 40 lowercase hex chars" >&2; exit 1; }
[[ "${BUILDER_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "ERROR: BUILDER_IMAGE_DIGEST must be sha256:<64-hex>" >&2; exit 1; }
[[ "${RUSTC_VERSION}" =~ ^[0-9A-Za-z._-]+$ ]] || { echo "ERROR: invalid RUSTC_VERSION" >&2; exit 1; }
[[ "${WASM_BINDGEN_VER}" =~ ^[0-9A-Za-z._-]+$ ]] || { echo "ERROR: invalid WASM_BINDGEN_VER" >&2; exit 1; }
[[ "${BINARYEN_VER}" =~ ^[0-9A-Za-z._-]+$ ]] || { echo "ERROR: invalid BINARYEN_VER" >&2; exit 1; }

export SOURCE_DATE_EPOCH
export TZ=UTC
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export CARGO_INCREMENTAL=0

build_in_path() {
  local label="$1"
  local work_root="$2"
  local work_src="${work_root}/src"
  local target_dir="${work_root}/target"
  local home_dir="${work_root}/home"
  local dist_dir="${work_root}/dist"

  rm -rf "${work_root}"
  mkdir -p "${work_src}" "${target_dir}" "${home_dir}" "${dist_dir}"

  # Copy only source files needed for the workspace (never host target/ or .git/).
  cp "${SRC_DIR}/Cargo.toml" "${SRC_DIR}/Cargo.lock" "${SRC_DIR}/rust-toolchain.toml" "${work_src}/"
  cp -R "${SRC_DIR}/crates" "${work_src}/crates"
  if [ -d "${SRC_DIR}/vendor" ]; then
    cp -R "${SRC_DIR}/vendor" "${work_src}/vendor"
  fi
  if [ -d "${SRC_DIR}/.cargo" ]; then
    cp -R "${SRC_DIR}/.cargo" "${work_src}/.cargo"
  fi

  local cargo_home="${CARGO_HOME:-/usr/local/cargo}"
  # Keep target_features intact for wasm-bindgen; wasm-opt strips debug/producers afterwards.
  local rustflags="--remap-path-prefix=${home_dir}=/home --remap-path-prefix=${work_src}=/src --remap-path-prefix=${cargo_home}=/cargo -C debuginfo=0 -C strip=none"

  echo "[${label}] Building sovret-crypto-wasm in ${work_src} ..."
  (
    cd "${work_src}"
    HOME="${home_dir}" \
    CARGO_TARGET_DIR="${target_dir}" \
    RUSTFLAGS="${rustflags}" \
      cargo build --locked --release --target wasm32-unknown-unknown -p sovret-crypto-wasm
  )

  wasm-bindgen \
    --target web \
    --no-typescript \
    --out-dir "${dist_dir}" \
    "${target_dir}/wasm32-unknown-unknown/release/sovret_crypto_wasm.wasm"

  wasm-opt \
    -Oz \
    --strip-debug \
    --strip-producers \
    --enable-bulk-memory \
    --enable-sign-ext \
    --enable-mutable-globals \
    --enable-nontrapping-float-to-int \
    -o "${dist_dir}/sovret_crypto_wasm_bg.wasm.opt" \
    "${dist_dir}/sovret_crypto_wasm_bg.wasm"
  mv "${dist_dir}/sovret_crypto_wasm_bg.wasm.opt" "${dist_dir}/sovret_crypto_wasm_bg.wasm"

  touch -d "@${SOURCE_DATE_EPOCH}" \
    "${dist_dir}/sovret_crypto_wasm.js" \
    "${dist_dir}/sovret_crypto_wasm_bg.wasm"
}

# Build in two deliberately different directory depths & path lengths!
build_in_path "build-a" "/build-a/workspace"
build_in_path "build-b" "/build-b/alt-repro-path-check/workspace"

echo "=== Dual-Path Determinism Gate (/build-a vs /build-b) ==="
for fname in sovret_crypto_wasm.js sovret_crypto_wasm_bg.wasm; do
  hash_a="$(sha256sum "/build-a/workspace/dist/${fname}" | awk '{print $1}')"
  hash_b="$(sha256sum "/build-b/alt-repro-path-check/workspace/dist/${fname}" | awk '{print $1}')"
  echo "  ${fname}:"
  echo "    build-a: ${hash_a}"
  echo "    build-b: ${hash_b}"
  if [ "${hash_a}" != "${hash_b}" ]; then
    echo "FATAL: NON-DETERMINISTIC BUILD DETECTED for ${fname}!" >&2
    exit 1
  fi
done

mkdir -p "${OUT_DIR}"
cp "/build-a/workspace/dist/sovret_crypto_wasm.js" "${OUT_DIR}/sovret_crypto_wasm.js"
cp "/build-a/workspace/dist/sovret_crypto_wasm_bg.wasm" "${OUT_DIR}/sovret_crypto_wasm_bg.wasm"
touch -d "@${SOURCE_DATE_EPOCH}" "${OUT_DIR}/sovret_crypto_wasm.js" "${OUT_DIR}/sovret_crypto_wasm_bg.wasm"

js_size="$(stat -c%s "${OUT_DIR}/sovret_crypto_wasm.js")"
js_sha256="$(sha256sum "${OUT_DIR}/sovret_crypto_wasm.js" | awk '{print $1}')"
js_sri="sha384-$(openssl dgst -sha384 -binary "${OUT_DIR}/sovret_crypto_wasm.js" | openssl base64 -A)"

wasm_size="$(stat -c%s "${OUT_DIR}/sovret_crypto_wasm_bg.wasm")"
wasm_sha256="$(sha256sum "${OUT_DIR}/sovret_crypto_wasm_bg.wasm" | awk '{print $1}')"
wasm_sri="sha384-$(openssl dgst -sha384 -binary "${OUT_DIR}/sovret_crypto_wasm_bg.wasm" | openssl base64 -A)"

# Emit canonical sorted release-manifest.json matching `sovret-verify::ReleaseManifestV1`.
cat > "${OUT_DIR}/release-manifest.json" <<EOF
{
  "schema_version": 1,
  "release_version": "${RELEASE_VERSION}",
  "git_commit": "${GIT_COMMIT}",
  "source_date_epoch": ${SOURCE_DATE_EPOCH},
  "builder_image_digest": "${BUILDER_IMAGE_DIGEST}",
  "toolchain": {
    "rustc": "${RUSTC_VERSION}",
    "wasm_bindgen_cli": "${WASM_BINDGEN_VER}",
    "binaryen": "${BINARYEN_VER}"
  },
  "artifacts": [
    {
      "path": "/assets/v${RELEASE_VERSION}/sovret_crypto_wasm.js",
      "media_type": "text/javascript",
      "size_bytes": ${js_size},
      "sha256": "${js_sha256}",
      "sri_sha384": "${js_sri}"
    },
    {
      "path": "/assets/v${RELEASE_VERSION}/sovret_crypto_wasm_bg.wasm",
      "media_type": "application/wasm",
      "size_bytes": ${wasm_size},
      "sha256": "${wasm_sha256}",
      "sri_sha384": "${wasm_sri}"
    }
  ]
}
EOF
touch -d "@${SOURCE_DATE_EPOCH}" "${OUT_DIR}/release-manifest.json"

if command -v brotli >/dev/null 2>&1; then
  js_br="$(brotli -q 11 -c "${OUT_DIR}/sovret_crypto_wasm.js" | wc -c)"
  wasm_br="$(brotli -q 11 -c "${OUT_DIR}/sovret_crypto_wasm_bg.wasm" | wc -c)"
  echo "=== Deterministic Output Sizes ==="
  echo "  sovret_crypto_wasm.js:      ${js_size} B raw / ${js_br} B brotli-11"
  echo "  sovret_crypto_wasm_bg.wasm: ${wasm_size} B raw / ${wasm_br} B brotli-11"
fi

echo "PASS: dual-path deterministic WASM build verified and release-manifest.json emitted."

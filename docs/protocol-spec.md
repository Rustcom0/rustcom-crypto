# Sovret Deep-Dive Spec: `sovret-crypto` v1 Wire Protocol & Verification

Date: 2026-11-23
Companion to: `docs/02-architecture/master-plan.md` (`sovret-backend`)
Crate / Repo: `sovret/sovret-crypto` (Public, AGPL-3.0, `#![forbid(unsafe_code)]`, `no_std` + `wasm32-unknown-unknown` + native Rust, `zeroize` on all secret types, `subtle` constant-time comparisons, heap-`Box`ed ML-KEM matrices for WASM stack safety).

---

## 1. Canonical Binary Envelope (`RCENC` v1)

Fixed big-endian binary framing eliminates JSON canonicalization bugs across native Rust and browser WASM.

```text
+-------------------------------------------------------------------+
| HEADER (10 bytes fixed)                                           |
|   magic           [5B] : "RCENC" (0x52 0x43 0x45 0x4E 0x43)       |
|   format_version  [1B] : 0x01                                     |
|   cipher_suite    [1B] : 0x01 = X-Wing(ML-KEM-768+X25519)         |
|                                 + XChaCha20-Poly1305              |
|   envelope_kind   [1B] : 0x01 = OrderFulfillment                  |
|                          0x02 = OrderAccounting (6-10yr VAT)      |
|                          0x03 = PortalMessage                     |
|                          0x04 = PrivateProduct                    |
|                          0x05 = StaffKeyWrap                      |
|                          0x06 = RecoveryBackup                    |
|   flags           [1B] : bit0=compressed(zstd), bit1=rcstr_header |
|                          (internal only; rejected by standalone     |
|                           rcenc::decrypt), bits2..7=0               |
|   recipient_count [1B] : 1..=8 (unique (type,key_id,key_version))   |
+-------------------------------------------------------------------+
| RECIPIENT SLOTS (repeated recipient_count times)                  |
|   recipient_type  [1B] : 0x01 = XWingOrgKey                       |
|                          0x02 = XWingCustomerVault (Strict dual)  |
|                          0x03 = XWingStaffKey                     |
|                          0x04 = XWingVipGroup                     |
|                          0x05 = Argon2idPassword (Private Prod)   |
|                          0x06 = RecoveryBip39                     |
|   key_id         [16B] : UUID or BLAKE3(pub_key)[0..16]           |
|   key_version     [4B] : u32 BE (>= 1; 0 rejected)                |
|   kem_data_len    [2B] : u16 BE (1120 for X-Wing; 44 for Argon2;  |
|                                   0 for RecoveryBip39)              |
|   kem_data        [NB] : X-Wing ciphertext OR (salt[32]+params)   |
|   wrap_nonce     [24B] : CSPRNG XChaCha20 nonce                   |
|   wrapped_dek    [48B] : AEAD(wrap_key, wrap_nonce, DEK[32],      |
|                               slot_aad) -> 32B CT + 16B tag       |
+-------------------------------------------------------------------+
| PAYLOAD BLOCK                                                     |
|   payload_nonce  [24B] : CSPRNG XChaCha20 nonce                   |
|   ciphertext_len  [4B] : u32 BE                                   |
|   ciphertext      [MB] : AEAD(DEK[32], payload_nonce, plaintext,  |
|                               canonical_aad) -> CT + 16B tag      |
+-------------------------------------------------------------------+
```

### Key Derivation & Canonical AAD
- `wrap_key = HKDF-SHA256(ikm = shared_secret_32B, salt = key_id || key_version, info = "sovret-v1-dek-wrap")`
- `slot_aad = header[0..10] || recipient_type || key_id || key_version`
- `canonical_aad` (recomputed independently on encrypt & decrypt; never trusted from wire):
  ```text
  "sovret-v1-aad"
  || envelope_kind [1B]
  || tenant_id     [16B UUID]
  || resource_id   [16B UUID: order_id / product_id / msg_id]
  || privacy_tier  [1B: 1=Legacy, 2=Enhanced, 3=Strict]
  || schema_ver    [2B u16 BE]
  || BLAKE3(raw_header_and_all_recipient_slots) [32B]
  ```
- Binding `BLAKE3(header + all recipient slots)` into `canonical_aad` defeats recipient-slot stripping, cipher-suite downgrade, and cross-tenant/cross-order ciphertext replay.

---

## 2. Chunked Streaming E2EE for Large Private Files (`RCSTR` v1)

- Header (`26B` fixed prefix + embedded self-delimiting `RCENC` v1 envelope):
  - Fixed prefix (`26B`): `"RCSTR"` (`5B`) + `version=0x01` (`1B`) + `chunk_size` (`4B u32 BE`, default `65536`, valid range `4096..=4194304`) + `file_nonce_prefix` (`16B` CSPRNG).
  - Embedded `RCENC` v1 payload (`58B`, `flags = 0x02` `rcstr_header` domain-separated from standalone `RCENC`, ciphertext length strictly `74B` verified before decapsulation): `FileDEK[32B] || rcstr_fixed_header[26B]`. On decrypt, the authenticated 26-byte copy is verified in constant time (`subtle::ConstantTimeEq`) against the wire prefix so `magic`, `version`, `chunk_size`, and `file_nonce_prefix` are fully authenticated before any chunk is decrypted.
- Per chunk `i = 0, 1, ...` (`i < 2^56`; non-final chunks MUST be exactly `chunk_size` plaintext bytes; final chunk `0..=chunk_size` bytes, including a single 0-byte final chunk for empty files):
  - Nonce (`24B`): `file_nonce_prefix[16B] || chunk_index[7B BE] || is_final_flag[1B: 0x00 | 0x01]`.
  - Chunk AAD (`57B`): `"sovret-v1-stream" || tenant_id[16B] || file_id[16B] || chunk_index[8B BE] || is_final_flag[1B]`.
- Constant ~128 KB RAM for multi-GB uploads/downloads in WASM; authenticates chunk order and prevents silent truncation, extension, or header malleation.

---

## 3. Staff Auth (`OPAQUE`), Multi-Staff Org Grants, SKL & Recovery

- **Staff Auth:** `opaque-ke` (`Ristretto255` + `Argon2id`) -- server stores ONLY OPAQUE registration record.
- **Personal Vault KEK:** Separate `key_salt[32B]` -> `Argon2id(password, key_salt, m=65536 KiB, t=3, p=1)` unwraps `Staff_XWing_SK` + `Staff_Ed25519_SK`.
- **Admin-Signed Staff Org Key Grants (`StaffGrantV1`, `158 B` wire) & Org Key Wrapping:**
  ```text
  grant_msg [114B] = "sovret-v1-staff-grant"[21B]
                     || tenant_id[16B] || vault_role[1B: 1=OrgMaster,2=Fulfillment,3=Accounting]
                     || store_key_ver[4B BE, >=1] || target_staff_id[16B]
                     || BLAKE3(target_staff_xwing_pk)[32B]
                     || issued_at_unix[8B BE, >0] || grantor_staff_id[16B]
  grant_sig [64B]  = Ed25519_Sign(grantor_ed25519_sk, grant_msg)  (verified with verify_strict)
  wire      [158B] = version=0x01[1B] || tenant_id[16B] || vault_role[1B] || store_key_ver[4B]
                     || target_staff_id[16B] || target_staff_xwing_pk_hash[32B]
                     || issued_at_unix[8B] || grantor_staff_id[16B] || grant_sig[64B]
  ```
  - **Staff Key Wrap (`RCSKW` v1):** Single-recipient `RCENC(kind=0x05, schema_ver=1, flags=0x00, resource_id=target_staff_id)` to `XWingStaffKey` wrapping `75 B`: `"RCSKW"[5B] || 0x01[1B] || tenant_id[16B] || vault_role[1B] || store_key_ver[4B BE] || target_staff_id[16B] || org_xwing_seed[32B]`. Unwrap MUST verify `StaffGrantV1` first and confirm the unwrapped key matches the store's SKL-anchored `expected_org_pk` in constant time.
  - **Historical Rotation Archive (`RCARC` v1):** Revocation deletes target wrapped rows + rotates to `v(N+1)` and archives `v(N)` inside single-recipient `RCENC(kind=0x05, schema_ver=2, flags=0x00, resource_id=new_org_pk.key_id())` to `XWingOrgKey` wrapping `63 B`: `"RCARC"[5B] || 0x01[1B] || tenant_id[16B] || vault_role[1B] || archived_key_ver[4B BE] || new_key_ver[4B BE] || archived_org_xwing_seed[32B]` (with `1 <= archived_key_ver < new_key_ver` and distinct keys enforced on both wrap and unwrap, preserving 6-10 yr VAT retention).
- **Append-Only Signed Key List (`/.well-known/sovret-skl.json`, `SklEntryV1`):**
  ```text
  canonical_body [1337B] = "sovret-v1-skl-entry"[19B] || ver=0x01[1B] || tenant_id[16B]
                           || seq[8B BE] || vault_role[1B] || key_version[4B BE, monotonic per role]
                           || xwing_pk[1216B, distinct across chain] || identity_ed25519_pk[32B]
                           || issued_at_unix[8B BE, non-decreasing] || prev_entry_hash[32B]
  signature      [64B]   = Ed25519_Sign(identity_ed25519_sk, canonical_body)
  rotate_msg     [116B]  = "sovret-v1-skl-rotate"[20B] || BLAKE3(canonical_body)[32B]
                           || prev_identity_ed25519_pk[32B] || new_identity_ed25519_pk[32B]
  canonical_wire         = canonical_body[1337B] || signature[64B] || has_cross_sig[1B: 0|1]
                           || (rotation_cross_signature[64B] if has_cross_sig == 1)
  prev_entry_hash [32B]  = [0; 32] at genesis (seq=0), else BLAKE3(canonical_wire(entry[n-1]))
  ```
  Identity rotations MUST include a strict cross-signature from `prev_identity_ed25519_pk` and MUST NOT resurrect any previously retired `identity_ed25519_pk`; non-rotation entries MUST omit cross-signatures. Verifiers enforce contiguous `seq`, gap-free monotonic `key_version` per role, distinct `xwing_pk` across all entries (blocking role collision & key resurrection), optional pinned `SklCheckpoint` anti-rollback checks, and bounded length (`<= 4,096` entries).
- **Recovery Kit (BIP-39 24-Word + `RCREC` v1) & `GF(256)` Shamir (`RCSHR` v1):**
  - 256-bit `RecoveryMasterSecret` encodes/decodes as a standard 24-word BIP-39 English phrase (official wordlist `SHA-256 = 2f5eed53...dbda`, constant-time lookup, 8-bit `SHA-256` checksum) and derives `RecoveryKEK = HKDF-SHA256(secret, salt=tenant_id, info="sovret-v1-recovery-kek")`.
  - **Recovery Backup (`RCREC` v1):** Single-recipient `RCENC(kind=0x06, schema_ver=1, flags=0x00, resource_id=tenant_id)` to `RecoveryBip39` (`kem_data = empty`) wrapping `"RCREC"[5B] || 0x01[1B] || tenant_id[16B] || recovery_ver[4B BE] || store_identity_ed25519_seed[32B] || key_count[1B: 1..=3] || (vault_role[1B] || key_version[4B BE] || org_xwing_seed[32B]) * key_count` (unique `vault_role`s and distinct `org_xwing_seed`s).
  - **Shamir Split (`RCSHR` v1, `105 B`):** Enhanced+ optional M-of-N (`2 <= M <= N <= 64`) over `GF(2^8)` (`x^8 + x^4 + x^3 + x + 1`, constant-time table-free arithmetic & Fermat `a^254` inversion). Wire frame: `"RCSHR"[5B] || 0x01[1B] || tenant_id[16B] || split_id[16B, non-zero] || threshold[1B] || total_shares[1B] || share_index[1B: 1..=N] || share_value[32B] || commitment_sha256[32B]`, where `commitment_sha256 = SHA-256("sovret-v1-shamir-share-commit" || tenant_id || split_id || threshold || total_shares || share_index || share_value)`. Commitments provide share **integrity** (corruption detection and binding to stored/out-of-band commitments via `verify_commitment`), NOT cryptographic share authenticity against malicious share holders (not Feldman/Pedersen VSS). Combining `> M` shares verifies polynomial consistency across every extra share in constant time; downstream `RCREC` AEAD rejects wrong reconstructed secrets.

---

## 4. Mullvad / IVPN-Style 128-Bit Strict Account ID

- **Entropy & Format:** 16 CSPRNG bytes (`128 bits`) encoded big-endian as `26` Crockford Base32 chars (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, top 2 pad bits of symbol 0 strictly `00` so symbol 0 is in `0..=7`; decoders MUST reject non-zero pad bits to enforce bijective canonicality) + **2-char checksum** (`10 bits` = top 10 bits of `BLAKE3_derive_key("sovret-v1-account-id-chk", raw_16B)[0..2]`, split as high 5 bits `sym[26]` || low 5 bits `sym[27]`). Displayed as 28 chars (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, 34 chars with hyphens). Client strips ASCII whitespace/`-`, case-insensitively normalizes `i/l->1`, `o->0`, rejects `u`/`U`, and compares checksums in constant time (`subtle::ConstantTimeEq`).
- **3 Domain-Separated Client Keys (WASM Only):**
  1. `auth_lookup_id = HKDF-SHA256(raw_16B, salt=tenant_id, info="sovret-v1-strict-lookup")[0..16]` -> server indexes `BLAKE3_keyed(kms_pepper, tenant_id || auth_lookup_id)`.
  2. `auth_secret = HKDF-SHA256(raw_16B, salt=tenant_id, info="sovret-v1-strict-auth")[0..32]` -> OPAQUE client password.
  3. `customer_vault_seed = HKDF-SHA256(raw_16B, salt=tenant_id, info="sovret-v1-strict-vault")[0..32]` -> derives buyer `X-Wing` (`HKDF-SHA256(vault_seed, salt=tenant_id, info="sovret-v1-strict-vault-xwing")[0..32]`) + `Ed25519` (`HKDF-SHA256(vault_seed, salt=tenant_id, info="sovret-v1-strict-vault-ed25519")[0..32]`) keypairs strictly inside browser.

---

## 5. Private Products, Logged-In E2EE Blog/News, E2EE Digital Downloads & Platform Review Tokens

- **Private Products (`RCENC(kind=0x04)`):** Random `ProductDEK` encrypts metadata into `RCENC(kind=0x04)` (with `schema_version != 0x8001` reserved for VIP key wrapping; merchants include `XWingOrgKey` alongside buyer access slots).
  - **Password Mode (`recipient_type=0x05`, `key_id=product_id`, `password_version >= 1`):** Wraps `ProductDEK` under `Argon2id(v0x13, password, product_salt[32B], m=65536 KiB, t=3, p=1)`. Slot `kem_data` (`44B`) encodes `salt[32B] || m_cost_kib[4B BE] || t_cost[4B BE] || p_cost[4B BE]`. Protocol bounds enforce `m: 19456..=131072 KiB`, `t: 2..=8`, `p: 1..=4`, non-zero salt, password `1..=1024 B`; single-threaded browser WASM (`sovret-crypto-wasm`) enforces the tighter `Argon2idBudget::WASM_CLIENT` ceiling (`m <= 65536 KiB`, `t <= 4`, `p <= 2`, `m * t <= 262144 KiB-iters`) before executing Argon2id to prevent browser tab OOM/CPU DoS.
  - **VIP Group Mode (`recipient_type=0x04`, `key_id=vip_group_id`, `key_version >= 1`):** Each VIP group holds a versioned `X-Wing` keypair (`32B` seed). Group secret seeds are distributed either:
    1. **Per-Member / Vault Wrap (`RCVIP` v1):** `RCENC(kind=0x04, schema_ver=0x8001, resource_id=vip_group_id)` encrypting the `74B` payload `"RCVIP" || 0x01 || tenant_id[16B] || vip_group_id[16B] || group_key_version[4B BE] || vip_group_seed[32B]` to `XWingCustomerVault` / `XWingOrgKey` recipients.
    2. **URL Hash Fragment (`#k=<52-char Base64URL-unpadded>`):** Constant-time unpadded Base64URL encoding of `39B` (0 pad bits): `version=0x01[1B] || key_version[4B BE] || vip_group_seed[32B] || BLAKE3_derive_key("sovret-v1-vip-fragment-chk", prefix_37B)[0..2]`. Never transmitted to servers (RFC 3986); parsers reject duplicate `k=` parameters.
- **Private Storefront Blog / News Posts (`logged_in_e2ee` | `vip_group_e2ee` | `password_e2ee` -- `ADR-026`):**
  - Merchant browser (`admin-crypto-bridge`) encrypts `{ title, excerpt, body_markdown, cover_media_ref, inline_media_refs }` using `RCENC(kind=0x04, resource_id=post_id)` (with `schema_ver = 2` domain-separated from `RCVIP`'s `0x8001`) to `XWingOrgKey` + the store's **Account Reader `XWingVipGroup`** (or a specific `vip_group_id` / `Argon2idPassword`). Inline & cover images use client-side WebP resize + `RCSTR` v1 (`client_encrypted = true`).
  - Both `Strict` Mullvad ID accounts and `Legacy`/`Enhanced` logged-in customer accounts register a client-derived `CustomerVault` X-Wing public key (`customers.customer_vault_xwing_pk`). Merchant Vault wraps the Account Reader `VipGroupSeed` (`RCVIP` v1) to each eligible account's `XWingCustomerVault` (`0x02`) so only authenticated account holders can unwrap and render the post locally inside `sovret-crypto-wasm`.
- **E2EE Digital Downloads & `.txt` License Key Pools (Staff-Approved; Forced in `Strict` -- `ADR-026`):**
  - **`.txt` License Key Pools (`digital_license_pools`):** When importing a `.txt` license key file in E2EE mode (mandatory in `Strict`), Dioxus Admin (`admin-crypto-bridge`) parses each line client-side, computes a tenant-keyed BLAKE3 commitment (`key_commitment_blake3`) to block duplicate issuance without leaking plaintext keys, and encrypts the pool blob in `RCENC` (`XWingOrgKey` only -- server holds zero decryption keys).
  - **Staff Approval & Buyer Key Sealing:** Because the server cannot unwrap `StoreOrgPK`-encrypted `.txt` pools or `RCSTR` `FileDEK`s, order fulfillment enters `flow.wait_approval` (`awaiting_staff_approval`). Store staff unlock Vault in Admin, decrypt the pool / `FileDEK` client-side, allocate the unused key(s) (or re-wrap `FileDEK` / buyer-scoped `RCSTR` header), and encrypt the deliverable payload in `RCENC` (`resource_id = entitlement_id`) dual-wrapped to `XWingOrgKey` + buyer's `XWingCustomerVault` (or checkout-generated ephemeral `#k=` order vault key).
  - **Buyer Local Decryption (`sovret-crypto-wasm`):** Buyer opens their Encrypted Order Portal (after EU/UK withdrawal waiver enforcement), decrypts the allocated license key `.txt` / `FileDEK` locally, and streams/decrypts any `RCSTR` v1 file download in ~128 KB RAM. Plaintext downloads and unencrypted `.txt` pools are hard-blocked when `privacy_tier = Strict`.
- **Platform Review Receipt Token (Zero-PII Verified Purchase, Even in Strict Tier):**
  ```text
  token_id = BLAKE3_keyed(PlatformReviewSecret, tenant_id || order_id || product_id)[0..16]
  payload  = "sovret-v1-review-token" || token_id[16B] || tenant_id[16B]
             || product_id[16B] || is_private[1B] || issued_at[8B] || expires_at[8B]
  sig      = Ed25519_Sign(PlatformReviewAuthority_SK, payload)
  ```
  Redeemed once at `/api/v1/platform/reviews` into platform-owned `platform_reviews` (RLS grants tenant `SELECT` + `merchant_reply` INSERT only -- **store owners cannot edit or delete reviews**; reviews & aggregate scores are platform Ed25519-signed/hash-chained).

---

## 6. Deterministic WASM Build & Rekor v2 JS-Proof (`/.well-known/sovret-manifest.json`)

- **Digest-Pinned Builder (`builder/Dockerfile.wasm` + `scripts/build-wasm-deterministic.sh`):**
  - Non-root (`USER builder`) image pinned by exact SHA-256 digest (`rust:1.97.1-slim-bookworm@sha256:39f68a3e...46f1b`), pinned `rust-toolchain.toml` (`1.97.1`), `Cargo.lock` (`--locked`), SHA-256-verified `wasm-bindgen-cli` (`0.2.130`), and SHA-256-verified `binaryen` (`version_133`, `wasm-opt -Oz --strip-debug --strip-producers --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int`).
  - `RUSTFLAGS="--remap-path-prefix=$HOME=/home --remap-path-prefix=$WORK=/src --remap-path-prefix=$CARGO_HOME=/cargo -C debuginfo=0 -C strip=none"` (keeping `target_features` intact for `wasm-bindgen`, with `wasm-opt` stripping debug and producer custom sections afterwards), fixed `SOURCE_DATE_EPOCH`, `TZ=UTC`, `LC_ALL=C.UTF-8`, `CARGO_INCREMENTAL=0`.
- **Dual-Path Determinism Gate:** Compiles `sovret-crypto-wasm` twice in independent directory depths (`/build-a/workspace/src` vs `/build-b/alt-repro-path-check/workspace/src`) with `--network=none` over `vendor/` crates in CI, asserts identical `sha256sum` on both `sovret_crypto_wasm.js` and `sovret_crypto_wasm_bg.wasm`, and emits canonical `release-manifest.json` (`schema_version = 1`, `release_version`, 40-char `git_commit`, `source_date_epoch`, `builder_image_digest`, `toolchain`, sorted immutable `/assets/vX.Y.Z/*` artifacts with exact `size_bytes`, `sha256`, and `sri_sha384`).
- **Sigstore Cosign v3 OIDC -> Rekor v2 + RFC 3161 TSA Attestation:** Signed via `cosign sign-blob --yes --new-bundle-format --use-signing-config --bundle release-manifest.sigstore.json release-manifest.json`, logged to Rekor v2 (`log2025-1.rekor.sigstore.dev`, `PKIX_ED25519` C2SP signed-note checkpoint + `hashedRekordV002` + RFC 6962 Merkle inclusion proof) and timestamped by Sigstore's RFC 3161 TSA (`timestamp.sigstore.dev`).
- **`sovret-verify` CLI (`crates/sovret-verify`, Dec 31 MVP) + Browser Extension (Phase 2):** Pure-Rust `#![forbid(unsafe_code)]` verifier embedding the official Sigstore Public Good `trusted_root.json` (overriding requires `--trust-root <PATH> --unsafe-custom-trust-root` and prints the custom root SHA-256 fingerprint warning to stderr; all manifest, SKL, checkpoint, and Sigstore JSON parsers reject duplicate object keys including Unicode-escaped duplicates):
  1. `manifest`: verifies Sigstore bundle (`v0.3`/`v0.2`/`v0.1`) against RFC 5280 Fulcio CA chain (P-384/P-256/Ed25519, `KeyUsage`, `pathLenConstraint`, critical-extension enforcement, `id-kp-codeSigning` EKU, non-CA leaf, OIDC Issuer + exact tag SAN `@refs/tags/v<release_version>` + Fulcio Source Repository Digest OID `1.3.6.1.4.1.57264.1.13 == git_commit`), **authenticated signing time** (RFC 3161 TSA `TSTInfo` `genTime` over artifact signature for Rekor v2, OR verified Rekor v1 `inclusionPromise.signedEntryTimestamp` SET -- never trusting unsigned `integratedTime`), AND Rekor v2 (`PKIX_ED25519` C2SP key hash `SHA-256(origin || "\n" || 0x01 || raw32)` + `hashedRekordV002`) / Rekor v1 (`PKIX_ECDSA_P256_SHA_256` + `hashedrekord v0.0.1`) RFC 6962 Merkle inclusion proof + C2SP checkpoint (`origin` + 4-byte `key_hint` verified).
  2. `site`: verifies live served HTTP `Content-Type: text/html; charset=utf-8` (explicit UTF-8 required), HTTP CSP headers (comma-split multi-policy, strict allowlist on `script-src`/`script-src-elem`/`script-src-attr`/`object-src`/`base-uri`/`worker-src` + `child-src` fallback), WHATWG HTML5 tokenized `<script>` tags (`html5gum` with RCDATA/RAWTEXT/ScriptData state switching, entity decoding, forbidden active elements `<iframe>`/`<object>`/`<embed>`/`<svg>`/`<math>`, zero inline executable scripts, `serde_json`-validated JSON-LD blocks, zero `on*=`/`srcdoc`/`javascript:` URIs, zero unlisted scripts, constant-time SRI match), and no-redirect (`max_redirects=0`, 30s timeout) served JS/WASM bytes + `Content-Type` + `immutable` `Cache-Control`.
  3. `skl`: verifies `/.well-known/sovret-skl.json` chain + optional `--pinned-checkpoint`.
  4. `rebuild`: exports a clean `git archive` of `git_commit`, enforces digest-pinned `<image>@sha256:... == manifest.builder_image_digest`, runs fixed-argv `--network=none` read-only Docker rebuild (requiring `vendor/` for offline mode or explicit `--allow-network`), reads rebuilt artifacts bounded after `symlink_metadata` length verification, and recursively verifies nested artifact paths with zero unexpected extra files, subdirectories, or symlinks.
- **Minimal Public Verifiable Surface & Trust Boundary (`ADR-032`):**
  - **Single-Commit Storefront JS + WASM Manifest:** All executable client scripts loaded on storefront checkout, private unlock, E2EE blog/download, and Strict portal pages (`sovret-crypto-wasm` plus minimal `storefront-js/`: `checkout.js`, `portal.js`, vendored Datastar, and `storefront-live.js` -- kept off checkout/portal where unneeded) live in public `sovret-crypto` and are packaged under the exact same `git_commit` and Rekor v2 `release-manifest.json`. Server-side SSR templates (`MiniJinja`), declarative `themes/`, `platform-site/`, and Dioxus `admin/` stay in private `sovret-web` (`sovret-verify site` audits rendered HTML/CSP directly).
  - **GitHub Actions Hosted Live-Store Checker (`verify-live-store.yml`, Sprint 5):** Public `workflow_dispatch` (accepting any live store URL) + scheduled reference-store checks running `sovret-verify manifest`/`site`/`skl` against Rekor v2 and this repo's release tags. Provides zero-install public transparency and global tampering detection; explicitly documented as complementary to local `sovret-verify` / Phase 2 browser extension (since a remote runner from GitHub/Azure IPs cannot by itself rule out IP-targeted split-view responses).
  - **Merchant Admin Transparency & Offline CLI Escape Hatch:** Because `sovret-web/admin` (Web WASM, Desktop, Mobile) is closed-source, Sovret does not claim public Rekor source-reproducibility for Admin clients. Instead, Admin enforces strict CSP, zero third-party JS, and network-auditable ciphertext-only API calls; merchants who prefer not to install native apps can use the browser (`admin-web`, with optional manually-enabled Web Auto-Accept in Settings); and `sovret-verify` will provide an open-source offline `decrypt` CLI subcommand so zero-trust `Strict` merchants can decrypt orders/backups offline without trusting any GUI binary.

# Rustcom-Desk Deep-Dive Spec: `rustcom-crypto` v1 Wire Protocol & Verification

Date: 2026-11-23
Companion to: `C:\Users\admin\.opencode\plan\rustcom-master-plan.md`
Crate / Repo: `<org>/rustcom-crypto` (Public, AGPL-3.0, `#![forbid(unsafe_code)]`, `no_std` + `wasm32-unknown-unknown` + native Rust, `zeroize` on all secret types, `subtle` constant-time comparisons, heap-`Box`ed ML-KEM matrices for WASM stack safety).

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
|   flags           [1B] : bit0=compressed(zstd), bits1..7=0        |
|   recipient_count [1B] : 1..=8                                    |
+-------------------------------------------------------------------+
| RECIPIENT SLOTS (repeated recipient_count times)                  |
|   recipient_type  [1B] : 0x01 = XWingOrgKey                       |
|                          0x02 = XWingCustomerVault (Strict dual)  |
|                          0x03 = XWingStaffKey                     |
|                          0x04 = XWingVipGroup                     |
|                          0x05 = Argon2idPassword (Private Prod)   |
|                          0x06 = RecoveryBip39                     |
|   key_id         [16B] : UUID or BLAKE3(pub_key)[0..16]           |
|   key_version     [4B] : u32 BE                                   |
|   kem_data_len    [2B] : u16 BE (1120 for X-Wing; 44 for Argon2)  |
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
- `wrap_key = HKDF-SHA256(ikm = shared_secret_32B, salt = key_id || key_version, info = "rustcom-v1-dek-wrap")`
- `slot_aad = header[0..10] || recipient_type || key_id || key_version`
- `canonical_aad` (recomputed independently on encrypt & decrypt; never trusted from wire):
  ```text
  "rustcom-v1-aad"
  || envelope_kind [1B]
  || tenant_id     [16B UUID]
  || resource_id   [16B UUID: order_id / product_id / msg_id]
  || privacy_tier  [1B: 1=Standard, 2=Flexible, 3=Strict]
  || schema_ver    [2B u16 BE]
  || BLAKE3(raw_header_and_all_recipient_slots) [32B]
  ```
- Binding `BLAKE3(header + all recipient slots)` into `canonical_aad` defeats recipient-slot stripping, cipher-suite downgrade, and cross-tenant/cross-order ciphertext replay.

---

## 2. Chunked Streaming E2EE for Large Private Files (`RCSTR` v1)

- Header: `"RCSTR"` (`5B`) + `version=0x01` (`1B`) + `chunk_size=65536` (`4B u32 BE`) + `file_nonce_prefix` (`16B` CSPRNG) + `RCENC` wrapped 32-byte `FileDEK`.
- Per chunk `i = 0, 1, ...`:
  - Nonce (`24B`): `file_nonce_prefix[16B] || chunk_index[7B BE] || is_final_flag[1B: 0x00 | 0x01]`.
  - Chunk AAD: `"rustcom-v1-stream" || tenant_id[16B] || file_id[16B] || chunk_index[8B BE] || is_final_flag[1B]`.
- Constant ~128 KB RAM for multi-GB uploads/downloads in WASM; authenticates chunk order and prevents silent truncation.

---

## 3. Staff Auth (`OPAQUE`), Multi-Staff Org Grants, SKL & Recovery

- **Staff Auth:** `opaque-ke` (`Ristretto255` + `Argon2id`) -- server stores ONLY OPAQUE registration record.
- **Personal Vault KEK:** Separate `key_salt[32B]` -> `Argon2id(password, key_salt, m=65536 KiB, t=3, p=1)` unwraps `Staff_XWing_SK` + `Staff_Ed25519_SK`.
- **Admin-Signed Staff Org Key Grants (`StaffGrantV1`):**
  ```text
  grant_msg = "rustcom-v1-staff-grant"
              || tenant_id[16B] || vault_role[1B: 1=OrgMaster,2=Fulfillment,3=Accounting]
              || store_key_ver[4B] || target_staff_id[16B]
              || BLAKE3(target_staff_xwing_pk)[32B]
              || issued_at_unix[8B] || grantor_staff_id[16B]
  grant_sig = Ed25519_Sign(grantor_ed25519_sk, grant_msg)
  ```
  Revocation deletes target wrapped row + rotates to `store_key_ver + 1` (archiving `v(N)` wrapped under `v(N+1)` for 6-10 yr VAT retention).
- **Append-Only Signed Key List (`/.well-known/rustcom-skl.json`):** Hash-chained `prev_entry_hash = BLAKE3(canonical(entry[n-1]))`, signed by `StoreIdentity_Ed25519_SK` (cross-signed on rotation). Verified by checkout WASM before encrypting PII.
- **Recovery Kit & Shamir:** 256-bit `RecoveryMasterSecret` -> 24-word BIP-39 phrase + printable Recovery Kit PDF/QR (`RecoveryKEK = HKDF-SHA256(secret, salt=tenant_id, info="rustcom-v1-recovery-kek")`). Enhanced+ supports optional M-of-N Shamir split over `GF(256)` with per-share SHA-256 commitments.

---

## 4. Mullvad / IVPN-Style 128-Bit Strict Account ID

- **Entropy & Format:** 16 CSPRNG bytes (`128 bits`) -> `26` Crockford Base32 chars (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, top 2 pad bits `00`) + **2-char checksum** (top 10 bits of `BLAKE3_derive_key("rustcom-v1-account-id-chk", raw_16B)[0..2]`). Displayed as 28 chars (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`). Client normalizes `i/l->1`, `o->0`.
- **3 Domain-Separated Client Keys (WASM Only):**
  1. `auth_lookup_id = HKDF-SHA256(raw_16B, salt=tenant_id, info="rustcom-v1-strict-lookup")[0..16]` -> server indexes `BLAKE3_keyed(kms_pepper, tenant_id || auth_lookup_id)`.
  2. `auth_secret = HKDF-SHA256(raw_16B, salt=tenant_id, info="rustcom-v1-strict-auth")[0..32]` -> OPAQUE client password.
  3. `customer_vault_seed = HKDF-SHA256(raw_16B, salt=tenant_id, info="rustcom-v1-strict-vault")[0..32]` -> derives buyer `X-Wing` + `Ed25519` keypair strictly inside browser.

---

## 5. Private Products & Platform-Owned Verified-Purchase Review Tokens

- **Private Products:** Random `ProductDEK` encrypts metadata into `RCENC(kind=0x04)`. Password mode wraps `ProductDEK` under `Argon2id(password, product_salt[32B], m=65536 KiB, t=3, p=1)`. VIP mode wraps `VipGroupKey` per member or delivers via URL hash fragment `#k=...`.
- **Platform Review Receipt Token (Zero-PII Verified Purchase, Even in Strict Tier):**
  ```text
  token_id = BLAKE3_keyed(PlatformReviewSecret, tenant_id || order_id || product_id)[0..16]
  payload  = "rustcom-v1-review-token" || token_id[16B] || tenant_id[16B]
             || product_id[16B] || is_private[1B] || issued_at[8B] || expires_at[8B]
  sig      = Ed25519_Sign(PlatformReviewAuthority_SK, payload)
  ```
  Redeemed once at `/api/v1/platform/reviews` into platform-owned `platform_reviews` (RLS grants tenant `SELECT` + `merchant_reply` INSERT only -- **store owners cannot edit or delete reviews**; reviews & aggregate scores are platform Ed25519-signed/hash-chained).

---

## 6. Deterministic WASM Build & Rekor v2 JS-Proof (`/.well-known/rustcom-manifest.json`)

- Pinned `rust-toolchain.toml`, `Cargo.lock` (`--locked`), digest-pinned Docker/Nix builder, pinned `wasm-bindgen-cli` & `binaryen` (`wasm-opt -Oz --strip-debug --strip-producers`), `RUSTFLAGS="--remap-path-prefix=$HOME=/home --remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME=/cargo"`, fixed `SOURCE_DATE_EPOCH`.
- Dual-directory CI determinism gate (`/build-a` vs `/build-b` identical `sha256sum`) -> Sigstore Cosign OIDC attestation logged to **Rekor v2**.
- `rustcom-verify` CLI (Dec 31 MVP) + Browser Extension (Phase 2) verify: (1) `sigstore_bundle` against Fulcio + Rekor v2, (2) live served JS/WASM + HTML `<script>` + CSP against manifest hashes with zero unlisted scripts, (3) `/.well-known/rustcom-skl.json` chain, (4) optional `--rebuild` from `git_commit` inside pinned Docker builder.

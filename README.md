# rustcom-crypto (Public, AGPL-3.0)

Minimal, auditable, `#![forbid(unsafe_code)]` Rust + WebAssembly cryptography and verifiable-client toolkit powering 3-tier E2EE order records, post-quantum hybrid X-Wing (`ML-KEM-768 + X25519`) envelopes, Mullvad-style 128-bit Crockford Strict Account IDs, client-side private product decryption, and Sigstore Rekor v2 JS-Proof verification.

## Crates (Sprint 1 Complete)
- `crates/rustcom-crypto-core` -- `no_std` + `wasm32` + native Rust (`RCENC` v1, `RCSTR` v1, `StaffGrantV1`, SKL, BIP-39/Shamir, Mullvad IDs, Private Products, Review Tokens).
- `crates/rustcom-crypto-wasm` -- Deterministic `wasm-bindgen` bindings compiled reproducibly for browser checkout & admin decryption.
- `crates/rustcom-verify` -- Independent CLI verifying live store JS/WASM hashes, RFC 3161 TSA / Sigstore Rekor v2 bundles, and Signed Key Lists, plus clean `git archive` `--rebuild`.
- `builder/Dockerfile.wasm` & `scripts/build-wasm-deterministic.sh` -- Non-root digest-pinned dual-path deterministic WASM builder (`cargo vendor --locked` + `--network=none`).

## Specification
See `docs/protocol-spec.md`.

## Security & Audits
See `SECURITY.md`. Every release includes deterministic dual-path CI build verification and a Rekor v2 inclusion proof.

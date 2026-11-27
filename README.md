# sovret-crypto (Public, AGPL-3.0)

Minimal, auditable, `#![forbid(unsafe_code)]` Rust + WebAssembly cryptography and verifiable-client toolkit powering 3-tier E2EE order records, post-quantum hybrid X-Wing (`ML-KEM-768 + X25519`) envelopes, Mullvad-style 128-bit Crockford Strict Account IDs, client-side private product/blog/download decryption, **minimal verifiable storefront client JS (`<= 50 KB` brotli)**, and Sigstore Rekor v2 JS-Proof verification (`ADR-032`).

## Crates & Verifiable Web Surface
- `crates/sovret-crypto-core` -- `no_std` + `wasm32` + native Rust (`RCENC` v1, `RCSTR` v1, `StaffGrantV1`, SKL, BIP-39/Shamir, Mullvad IDs, Private Products; Platform Review Tokens specified in `docs/protocol-spec.md` for Sprint 4 `S4-4`).
- `crates/sovret-crypto-wasm` -- Deterministic `wasm-bindgen` bindings compiled reproducibly for browser checkout, private unlock, and Strict portal decryption.
- `storefront-js/` *(Scheduled Sprint 5, `ADR-032`)* -- Minimal publicly auditable storefront client JS (`checkout.js`, `portal.js`, vendored Datastar, `storefront-live.js`) compiled & packaged alongside `sovret-crypto-wasm` under a single `git_commit` and signed `release-manifest.json` so `sovret-web` (SSR templates, ~50 themes, marketing site, Dioxus Admin) can stay private without weakening buyer-side JS-Proof.
- `crates/sovret-verify` -- Independent CLI verifying live store JS/WASM hashes, RFC 3161 TSA / Sigstore Rekor v2 bundles, and Signed Key Lists, plus clean `git archive` `--rebuild` *(and planned offline `decrypt-order` / backup decryptor subcommand so zero-trust `Strict` merchants can decrypt orders/backups offline without trusting the closed-source Admin GUI)*.
- `.github/workflows/verify-live-store.yml` *(Scheduled Sprint 5, `ADR-032`)* -- Public GitHub Actions live-store JS/WASM checker (`workflow_dispatch` taking any store URL + scheduled reference-store audits) running `sovret-verify` against Rekor v2 and this repository's release tags.
- `builder/Dockerfile.wasm` & `scripts/build-wasm-deterministic.sh` -- Non-root digest-pinned dual-path deterministic WASM + storefront-JS builder (`cargo vendor --locked` + `--network=none`).

## Specification
See `docs/protocol-spec.md`.

## Security & Audits
See `SECURITY.md`. Every release includes deterministic dual-path CI build verification and a Rekor v2 inclusion proof.

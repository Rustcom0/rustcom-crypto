# AGENTS.md (`sovret-crypto`)

Public AGPL-3.0 auditable cryptography, minimal verifiable storefront client JS (`<= 50 KB` brotli), and JS-Proof verifier repository (`ADR-032`).

## Mandatory Cryptography & Verifiability Rules
- `#![forbid(unsafe_code)]` across all crates in this repository.
- Zero panics in library paths: deny `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro`.
- Implement `Zeroize` / `ZeroizeOnDrop` on every secret key, DEK, shared secret, and KEK type.
- Use `subtle::ConstantTimeEq` for all secret/tag/checksum comparisons.
- Heap-allocate (`Box`) large ML-KEM polynomial structures to avoid `wasm32` stack overflow.
- Keep `sovret-crypto-core` strictly `no_std` + `alloc` compatible and deterministic for `wasm32-unknown-unknown` (`getrandom` `wasm_js`).
- Keep `storefront-js/` (Sprint 5) strictly minimal, dependency-free (only vendored pinned Datastar + tiny checkout/portal/live glue), and packaged in the exact same single-commit deterministic `release-manifest.json` + Rekor v2 attestation as `sovret-crypto-wasm`.
- Any change to wire formats (`RCENC`, `RCSTR`, `StaffGrantV1`, `canonical_aad`) must consult and update `docs/protocol-spec.md` on demand, update test vectors in `vectors/`, and pass `security-reviewer` (`gemini-4-neon#xhigh`). Store actionable audit findings in gitignored `.tmp/sec-findings.md` and remediate them in a fresh `security-fixer` session (or `/sec-fix`), deleting `.tmp/sec-findings.md` once verified green.

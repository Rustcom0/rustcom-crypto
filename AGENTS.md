# AGENTS.md (`rustcom-crypto`)

Public AGPL-3.0 auditable cryptography & JS-Proof repository.

## Mandatory Cryptography Rules
- `#![forbid(unsafe_code)]` across all crates in this repository.
- Zero panics in library paths: deny `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro`.
- Implement `Zeroize` / `ZeroizeOnDrop` on every secret key, DEK, shared secret, and KEK type.
- Use `subtle::ConstantTimeEq` for all secret/tag/checksum comparisons.
- Heap-allocate (`Box`) large ML-KEM polynomial structures to avoid `wasm32` stack overflow.
- Keep `rustcom-crypto-core` strictly `no_std` + `alloc` compatible and deterministic for `wasm32-unknown-unknown` (`getrandom` `wasm_js`).
- Any change to wire formats (`RCENC`, `RCSTR`, `StaffGrantV1`, `canonical_aad`) must update `docs/protocol-spec.md`, test vectors in `vectors/`, and pass `/sec-audit` (`security-reviewer`, Gemini 4 Neon).

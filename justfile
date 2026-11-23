default:
    @just --list

check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo check -p rustcom-crypto-wasm --target wasm32-unknown-unknown

test:
    cargo nextest run --workspace

sec:
    gitleaks detect --no-git --redact
    cargo audit
    cargo deny check

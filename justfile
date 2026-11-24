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

build-wasm-deterministic:
    docker build -f builder/Dockerfile.wasm -t rustcom-wasm-builder:local .
    mkdir -p dist
    docker run --rm \
        -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD 2>/dev/null || echo 1700000000)" \
        -e RELEASE_VERSION="0.1.0" \
        -e GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo 0000000000000000000000000000000000000000)" \
        -e BUILDER_IMAGE_DIGEST="$(docker image inspect --format='{{{{.Id}}}}' rustcom-wasm-builder:local)" \
        -v "$(pwd):/src:ro" \
        -v "$(pwd)/dist:/out:rw" \
        rustcom-wasm-builder:local

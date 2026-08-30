# Contributing

## Setup

```bash
git clone https://github.com/P3M-ACTF/metadissect.git
cd metadissect
```

Consumers (MetaInstructor / MetaTrace / MetaFake) expect this checkout as a **sibling** under the Metadata umbrella when using `[patch]`.

## Checks

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

**MSRV:** Rust **1.89**.

CI de PRs = **Linux debug** only (fmt + clippy + test). Windows/macOS: en tu máquina o `workflow_dispatch`. No hace `cargo build --release` en cada push.

## Documentation

Product docs (Uso, Arquitectura, Desarrollo, Estado) live in the **[GitHub Wiki](https://github.com/P3M-ACTF/metadissect/wiki)**. Do **not** add LLM instruction dumps (`CLAUDE.md`, `llms.txt`, `.cursorrules`, session transcripts). The only agent contract in-repo is [`AGENTS.md`](AGENTS.md).

## Pull requests

- Open PRs against **`main`**.
- Do **not** commit `evidence/`, `.env`, secrets, or real case files.

## HTTP API

El binario sirve solo JSON (`metadissect serve --api`). No hay UI educativa aquí. Por defecto `127.0.0.1:8787`; no enlaces `0.0.0.0` en demos públicas sin auth.

## Releasing / crates.io / tag pin for consumers

1. Bump workspace `version`, update `CHANGELOG.md`.
2. Verify package: `cargo publish -p metadissect --dry-run`
3. Publish library (needs [crates.io](https://crates.io) token):

```powershell
# One-time: https://crates.io/me → New Token → then:
cargo login
cargo publish -p metadissect
```

4. Tag `vX.Y.Z` and publish [Releases](https://github.com/P3M-ACTF/metadissect/releases) (CLI binaries).
5. Downstream repos update `metadissect` / `meta-ui` git `tag = "vX.Y.Z"` (and CI `ref:`) — keep local `[patch]` for umbrella work.

`metadissect-cli` and `meta-ui` have `publish = false`. Only publish the `metadissect` library crate.

**crates.io:** `cargo publish -p metadissect` requires `cargo login` on the maintainer machine. If not logged in, run `cargo publish -p metadissect --dry-run` only and document the gap in CHANGELOG.

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

## Pull requests

- Open PRs against **`main`**.
- CI runs **Linux debug** only. Windows/macOS: test locally or via `workflow_dispatch` if available.
- Do **not** commit `evidence/`, `.env`, secrets, or real case files.

## Releasing / tag pin for consumers

1. Bump workspace `version`, update `CHANGELOG.md`.
2. Tag `vX.Y.Z` and publish [Releases](https://github.com/P3M-ACTF/metadissect/releases).
3. Downstream repos update `metadissect = { git = "...", tag = "vX.Y.Z" }` (keep local `[patch]` for umbrella work).

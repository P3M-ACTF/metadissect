# AGENTS.md

Contrato mínimo para agentes/humanos que retoman este repo. Docs largas viven en la **wiki**, no en más archivos para LLM.

## Misión

**MetaDissect** = librería + CLI + API JSON (`serve --api`) + TUI. Análisis local de metadatos. **No** es UI educativa, crawler ni FOCA.

## Antes de implementar

1. [Wiki Home](https://github.com/P3M-ACTF/metadissect/wiki)
2. [Wiki Estado](https://github.com/P3M-ACTF/metadissect/wiki/Estado) — pin, bloqueos, siguiente paso

## Familia / pin

Umbrella local: sibling `../metadissect`. Consumidores fijan por **git tag** (`v0.11.1`) + `[patch]` a este checkout. No publicar `meta-ui` ni `metadissect-cli` en crates.io (solo crate `metadissect`).

## Nunca

- Evidencias reales, `.env`, secretos, tokens de serve
- Añadir `CLAUDE.md`, `llms.txt`, `.cursorrules`, dumps de sesión
- Refactors grandes de parsers sin pedido explícito

## Checks

```bash
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

MSRV **1.89**. CI frugal (debug Linux); no `--release` en cada push.

## API docs

Rustdoc / [docs.rs/metadissect](https://docs.rs/metadissect) = API de la lib. Wiki = producto y estado.

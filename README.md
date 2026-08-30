# MetaDissect 🔍

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/P3M-ACTF/metadissect)](https://github.com/P3M-ACTF/metadissect/releases)
[![CI](https://github.com/P3M-ACTF/metadissect/actions/workflows/ci.yml/badge.svg)](https://github.com/P3M-ACTF/metadissect/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.89%2B-orange.svg)](https://github.com/P3M-ACTF/metadissect)
[![Library](https://img.shields.io/badge/library-git%20tag-informational.svg)](https://github.com/P3M-ACTF/metadissect/releases/tag/v0.11.1)

Motor Rust de metadatos **local y exhaustivo** (lib + CLI + API JSON + TUI). Binario: `metadissect` · **v0.11.1**.

> [!NOTE]
> Todo el análisis corre en tu máquina. Solo se descarga una URL si usas `fetch` o `POST /api/fetch`.

> [!IMPORTANT]
> Bind fuera de loopback (`0.0.0.0`, etc.) **exige** `--token` / `META_SERVE_TOKEN`. Sin token el servidor no arranca en remoto.

> [!NOTE]
> Sin trust anchors oficiales, `Valid ≠ Trusted` en C2PA es lo esperado: firmas se verifican, la confianza de ancla no viene incluida.

## Arranque en 30 s

```bash
# Binario: https://github.com/P3M-ACTF/metadissect/releases
metadissect foto.jpg --no-tui -f json
metadissect serve --api                 # 127.0.0.1:8787
```

Desde fuente (segundo recurso):

```bash
git clone https://github.com/P3M-ACTF/metadissect.git && cd metadissect
cargo build --release -p metadissect-cli
```

## Qué es / no es

**Es**

- Extrae metadatos en local (CLI, lib, API JSON, TUI).
- Cubre PDF, Office, imágenes, audio, EML/MSG, WARC, HTML/JSON, C2PA/JUMBF, PE/ELF/Mach-O y más.
- Expone `serve --api` en loopback por defecto.
- Se consume por git tag desde Instructor / Trace / Fake.

**No es**

- La web educativa ([MetaInstructor](https://github.com/P3M-ACTF/metainstructor)).
- Un crawler ni un FOCA.
- Paridad total con ExifTool.
- Un validador C2PA con lista de confianza remota.

## Familia

Cuatro repos, un motor:

| Proyecto | Acceso | Rol |
|----------|--------|-----|
| **MetaDissect** | [público](https://github.com/P3M-ACTF/metadissect) | Lib + CLI + API JSON |
| **MetaInstructor** | [público](https://github.com/P3M-ACTF/metainstructor) | Web educativa |
| **MetaTrace** | Privado — Hellcode Collective | IR / forense |
| **MetaFake** | Privado — Hellcode Collective | Mutación (copias) |

## Privacidad

> [!NOTE]
> Análisis local. No hay telemetría. URLs solo vía `fetch` / API fetch explícitos.

## Docs y licencia

Docs largas: **[Wiki](https://github.com/P3M-ACTF/metadissect/wiki)** · retomar: **[Estado](https://github.com/P3M-ACTF/metadissect/wiki/Estado)** · API lib: [docs.rs/metadissect](https://docs.rs/metadissect).

Crates: `metadissect` (publicable) · `metadissect-cli` / `meta-ui` (`publish = false`).

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

<details>
<summary>English</summary>

**MetaDissect** (**v0.11.1**) is a Rust library + CLI + optional JSON HTTP API for exhaustive local metadata analysis. Binary: `metadissect`.

**Is:** library, CLI, `serve --api`, terminal TUI. **Is not:** educational web UI (MetaInstructor), crawler, or FOCA. No full ExifTool parity; no remote C2PA trust list (`Valid ≠ Trusted` without anchors).

```bash
metadissect foto.jpg --no-tui -f json
metadissect serve --api --token "$META_SERVE_TOKEN"   # required off-loopback
```

Long-form docs: **[Wiki](https://github.com/P3M-ACTF/metadissect/wiki)** (Spanish). Privacy: local analysis; URLs only via `fetch`. License: [MIT](LICENSE).

</details>

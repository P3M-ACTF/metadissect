# MetaDissect

Biblioteca y CLI Rust para análisis **local y exhaustivo** de metadatos (**v0.11.1**). Binario: `metadissect`.

## Qué es / qué no es

**Es:** librería + CLI + API HTTP JSON (`serve --api`) + TUI en terminal. Extrae metadatos que cada parser lee (PDF, Office, imágenes, audio, EML/MSG, WARC, HTML/JSON, C2PA/JUMBF, PE/ELF/Mach-O, MakerNotes parciales, OLE CFBF legado — subset, etc.).

**No es:** UI web educativa ([MetaInstructor](https://github.com/P3M-ACTF/metainstructor)), crawler ni FOCA. Sin paridad total con ExifTool. No descarga manifiestos C2PA remotos ni trae la lista de confianza oficial (`Valid ≠ Trusted` es lo normal sin anchors).

Docs largas: **[Wiki](https://github.com/P3M-ACTF/metadissect/wiki)** · estado para retomar: **[Estado](https://github.com/P3M-ACTF/metadissect/wiki/Estado)**.

## Familia

| Proyecto | Acceso | Rol |
|----------|--------|-----|
| **MetaDissect** | [público](https://github.com/P3M-ACTF/metadissect) | Lib + CLI + API JSON |
| **MetaInstructor** | [público](https://github.com/P3M-ACTF/metainstructor) | Web educativa |
| **MetaTrace** | Privado — Hellcode Collective | IR / forense |
| **MetaFake** | Privado — Hellcode Collective | Mutación (copias) |

## Instalación

```bash
cargo add metadissect
# o binario: https://github.com/P3M-ACTF/metadissect/releases
git clone https://github.com/P3M-ACTF/metadissect.git && cd metadissect
cargo build --release -p metadissect-cli
```

## Comandos

```bash
metadissect foto.jpg                    # TUI analyze en TTY
metadissect foto.jpg --no-tui -f json
metadissect analyze documento.pdf -f json
metadissect fetch https://example.com/page.html -f markdown
metadissect serve --api                 # 127.0.0.1:8787
metadissect serve --api --host 0.0.0.0 --token "$META_SERVE_TOKEN"
```

TUI, auth remota (`Bearer` / `?token=`), retain y rutas API → [Wiki · Uso](https://github.com/P3M-ACTF/metadissect/wiki/Uso).

## Librería

```rust
use std::path::Path;
use metadissect::analyze_path;

let analysis = analyze_path(Path::new("photo.jpg"))?;
println!("{} — {} fields", analysis.mime, analysis.field_count());
```

API: [docs.rs/metadissect](https://docs.rs/metadissect).

## Privacidad

Análisis local. Solo se descarga una URL con `fetch` / `POST /api/fetch`.

## Crates

`metadissect` (publicable) · `metadissect-cli` / `meta-ui` (`publish = false`; `meta-ui` por git tag).

## Licencia

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

---

## English

**MetaDissect** (**v0.11.1**) is a Rust library + CLI + optional JSON HTTP API for exhaustive local metadata analysis. Binary: `metadissect`.

**Is:** library, CLI, `serve --api`, terminal TUI. **Is not:** educational web UI (MetaInstructor), crawler, or FOCA. No full ExifTool parity; no remote C2PA trust list.

Long-form docs: **[Wiki](https://github.com/P3M-ACTF/metadissect/wiki)** (Spanish) · resume snapshot: **[Estado](https://github.com/P3M-ACTF/metadissect/wiki/Estado)**.

```bash
cargo add metadissect
metadissect foto.jpg --no-tui -f json
metadissect serve --api --token "$META_SERVE_TOKEN"
```

Privacy: local analysis; URLs only via `fetch`. License: [MIT](LICENSE).

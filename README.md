# MetaDissect

Biblioteca y CLI Rust para análisis **local y exhaustivo** de metadatos (v0.10.0). Binario: `metadissect`.

## Qué es / qué no es

**Es:** librería + CLI + API HTTP JSON opcional. Extrae tags que cada parser lee (PDF, Office, imágenes, audio, EML/MSG, WARC, HTML/JSON, C2PA/JUMBF, PE/ELF/Mach-O, MakerNotes parciales, etc.). Comandos: `analyze`, `fetch`, `extract`, `html`, `json`, `serve --api`. Formatos: `table`, `json`, `markdown`, `csv`.

**No es:** interfaz web educativa (eso es MetaInstructor), crawler ni FOCA. Sin UI. No descarga manifiestos C2PA remotos ni incluye la lista de confianza C2PA oficial (firma válida ≠ `Trusted`). No valida cadenas Authenticode (solo lista certificados).

## Qué no entra (este ciclo)

- Paridad total de tags con ExifTool
- Lista de confianza CAI oficial embebida en el binario
- Descarga de manifiestos C2PA remotos (sigue siendo solo local)
- `cargo publish` en crates.io (hace falta `cargo login`)
- Parsers de la Fase C: OLE CFBF `.doc/.xls/.ppt`, feature C2PA-in-PDF del crate, MakerNotes más profundos, validación de cadena Authenticode, PST, HEIC item/iloc, ICC profundo, PAdES completo
- Dump estilo ExifTool `--compare` / `-G`
- Actions privadas de MetaTrace/MetaFake (facturación de la org)

`--trust-anchors` / `C2PA_TRUST_ANCHORS` alimentan el verificador CAI (`Settings.trust.trust_anchors`). Sin la lista oficial, **`Valid ≠ Trusted` es lo normal**.

## Familia MetaDissect

| Proyecto | Acceso | Rol |
|----------|--------|-----|
| **MetaDissect** | [público](https://github.com/P3M-ACTF/metadissect) | Lib + CLI + API JSON, sin UI |
| **MetaInstructor** | [público](https://github.com/P3M-ACTF/metainstructor) | Web educativa |
| **MetaTrace** | Privado — Hellcode Collective | Herramienta IR / forense |
| **MetaFake** | Privado — Hellcode Collective | Mutación de metadatos (copias) |

## Instalación

**Como dependencia (crates.io):**

```bash
cargo add metadissect
```

**Releases:** descarga el binario de [Releases](https://github.com/P3M-ACTF/metadissect/releases) para tu SO.

**Desde código:**

```bash
git clone https://github.com/P3M-ACTF/metadissect.git
cd metadissect
cargo build --release -p metadissect-cli
# binario: target/release/metadissect
```

```powershell
cargo build --release -p metadissect-cli
.\target\release\metadissect.exe --help
```

## Ejemplos CLI

```bash
metadissect foto.jpg
metadissect analyze documento.pdf -f json
metadissect fetch https://example.com/page.html -f markdown
metadissect html --file page.html -f csv
metadissect json --file data.json
metadissect imagen.png --sections c2pa,normalized,general
metadissect imagen.png --verbose
metadissect imagen.png --trust-anchors ./c2pa-trust.pem
metadissect extract imagen.png --assertion c2pa.actions -o actions.json
metadissect extract imagen.png --thumbnail -o thumb.jpg
metadissect extract imagen.png --c2pa-icon -o icon.bin
```

## API HTTP JSON (sin UI)

Por defecto solo escucha en localhost. Aviso si usas `0.0.0.0` / `::` (sin autenticación).

```bash
metadissect serve --api
# http://127.0.0.1:8787
metadissect serve --api --host 127.0.0.1 --port 8787
```

| Método | Ruta | Cuerpo |
|--------|------|--------|
| `GET` | `/api/health` | — |
| `POST` | `/api/analyze` | `multipart` con archivo |
| `POST` | `/api/analyze-text` | JSON `{ "text", "kind": "html\|json", "filename"? }` |
| `POST` | `/api/fetch` | JSON `{ "url" }` (misma política anti-SSRF que `fetch`) |

```bash
curl -s http://127.0.0.1:8787/api/health
curl -s -F "file=@foto.jpg" http://127.0.0.1:8787/api/analyze
```

## Librería

```rust
use std::path::Path;
use metadissect::analyze_path;

let analysis = analyze_path(Path::new("photo.jpg"))?;
println!("{} — {} fields", analysis.mime, analysis.field_count());
```

Docs: [docs.rs/metadissect](https://docs.rs/metadissect).

## Privacidad

El análisis es local. Una URL solo se descarga si usas `fetch` o `POST /api/fetch`. No se envían archivos a terceros.

## Estructura de crates

| Crate | Rol |
|-------|-----|
| `metadissect` | Librería de análisis (publicable en crates.io) |
| `metadissect-cli` | Binario `metadissect` (CLI + `serve --api`) |

## Licencia

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

---

## English

**MetaDissect** is a Rust **library + CLI + optional JSON HTTP API** (v0.10.0) for exhaustive local metadata analysis. Binary: `metadissect`.

### What it is / is not

**Is:** library, CLI, and thin JSON API (`serve --api`). Commands: `analyze`, `fetch`, `extract`, `html`, `json`, `serve`. Output: `table`, `json`, `markdown`, `csv`. Includes C2PA/JUMBF (feature `c2pa`, default), PE/ELF/Mach-O, WARC, Outlook MSG (subset), and pragmatic MakerNote vendor/subset decode.

**Is not:** an educational web UI (see MetaInstructor), crawler, or FOCA-like tool. Does not fetch remote C2PA manifests or ship the official C2PA trust list. Authenticode is listed, not chain-validated.

### Out of scope (this cycle)

- Full ExifTool tag parity
- Official CAI trust list bundled in the binary
- Fetch of remote C2PA manifests (stays local-only)
- crates.io `cargo publish` (still needs `cargo login`)
- Phase C parsers: OLE CFBF `.doc/.xls/.ppt`, C2PA-in-PDF crate feature, deeper MakerNotes, Authenticode chain validation, PST, HEIC item/iloc, deep ICC, full PAdES
- ExifTool `--compare` / `-G` style dump
- MetaTrace/MetaFake private Actions (org billing)

`--trust-anchors` / `C2PA_TRUST_ANCHORS` feed the CAI verifier (`Settings.trust.trust_anchors`). Without the official list, **`Valid ≠ Trusted` is normal**.

### Family

| Project | Access | Role |
|---------|--------|------|
| **MetaDissect** | [public](https://github.com/P3M-ACTF/metadissect) | Lib + CLI + JSON API, no UI |
| **MetaInstructor** | [public](https://github.com/P3M-ACTF/metainstructor) | Educational web |
| **MetaTrace** | Private — Hellcode Collective | IR / forensic tool |
| **MetaFake** | Private — Hellcode Collective | Metadata mutation (copies) |

### Install

```bash
cargo add metadissect
```

From [Releases](https://github.com/P3M-ACTF/metadissect/releases), or `cargo build --release -p metadissect-cli`.

### CLI / API

```bash
metadissect foto.jpg
metadissect analyze documento.pdf -f json
metadissect imagen.png --trust-anchors ./c2pa-trust.pem
metadissect extract imagen.png --assertion c2pa.actions -o actions.json
metadissect serve --api   # http://127.0.0.1:8787
```

### Privacy

Analysis is local. URLs are fetched only via `fetch` / `POST /api/fetch`.

### Crates

`metadissect` (library, crates.io), `metadissect-cli` (binary; not published).

### License

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

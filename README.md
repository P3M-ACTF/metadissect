# MetaDissect

Biblioteca y CLI Rust para análisis **local y exhaustivo** de metadatos (v0.11.0). Binario: `metadissect`.

## Qué es / qué no es

**Es:** librería + CLI + API HTTP JSON opcional + TUI interactiva en terminal. Extrae tags que cada parser lee (PDF, Office, imágenes, audio, EML/MSG, WARC, HTML/JSON, C2PA/JUMBF, PE/ELF/Mach-O, MakerNotes parciales, OLE CFBF legado — subset, etc.). Comandos: `analyze`, `fetch`, `extract`, `html`, `json`, `serve --api`. Formatos: `table`, `json`, `markdown`, `csv` (`--no-tui` para export).

**No es:** interfaz web educativa (eso es MetaInstructor), crawler ni FOCA. Sin UI. No hay paridad total de tags con ExifTool. No descarga manifiestos C2PA remotos ni incluye la lista de confianza C2PA oficial (firma válida ≠ `Trusted`). No valida cadenas Authenticode (solo lista certificados).

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
metadissect foto.jpg                    # TUI analyze en TTY
metadissect foto.jpg --no-tui -f json   # export sin TUI
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

## TUI analyze

En TTY, `analyze` abre una TUI ratatui (secciones, campos, `/` filtrar, `j/k` mover, `q` salir). Usa `--no-tui` o `-f json|csv|markdown` para export estructurado. Ver [`docs/tui.md`](docs/tui.md).

## API HTTP JSON (sin UI educativa)

Por defecto solo escucha en localhost. En bind remoto (`0.0.0.0`, `::`, etc.) exige token.

```bash
metadissect serve --api
# http://127.0.0.1:8787  (+ dashboard TUI de stats en TTY)
metadissect serve --api --host 0.0.0.0 --token "$META_SERVE_TOKEN"
metadissect serve --api --retain-dir ./uploads --retain-ttl 3600
```

Auth remota: header `Authorization: Bearer TOKEN` **o** query `?token=TOKEN`. Variable/env: `META_SERVE_TOKEN` / `--token`. Ver [`docs/serve.md`](docs/serve.md).

| Método | Ruta | Cuerpo |
|--------|------|--------|
| `GET` | `/api/health` | — |
| `GET` | `/api/retained` | lista uploads retenidos (`--retain-dir`) |
| `POST` | `/api/analyze` | `multipart` con archivo |
| `POST` | `/api/analyze-text` | JSON `{ "text", "kind": "html\|json", "filename"? }` |
| `POST` | `/api/fetch` | JSON `{ "url" }` (misma política anti-SSRF que `fetch`) |

```bash
curl -s http://127.0.0.1:8787/api/health
curl -s -F "file=@foto.jpg" http://127.0.0.1:8787/api/analyze
curl -s -H "Authorization: Bearer $META_SERVE_TOKEN" http://HOST:8787/api/health
curl -s "http://HOST:8787/api/health?token=$META_SERVE_TOKEN"
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
| `metadissect-cli` | Binario `metadissect` (CLI + `serve --api`; `publish = false`) |
| `meta-ui` | Shell compartido, banners, stats serve, TUI (`publish = false`; consumidores lo toman del repo) |

## Licencia

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

---

## English

**MetaDissect** is a Rust **library + CLI + optional JSON HTTP API** (v0.11.0) for exhaustive local metadata analysis. Binary: `metadissect`.

### What it is / is not

**Is:** library, CLI, and thin JSON API (`serve --api`). Commands: `analyze`, `fetch`, `extract`, `html`, `json`, `serve`. Output: `table`, `json`, `markdown`, `csv`. Includes C2PA/JUMBF (feature `c2pa`, default), PE/ELF/Mach-O, WARC, Outlook MSG (subset), and pragmatic MakerNote vendor/subset decode.

**Is not:** an educational web UI (see MetaInstructor), crawler, or FOCA-like tool. No full ExifTool tag parity. Does not fetch remote C2PA manifests or ship the official C2PA trust list. Authenticode is listed, not chain-validated.

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
metadissect foto.jpg              # TUI on TTY
metadissect analyze documento.pdf -f json
metadissect serve --api --token "$META_SERVE_TOKEN"
```

### Privacy

Analysis is local. URLs are fetched only via `fetch` / `POST /api/fetch`.

### Crates

`metadissect` (library, crates.io), `metadissect-cli` and `meta-ui` (not published; `meta-ui` is consumed via git tag from this repo).

### License

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

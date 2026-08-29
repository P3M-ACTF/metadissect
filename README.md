# MetaDissect

Biblioteca y CLI Rust para análisis **local y exhaustivo** de metadatos (v0.6.0). Binario: `metadissect`.

## Qué es / qué no es

**Es:** librería + CLI. Extrae tags que cada parser lee (PDF, Office, imágenes, audio, EML, HTML/JSON, C2PA/JUMBF, PE/ELF/Mach-O, etc.). Comandos: `analyze`, `fetch`, `html`, `json`. Formatos: `table`, `json`, `markdown`, `csv`.

**No es:** interfaz web, servidor (`serve`), crawler ni FOCA. Sin UI. No descarga manifiestos C2PA remotos ni incluye la lista de confianza C2PA oficial (firma válida ≠ `Trusted`). No valida cadenas Authenticode (solo lista certificados).

## Familia MetaDissect

| Proyecto | Acceso | Rol |
|----------|--------|-----|
| **MetaDissect** | [público](https://github.com/P3M-ACTF/metadissect) | Lib + CLI, sin UI |
| **MetaInstructor** | [público](https://github.com/P3M-ACTF/metainstructor) | Web educativa |
| **MetaTrace** | Privado — Hellcode Collective | Herramienta IR / forense |
| **MetaFake** | Privado — Hellcode Collective | Mutación de metadatos (copias) |

## Instalación

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
```

## Privacidad

El análisis es local. Una URL solo se descarga si usas `fetch`. No se envían archivos a terceros.

## Estructura de crates

| Crate | Rol |
|-------|-----|
| `metadissect` | Librería de análisis |
| `metadissect-cli` | Binario `metadissect` |

## Licencia

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

---

## English

**MetaDissect** is a Rust **library + CLI** (v0.6.0) for exhaustive local metadata analysis. Binary: `metadissect`.

### What it is / is not

**Is:** library and CLI. Commands: `analyze`, `fetch`, `html`, `json`. Output: `table`, `json`, `markdown`, `csv`. Includes C2PA/JUMBF when present (feature `c2pa`, default) and PE/ELF/Mach-O executable metadata.

**Is not:** a web UI, `serve` endpoint, crawler, or FOCA-like tool. Does not fetch remote C2PA manifests or ship the official C2PA trust list. Authenticode is listed, not chain-validated.

### Family

| Project | Access | Role |
|---------|--------|------|
| **MetaDissect** | [public](https://github.com/P3M-ACTF/metadissect) | Lib + CLI, no UI |
| **MetaInstructor** | [public](https://github.com/P3M-ACTF/metainstructor) | Educational web |
| **MetaTrace** | Private — Hellcode Collective | IR / forensic tool |
| **MetaFake** | Private — Hellcode Collective | Metadata mutation (copies) |

### Install

From [Releases](https://github.com/P3M-ACTF/metadissect/releases), or:

```bash
cargo build --release -p metadissect-cli
```

### CLI examples

```bash
metadissect foto.jpg
metadissect analyze documento.pdf -f json
metadissect fetch https://example.com/page.html -f markdown
```

### Privacy

Analysis is local. URLs are fetched only via `fetch`.

### Crates

`metadissect` (library), `metadissect-cli` (binary).

### License

[MIT](LICENSE) — Copyright 2026 MetaDissect Contributors.

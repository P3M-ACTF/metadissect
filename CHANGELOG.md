# Changelog

## 0.8.0

- **crates.io readiness:** library crate metadata (description, license, repository, homepage, keywords, categories, readme, docs.rs); expanded rustdoc on the crate root.
- **JSON HTTP API (no UI):** `metadissect serve --api` (default `127.0.0.1:8787`). Endpoints: `GET /api/health`, `POST /api/analyze` (multipart), `POST /api/analyze-text`, `POST /api/fetch` (SSRF-safe). Warns when binding `0.0.0.0` / `::`. Axum lives in `metadissect-cli` only.
- Documented install via `cargo add metadissect` / `cargo publish` one-liner for maintainers.

## 0.7.0

- **WARC (ISO 28500):** parse `warcinfo` / `request` / `response` / `metadata` records; surface WARC-Target-URI, WARC-Date, WARC-IP-Address, payload/block digests, and selected HTTP headers; graceful warnings on truncated files.
- **MSG/MAPI:** Outlook `.msg` via OLE CFBF (`cfb`); Subject, From, To, Cc, dates, Message-ID, attachment names when present. Honest warning that the full MAPI property set is not decoded. PST remains out of scope.
- **MakerNotes:** EXIF `0x927C` no longer opaque-only — vendor detect (Canon/Nikon/Sony/Apple) plus a pragmatic IFD subset when headers/offsets allow; otherwise length/offset/vendor with clear “not fully decoded” notes (not ExifTool parity).
- Fixtures: `sample.warc`, `sample.msg` (`cargo run -p metadissect --example write_phase5_fixtures`).

## 0.6.0

- **Executables (Phase 4):** PE, ELF, and Mach-O metadata via `goblin`.
- **PE:** VS_VERSIONINFO (CompanyName, ProductName, FileVersion, OriginalFilename, …), Rich Header (XOR-decoded tool telemetry with known CompID labels), sections (virtual vs raw sizes + packer hints), import table / IAT summary, Authenticode certificate table (type, blob hashes, best-effort Subject CN / leaf thumbprint — no chain validation).
- **ELF:** headers, program/section headers, `NT_GNU_BUILD_ID` and other notes when present.
- **Mach-O:** headers, segments/sections, UUID / build-version / version-min when present (including fat binaries).
- Magic sniffing + `parse_for_mime` dispatch for PE/ELF/Mach-O; fixtures `minimal.exe` / `minimal.elf`.

## 0.5.0

- **C2PA / JUMBF:** detect and parse embedded manifests (JPEG/PNG/ISO-BMFF and other formats supported by the CAI `c2pa` crate) via feature `c2pa` (default on; `rust_native_crypto`, no OpenSSL, no remote manifest fetch).
- Surfaces active manifest, `c2pa.actions` / `c2pa.actions.v2`, hard-binding (`assertion.dataHash.*`) outcome, and COSE issuer / common name when available.
- Honest warnings when validation is Invalid, credentials are untrusted, or remote URLs are present but not fetched.
- Fixture: `fixtures/c2pa-sample.png` (ephemeral-signed synthetic PNG; see `fixtures/README.md`).

## 0.4.0

- **Sniffing:** parser dispatch is magic/MIME-first; filename extension is only used when MIME is `application/octet-stream` / unknown.
- **Normalization:** new `normalized` section with unified keys (`Creator`, `Created`, `Title`, `Software`, `Gps`, …) while preserving source key/namespace/offset in `Field.raw`.
- **MWG:** Photoshop `IPTCDigest` (IRB 0x0425) verification; when out of sync, prefer XMP over IPTC for overlapping properties (IPTC retained with explanation).
- **Embeds:** recursive extraction of OOXML `media/` / `embeddings/` and PDF `EmbeddedFile` streams with depth limit and anchors (`slide:…`, `media:…`, `page:…` / `obj:…`).
- `AnalyzeOptions.max_embed_depth` (default 2).

## 0.3.0

- **Rebrand / split:** MetaDissect is the standalone library + CLI core of the family (no web UI).
- Educational UI lives in **MetaInstructor**; IR in **MetaTrace**; mutation in **MetaFake**.
- CLI: `analyze` / `fetch` / `html` / `json`; formats `table` / `json` / `markdown` / `csv`.
- Workspace crates: `metadissect`, `metadissect-cli`.

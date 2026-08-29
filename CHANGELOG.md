# Changelog

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

# Changelog

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

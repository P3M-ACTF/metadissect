//! ELF metadata: headers, sections/segments, GNU build-id and notes.

use crate::types::{Field, Section};
use goblin::elf::note::Note;
use goblin::elf::note::{NT_GNU_ABI_TAG, NT_GNU_BUILD_ID, NT_GNU_GOLD_VERSION};
use goblin::elf::Elf;

pub fn parse_elf(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();

    let elf = match Elf::parse(data) {
        Ok(e) => e,
        Err(e) => {
            warnings.push(format!("ELF parse failed: {e}"));
            return (sections, warnings);
        }
    };

    sections.push(header_section(&elf));
    if !elf.program_headers.is_empty() {
        sections.push(segments_section(&elf));
    }
    if !elf.section_headers.is_empty() {
        sections.push(sections_section(&elf));
    }
    match notes_section(&elf, data) {
        Some(notes) => sections.push(notes),
        None => {
            warnings.push("ELF: no PT_NOTE / SHT_NOTE notes found (build-id may be absent)".into())
        }
    }

    (sections, warnings)
}

fn header_section(elf: &Elf<'_>) -> Section {
    let mut s = Section::new("elf-header", "ELF header");
    let ns = "ELF";
    s.add("Class", if elf.is_64 { "ELF64" } else { "ELF32" }, Some(ns));
    s.add(
        "Endian",
        if elf.little_endian { "little" } else { "big" },
        Some(ns),
    );
    s.add("Type", elf_type(elf.header.e_type), Some(ns));
    s.add(
        "Machine",
        goblin::elf::header::machine_to_str(elf.header.e_machine),
        Some(ns),
    );
    s.add("Entry", format!("0x{:X}", elf.header.e_entry), Some(ns));
    if let Some(interp) = elf.interpreter {
        s.add("Interpreter", interp.to_string(), Some(ns));
    }
    if let Some(soname) = elf.soname {
        s.add("Soname", soname.to_string(), Some(ns));
    }
    if !elf.libraries.is_empty() {
        let libs: Vec<&str> = elf.libraries.iter().copied().take(32).collect();
        let mut v = libs.join(", ");
        if elf.libraries.len() > 32 {
            v.push_str(&format!(" (+{} more)", elf.libraries.len() - 32));
        }
        s.add("Needed", v, Some(ns));
    }
    s
}

fn segments_section(elf: &Elf<'_>) -> Section {
    let mut s = Section::new("elf-segments", "ELF program headers");
    let ns = "ELF:Segment";
    s.add(
        "ProgramHeaderCount",
        elf.program_headers.len().to_string(),
        Some(ns),
    );
    for (i, ph) in elf.program_headers.iter().take(48).enumerate() {
        s.fields.push(
            Field::new(
                format!("Phdr[{i}]"),
                format!(
                    "{} filesz={} memsz={} offset=0x{:X} vaddr=0x{:X} flags=0x{:X}",
                    goblin::elf::program_header::pt_to_str(ph.p_type),
                    ph.p_filesz,
                    ph.p_memsz,
                    ph.p_offset,
                    ph.p_vaddr,
                    ph.p_flags
                ),
            )
            .with_namespace(ns)
            .with_span(ph.p_offset, ph.p_filesz),
        );
    }
    s
}

fn sections_section(elf: &Elf<'_>) -> Section {
    let mut s = Section::new("elf-sections", "ELF section headers");
    let ns = "ELF:Section";
    s.add(
        "SectionCount",
        elf.section_headers.len().to_string(),
        Some(ns),
    );
    for (i, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name.is_empty() && sh.sh_size == 0 {
            continue;
        }
        let label = if name.is_empty() {
            format!("Shdr[{i}]")
        } else {
            name.to_string()
        };
        s.fields.push(
            Field::new(
                label,
                format!(
                    "{} size={} offset=0x{:X} addr=0x{:X}",
                    goblin::elf::section_header::sht_to_str(sh.sh_type),
                    sh.sh_size,
                    sh.sh_offset,
                    sh.sh_addr
                ),
            )
            .with_namespace(ns)
            .with_span(sh.sh_offset, sh.sh_size),
        );
    }
    s
}

fn notes_section(elf: &Elf<'_>, data: &[u8]) -> Option<Section> {
    let mut s = Section::new("elf-notes", "ELF notes");
    let ns = "ELF:Note";
    let mut any = false;
    let mut seen_build_id = false;

    let mut consume = |note: Note<'_>| {
        any = true;
        let desc_hex = if note.desc.len() <= 64 {
            hex::encode(note.desc)
        } else {
            format!(
                "{}… ({} bytes)",
                hex::encode(&note.desc[..32]),
                note.desc.len()
            )
        };
        match note.n_type {
            NT_GNU_BUILD_ID => {
                if !seen_build_id {
                    s.add("BuildId", hex::encode(note.desc), Some(ns));
                    seen_build_id = true;
                }
            }
            NT_GNU_ABI_TAG => {
                s.add("AbiTag", desc_hex, Some(ns));
            }
            NT_GNU_GOLD_VERSION => {
                let v = String::from_utf8_lossy(note.desc);
                s.add(
                    "GoldVersion",
                    v.trim_end_matches('\0').to_string(),
                    Some(ns),
                );
            }
            _ => {
                s.fields.push(
                    Field::new(
                        format!("Note:{}:{}", note.name.trim_end_matches('\0'), note.n_type),
                        desc_hex,
                    )
                    .with_namespace(ns),
                );
            }
        }
    };

    if let Some(iter) = elf.iter_note_headers(data) {
        for n in iter.flatten() {
            consume(n);
        }
    }
    if let Some(iter) = elf.iter_note_sections(data, None) {
        for n in iter.flatten() {
            consume(n);
        }
    }

    if any {
        Some(s)
    } else {
        None
    }
}

fn elf_type(t: u16) -> &'static str {
    match t {
        0 => "NONE",
        1 => "REL",
        2 => "EXEC",
        3 => "DYN",
        4 => "CORE",
        _ => "OTHER",
    }
}

/// Synthetic ELF64 used by tests and `fixtures/minimal.elf`.
pub fn minimal_elf_fixture() -> Vec<u8> {
    let mut buf = vec![0u8; 0x200];
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    write_u16(&mut buf, 16, 3);
    write_u16(&mut buf, 18, 62);
    write_u32(&mut buf, 20, 1);
    write_u64(&mut buf, 24, 0);
    write_u64(&mut buf, 32, 64);
    write_u64(&mut buf, 40, 0x100);
    write_u16(&mut buf, 52, 64);
    write_u16(&mut buf, 54, 56);
    write_u16(&mut buf, 56, 1);
    write_u16(&mut buf, 58, 64);
    write_u16(&mut buf, 60, 3);
    write_u16(&mut buf, 62, 2);

    write_u32(&mut buf, 64, 4);
    write_u32(&mut buf, 68, 4);
    write_u64(&mut buf, 72, 0xC0);
    write_u64(&mut buf, 80, 0xC0);
    write_u64(&mut buf, 88, 0xC0);
    write_u64(&mut buf, 96, 0x1C);
    write_u64(&mut buf, 104, 0x1C);
    write_u64(&mut buf, 112, 8);

    write_u32(&mut buf, 0xC0, 4);
    write_u32(&mut buf, 0xC4, 8);
    write_u32(&mut buf, 0xC8, 3);
    buf[0xCC..0xD0].copy_from_slice(b"GNU\0");
    buf[0xD0..0xD8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);

    let shstr = b"\0.note.gnu.build-id\0.shstrtab\0";
    buf[0xE0..0xE0 + shstr.len()].copy_from_slice(shstr);

    let sh1 = 0x100 + 64;
    write_u32(&mut buf, sh1, 1);
    write_u32(&mut buf, sh1 + 4, 7);
    write_u64(&mut buf, sh1 + 16, 0);
    write_u64(&mut buf, sh1 + 24, 0xC0);
    write_u64(&mut buf, sh1 + 32, 0x1C);
    write_u64(&mut buf, sh1 + 48, 4);
    let sh2 = 0x100 + 128;
    write_u32(&mut buf, sh2, 19);
    write_u32(&mut buf, sh2 + 4, 3);
    write_u64(&mut buf, sh2 + 24, 0xE0);
    write_u64(&mut buf, sh2 + 32, shstr.len() as u64);

    buf
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze_buffer;
    use crate::types::AnalyzeOptions;

    #[test]
    fn minimal_elf_exposes_build_id() {
        let elf = minimal_elf_fixture();
        let (secs, warns) = parse_elf(&elf);
        assert!(
            !warns.iter().any(|w| w.contains("parse failed")),
            "{warns:?}"
        );
        assert!(secs.iter().any(|s| s.id == "elf-header"));
        let notes = secs.iter().find(|s| s.id == "elf-notes");
        assert!(
            notes
                .map(|n| {
                    n.fields.iter().any(|f| {
                        f.key == "BuildId" && f.value.to_ascii_lowercase().contains("deadbeef")
                    })
                })
                .unwrap_or(false),
            "secs={:?}",
            secs.iter().map(|s| (&s.id, &s.fields)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn analyze_dispatches_elf() {
        let elf = minimal_elf_fixture();
        let a = analyze_buffer(&elf, AnalyzeOptions::from_filename("lib.so"));
        assert!(
            a.sections.iter().any(|s| s.id.starts_with("elf-")),
            "mime={} {:?}",
            a.mime,
            a.sections.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }
}

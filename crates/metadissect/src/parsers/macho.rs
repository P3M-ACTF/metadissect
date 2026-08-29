//! Mach-O metadata: headers, segments/sections, UUID / build version when present.

use crate::types::{Field, Section};
use goblin::mach::load_command::{
    CommandVariant, PLATFORM_BRIDGEOS, PLATFORM_IOS, PLATFORM_IOSSIMULATOR, PLATFORM_MACCATALYST,
    PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_WATCHOS,
};
use goblin::mach::{Mach, MachO};

pub fn parse_macho(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();

    match Mach::parse(data) {
        Ok(Mach::Binary(bin)) => {
            let (secs, warns) = parse_one(&bin);
            sections.extend(secs);
            warnings.extend(warns);
        }
        Ok(Mach::Fat(multi)) => {
            let mut fat = Section::new("macho-fat", "Mach-O fat binary");
            fat.add("ArchCount", multi.narches.to_string(), Some("MachO:Fat"));
            sections.push(fat);
            for (i, arch) in multi.iter_arches().enumerate() {
                match arch {
                    Ok(a) => {
                        let offset = a.offset as usize;
                        let size = a.size as usize;
                        if offset.saturating_add(size) > data.len() {
                            warnings.push(format!("Mach-O fat arch[{i}] out of range"));
                            continue;
                        }
                        match MachO::parse(data, offset) {
                            Ok(bin) => {
                                let (secs, warns) = parse_one(&bin);
                                for mut sec in secs {
                                    sec.id = format!("arch{i}-{}", sec.id);
                                    sec.label = format!("Arch[{i}] {}", sec.label);
                                    sections.push(sec);
                                }
                                warnings.extend(warns);
                            }
                            Err(e) => warnings.push(format!("Mach-O fat arch[{i}] parse: {e}")),
                        }
                    }
                    Err(e) => warnings.push(format!("Mach-O fat arch[{i}] header: {e}")),
                }
            }
        }
        Err(e) => {
            warnings.push(format!("Mach-O parse failed: {e}"));
        }
    }

    (sections, warnings)
}

fn parse_one(bin: &MachO<'_>) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let warnings = Vec::new();

    sections.push(header_section(bin));
    sections.push(segments_section(bin));
    if let Some(meta) = load_cmd_meta(bin) {
        sections.push(meta);
    }

    (sections, warnings)
}

fn header_section(bin: &MachO<'_>) -> Section {
    let mut s = Section::new("macho-header", "Mach-O header");
    let ns = "MachO";
    s.add("Is64", bin.is_64.to_string(), Some(ns));
    s.add(
        "Endian",
        if bin.little_endian {
            "little"
        } else {
            "big"
        },
        Some(ns),
    );
    let cpu = goblin::mach::cputype::get_arch_name_from_types(
        bin.header.cputype(),
        bin.header.cpusubtype(),
    )
    .unwrap_or("unknown");
    s.add("Cpu", cpu, Some(ns));
    s.add(
        "FileType",
        goblin::mach::header::filetype_to_str(bin.header.filetype),
        Some(ns),
    );
    s.add("Ncmds", bin.header.ncmds.to_string(), Some(ns));
    s.add("Flags", format!("0x{:X}", bin.header.flags), Some(ns));
    if let Some(name) = bin.name {
        if !name.is_empty() {
            s.add("Name", name.to_string(), Some(ns));
        }
    }
    if !bin.libs.is_empty() {
        let libs: Vec<&str> = bin.libs.iter().copied().take(32).collect();
        let mut v = libs.join(", ");
        if bin.libs.len() > 32 {
            v.push_str(&format!(" (+{} more)", bin.libs.len() - 32));
        }
        s.add("LinkedDylibs", v, Some(ns));
    }
    s
}

fn segments_section(bin: &MachO<'_>) -> Section {
    let mut s = Section::new("macho-segments", "Mach-O segments");
    let ns = "MachO:Segment";
    s.add("SegmentCount", bin.segments.len().to_string(), Some(ns));
    for seg in bin.segments.iter() {
        let name = seg.name().unwrap_or("").to_string();
        s.fields.push(
            Field::new(
                if name.is_empty() {
                    "Segment".into()
                } else {
                    name.clone()
                },
                format!(
                    "vmaddr=0x{:X} vmsize={} fileoff=0x{:X} filesize={} nsects={}",
                    seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize, seg.nsects
                ),
            )
            .with_namespace(ns)
            .with_span(seg.fileoff, seg.filesize)
            .with_raw(serde_json::json!({ "name": name })),
        );
        if let Ok(sects) = seg.sections() {
            for (sect, _) in sects {
                let sn = sect.name().unwrap_or("");
                let segn = sect.segname().unwrap_or("");
                s.fields.push(
                    Field::new(
                        format!("{segn},{sn}"),
                        format!(
                            "addr=0x{:X} size={} offset=0x{:X}",
                            sect.addr, sect.size, sect.offset
                        ),
                    )
                    .with_namespace("MachO:Section")
                    .with_span(sect.offset as u64, sect.size),
                );
            }
        }
    }
    s
}

fn load_cmd_meta(bin: &MachO<'_>) -> Option<Section> {
    let mut s = Section::new("macho-meta", "Mach-O identity / build");
    let ns = "MachO:Meta";
    let mut any = false;

    for lc in &bin.load_commands {
        match &lc.command {
            CommandVariant::Uuid(u) => {
                any = true;
                s.add("Uuid", format_uuid(&u.uuid), Some(ns));
            }
            CommandVariant::BuildVersion(bv) => {
                any = true;
                s.add("Platform", platform_name(bv.platform), Some(ns));
                s.add("Minos", format_version(bv.minos), Some(ns));
                s.add("Sdk", format_version(bv.sdk), Some(ns));
                if bv.ntools > 0 {
                    s.add("BuildToolCount", bv.ntools.to_string(), Some(ns));
                }
            }
            CommandVariant::VersionMinMacosx(v) => {
                any = true;
                s.add("VersionMinMacosx", format_version(v.version), Some(ns));
                s.add("SdkMacosx", format_version(v.sdk), Some(ns));
            }
            CommandVariant::VersionMinIphoneos(v) => {
                any = true;
                s.add("VersionMinIphoneos", format_version(v.version), Some(ns));
                s.add("SdkIphoneos", format_version(v.sdk), Some(ns));
            }
            CommandVariant::SourceVersion(v) => {
                any = true;
                s.add("SourceVersion", format!("0x{:X}", v.version), Some(ns));
            }
            _ => {}
        }
    }

    if any {
        Some(s)
    } else {
        None
    }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn format_version(v: u32) -> String {
    let major = (v >> 16) & 0xFFFF;
    let minor = (v >> 8) & 0xFF;
    let patch = v & 0xFF;
    format!("{major}.{minor}.{patch}")
}

fn platform_name(p: u32) -> &'static str {
    match p {
        PLATFORM_MACOS => "macOS",
        PLATFORM_IOS => "iOS",
        PLATFORM_TVOS => "tvOS",
        PLATFORM_WATCHOS => "watchOS",
        PLATFORM_BRIDGEOS => "bridgeOS",
        PLATFORM_MACCATALYST => "Mac Catalyst",
        PLATFORM_IOSSIMULATOR => "iOS Simulator",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze_buffer;
    use crate::types::AnalyzeOptions;

    /// Minimal little-endian 64-bit Mach-O with LC_UUID + one segment.
    pub fn minimal_macho_fixture() -> Vec<u8> {
        let mut buf = vec![0u8; 0x200];
        // mach_header_64
        write_u32(&mut buf, 0, 0xFEEDFACF); // MH_MAGIC_64
        write_u32(&mut buf, 4, 0x01000007); // CPU_TYPE_X86_64
        write_u32(&mut buf, 8, 0x80000003); // CPU_SUBTYPE_LIB64 | X86_ALL
        write_u32(&mut buf, 12, 6); // MH_DYLIB
        write_u32(&mut buf, 16, 2); // ncmds
        write_u32(&mut buf, 20, 72 + 24); // sizeofcmds (segment + uuid)
        write_u32(&mut buf, 24, 0); // flags
        write_u32(&mut buf, 28, 0); // reserved

        // LC_SEGMENT_64 at 32
        write_u32(&mut buf, 32, 0x19); // LC_SEGMENT_64
        write_u32(&mut buf, 36, 72); // cmdsize
        buf[40..46].copy_from_slice(b"__TEXT");
        write_u64(&mut buf, 56, 0); // vmaddr
        write_u64(&mut buf, 64, 0x1000); // vmsize
        write_u64(&mut buf, 72, 0); // fileoff
        write_u64(&mut buf, 80, 0x100); // filesize
        write_u32(&mut buf, 88, 5); // maxprot
        write_u32(&mut buf, 92, 5); // initprot
        write_u32(&mut buf, 96, 0); // nsects
        write_u32(&mut buf, 100, 0); // flags

        // LC_UUID at 104
        write_u32(&mut buf, 104, 0x1B); // LC_UUID
        write_u32(&mut buf, 108, 24); // cmdsize
        let uuid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        buf[112..128].copy_from_slice(&uuid);

        buf
    }

    fn write_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn write_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn minimal_macho_exposes_uuid() {
        let bin = minimal_macho_fixture();
        let (secs, warns) = parse_macho(&bin);
        assert!(
            !warns.iter().any(|w| w.contains("parse failed")),
            "{warns:?}"
        );
        assert!(secs.iter().any(|s| s.id == "macho-header"));
        let meta = secs.iter().find(|s| s.id == "macho-meta").expect("meta");
        assert!(
            meta.fields
                .iter()
                .any(|f| f.key == "Uuid" && f.value.starts_with("11223344")),
            "{:?}",
            meta.fields
        );
    }

    #[test]
    fn analyze_dispatches_macho() {
        let bin = minimal_macho_fixture();
        let a = analyze_buffer(&bin, AnalyzeOptions::from_filename("lib.dylib"));
        assert!(
            a.sections.iter().any(|s| s.id.starts_with("macho-")),
            "mime={} {:?}",
            a.mime,
            a.sections.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }
}

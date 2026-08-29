//! PE (Portable Executable) metadata: VS_VERSIONINFO, Rich Header, sections, IAT, Authenticode.

use crate::types::{Field, Section};
use goblin::pe::certificate_table::AttributeCertificateType;
use goblin::pe::header::{self, RichHeader};
use goblin::pe::resource::VersionInfo;
use goblin::pe::PE;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::collections::BTreeMap;

pub fn parse_pe(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();

    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(e) => {
            warnings.push(format!("PE parse failed: {e}"));
            return (sections, warnings);
        }
    };

    sections.push(header_section(&pe));
    if let Some(rich) = pe.header.rich_header {
        sections.push(rich_section(&rich));
    }
    sections.push(sections_section(&pe, &mut warnings));
    if !pe.libraries.is_empty() || !pe.imports.is_empty() {
        sections.push(imports_section(&pe));
    }
    if let Some(ref res) = pe.resource_data {
        if let Some(ref ver) = res.version_info {
            sections.push(version_section(ver));
        }
    }
    if !pe.certificates.is_empty() {
        let (sec, warns) = authenticode_section(&pe.certificates);
        sections.push(sec);
        warnings.extend(warns);
    }

    (sections, warnings)
}

fn header_section(pe: &PE<'_>) -> Section {
    let mut s = Section::new("pe-header", "PE header");
    let ns = "PE";
    s.add(
        "Machine",
        header::machine_to_str(pe.header.coff_header.machine).to_string(),
        Some(ns),
    );
    s.add(
        "MachineId",
        format!("0x{:04X}", pe.header.coff_header.machine),
        Some(ns),
    );
    s.add("IsDll", pe.is_lib.to_string(), Some(ns));
    s.add("Is64", pe.is_64.to_string(), Some(ns));
    s.add("ImageBase", format!("0x{:X}", pe.image_base), Some(ns));
    s.add("EntryPointRva", format!("0x{:X}", pe.entry), Some(ns));
    s.add("NumberOfSections", pe.sections.len().to_string(), Some(ns));
    s.add(
        "TimeDateStamp",
        format!("0x{:08X}", pe.header.coff_header.time_date_stamp),
        Some(ns),
    );
    if let Some(name) = pe.name {
        s.add("ExportName", name.to_string(), Some(ns));
    }
    if let Some(opt) = pe.header.optional_header {
        s.add(
            "Subsystem",
            subsystem_name(opt.windows_fields.subsystem).to_string(),
            Some(ns),
        );
        s.add(
            "SizeOfImage",
            opt.windows_fields.size_of_image.to_string(),
            Some(ns),
        );
        s.add(
            "Checksum",
            format!("0x{:08X}", opt.windows_fields.check_sum),
            Some(ns),
        );
        s.add(
            "DllCharacteristics",
            format!("0x{:04X}", opt.windows_fields.dll_characteristics),
            Some(ns),
        );
    }
    s
}

fn rich_section(rich: &RichHeader<'_>) -> Section {
    let mut s = Section::new("pe-rich", "PE Rich Header");
    let ns = "PE:Rich";
    let span_len = rich.end_offset.saturating_sub(rich.start_offset) as u64;
    s.fields.push(
        Field::new("XorKey", format!("0x{:08X}", rich.key))
            .with_namespace(ns)
            .with_span(rich.start_offset as u64, span_len),
    );
    s.add(
        "Offset",
        format!("0x{:X}-0x{:X}", rich.start_offset, rich.end_offset),
        Some(ns),
    );

    let mut i = 0usize;
    for meta in rich.metadatas() {
        match meta {
            Ok(m) => {
                let tool = rich_product_name(m.product);
                s.fields.push(
                    Field::new(
                        format!("Tool[{i}]"),
                        format!(
                            "{tool} (product=0x{:04X} build={} count={})",
                            m.product, m.build, m.use_count
                        ),
                    )
                    .with_namespace(ns)
                    .with_raw(serde_json::json!({
                        "product": m.product,
                        "build": m.build,
                        "use_count": m.use_count,
                        "tool": tool,
                    })),
                );
                i += 1;
            }
            Err(_) => break,
        }
    }
    s.add("ToolCount", i.to_string(), Some(ns));
    s
}

fn sections_section(pe: &PE<'_>, warnings: &mut Vec<String>) -> Section {
    let mut s = Section::new("pe-sections", "PE sections");
    let ns = "PE:Section";
    let mut packer_hints = Vec::new();
    for sec in &pe.sections {
        let name = sec.name().unwrap_or("").trim_end_matches('\0').to_string();
        let virt = sec.virtual_size;
        let raw = sec.size_of_raw_data;
        let hint = section_packer_hint(&name, virt, raw);
        if let Some(h) = hint {
            packer_hints.push(format!("{name}: {h}"));
        }
        s.fields.push(
            Field::new(
                if name.is_empty() {
                    format!("Section@{:X}", sec.pointer_to_raw_data)
                } else {
                    name.clone()
                },
                format!(
                    "virt={virt} raw={raw} rva=0x{:X} chars=0x{:08X}",
                    sec.virtual_address, sec.characteristics
                ),
            )
            .with_namespace(ns)
            .with_span(sec.pointer_to_raw_data as u64, raw as u64)
            .with_raw(serde_json::json!({
                "name": name,
                "virtual_size": virt,
                "raw_size": raw,
                "virtual_address": sec.virtual_address,
                "characteristics": sec.characteristics,
            })),
        );
    }
    if !packer_hints.is_empty() {
        s.add("PackerHints", packer_hints.join("; "), Some(ns));
        warnings.push(format!(
            "PE section size anomalies (possible packer): {}",
            packer_hints.join("; ")
        ));
    }
    s
}

fn section_packer_hint(name: &str, virt: u32, raw: u32) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "upx0" | "upx1" | "upx2" | ".upx" | "aspack" | ".aspack" | "themida" | ".themida"
    ) {
        return Some("known packer section name");
    }
    if virt > 0 && raw > 0 && virt > raw.saturating_mul(3) {
        return Some("virtual_size >> raw_size");
    }
    if raw == 0 && virt > 0x1000 {
        return Some("empty raw, large virtual");
    }
    None
}

fn imports_section(pe: &PE<'_>) -> Section {
    let mut s = Section::new("pe-imports", "PE import table (IAT)");
    let ns = "PE:Import";
    s.add("LibraryCount", pe.libraries.len().to_string(), Some(ns));
    s.add("ImportCount", pe.imports.len().to_string(), Some(ns));

    let mut by_dll: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for imp in &pe.imports {
        by_dll
            .entry(imp.dll)
            .or_default()
            .push(imp.name.as_ref().to_string());
    }
    const MAX_DLLS: usize = 40;
    const MAX_APIS_PER_DLL: usize = 24;
    for (i, (dll, apis)) in by_dll.iter().enumerate() {
        if i >= MAX_DLLS {
            s.add(
                "LibrariesTruncated",
                format!("{} more DLLs omitted", by_dll.len() - MAX_DLLS),
                Some(ns),
            );
            break;
        }
        let shown: Vec<&str> = apis
            .iter()
            .take(MAX_APIS_PER_DLL)
            .map(|a| a.as_str())
            .collect();
        let mut value = shown.join(", ");
        if apis.len() > MAX_APIS_PER_DLL {
            value.push_str(&format!(" (+{} more)", apis.len() - MAX_APIS_PER_DLL));
        }
        s.fields.push(
            Field::new(format!("Dll:{dll}"), value)
                .with_namespace(ns)
                .with_raw(serde_json::json!({
                    "dll": dll,
                    "api_count": apis.len(),
                })),
        );
    }
    s
}

fn version_section(ver: &VersionInfo<'_>) -> Section {
    let mut s = Section::new("pe-version", "PE VS_VERSIONINFO");
    let ns = "PE:Version";
    let info = &ver.string_info;
    push_opt(&mut s, "CompanyName", info.company_name(), ns);
    push_opt(&mut s, "FileDescription", info.file_description(), ns);
    push_opt(&mut s, "FileVersion", info.file_version(), ns);
    push_opt(&mut s, "InternalName", info.internal_name(), ns);
    push_opt(&mut s, "LegalCopyright", info.legal_copyright(), ns);
    push_opt(&mut s, "LegalTrademarks", info.legal_trademarks(), ns);
    push_opt(&mut s, "OriginalFilename", info.original_filename(), ns);
    push_opt(&mut s, "ProductName", info.product_name(), ns);
    push_opt(&mut s, "ProductVersion", info.product_version(), ns);
    push_opt(&mut s, "Comments", info.comments(), ns);
    push_opt(&mut s, "PrivateBuild", info.private_build(), ns);
    push_opt(&mut s, "SpecialBuild", info.special_build(), ns);

    if let Some(fi) = &ver.fixed_info {
        use goblin::pe::resource::VersionField;
        s.add(
            "FileVersionFixed",
            VersionField::from_ms_ls(fi.file_version_ms, fi.file_version_ls).to_string(),
            Some(ns),
        );
        s.add(
            "ProductVersionFixed",
            VersionField::from_ms_ls(fi.product_version_ms, fi.product_version_ls).to_string(),
            Some(ns),
        );
    }
    s
}

fn subsystem_name(id: u16) -> &'static str {
    match id {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => "OTHER",
    }
}

fn push_opt(sec: &mut Section, key: &str, value: Option<String>, ns: &str) {
    if let Some(v) = value {
        let v = v.trim();
        if !v.is_empty() {
            sec.add(key, v.to_string(), Some(ns));
        }
    }
}

fn authenticode_section(
    certs: &[goblin::pe::certificate_table::AttributeCertificate<'_>],
) -> (Section, Vec<String>) {
    let mut s = Section::new("pe-authenticode", "PE Authenticode certificates");
    let mut warnings = Vec::new();
    let ns = "PE:Authenticode";
    s.add("CertificateCount", certs.len().to_string(), Some(ns));
    warnings.push(
        "Authenticode: listing certificate blobs only; chain validation / trust is not performed"
            .into(),
    );

    for (i, cert) in certs.iter().enumerate() {
        let ctype = match cert.certificate_type {
            AttributeCertificateType::X509 => "X509",
            AttributeCertificateType::PkcsSignedData => "PKCS#7 SignedData",
            AttributeCertificateType::Reserved1 => "Reserved",
            AttributeCertificateType::TsStackSigned => "TS_STACK_SIGNED",
        };
        s.add(format!("Cert[{i}].Type"), ctype.to_string(), Some(ns));
        s.add(
            format!("Cert[{i}].Length"),
            cert.certificate.len().to_string(),
            Some(ns),
        );
        s.add(
            format!("Cert[{i}].Revision"),
            format!("{:?}", cert.revision),
            Some(ns),
        );

        let sha1 = hex::encode(Sha1::digest(cert.certificate));
        let sha256 = hex::encode(Sha256::digest(cert.certificate));
        s.add(format!("Cert[{i}].BlobSha1"), sha1, Some(ns));
        s.add(format!("Cert[{i}].BlobSha256"), sha256, Some(ns));

        if let Some(cn) = extract_best_effort_cn(cert.certificate) {
            s.add(format!("Cert[{i}].SubjectCN"), cn, Some(ns));
        }
        if let Some(tp) = extract_leaf_cert_sha1(cert.certificate) {
            s.add(format!("Cert[{i}].ThumbprintSha1"), tp, Some(ns));
        }
    }
    (s, warnings)
}

/// Best-effort Common Name from PKCS#7 / X.509 DER (OID 2.5.4.3).
fn extract_best_effort_cn(der: &[u8]) -> Option<String> {
    // OID 2.5.4.3 encoded as 06 03 55 04 03
    const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let mut last = None;
    let mut i = 0;
    while i + OID_CN.len() < der.len() {
        if &der[i..i + OID_CN.len()] == OID_CN {
            let after = i + OID_CN.len();
            if let Some(s) = read_asn1_string(&der[after..]) {
                last = Some(s);
            }
        }
        i += 1;
    }
    last
}

fn read_asn1_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let tag = bytes[0];
    // PrintableString(0x13), Teletex(0x14), IA5(0x16), UTF8(0x0C), BMP(0x1E)
    if !matches!(tag, 0x0C | 0x13 | 0x14 | 0x16 | 0x1E) {
        return None;
    }
    let (len, hdr) = read_asn1_len(&bytes[1..])?;
    let start = 1 + hdr;
    if start + len > bytes.len() || len == 0 || len > 256 {
        return None;
    }
    let raw = &bytes[start..start + len];
    let s = if tag == 0x1E {
        let u16s: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn read_asn1_len(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let b0 = bytes[0];
    if b0 & 0x80 == 0 {
        return Some((b0 as usize, 1));
    }
    let n = (b0 & 0x7F) as usize;
    if n == 0 || n > 2 || bytes.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Some((len, 1 + n))
}

/// Find outermost-looking X.509 cert SEQUENCEs and SHA-1 the last one (often leaf in PKCS#7).
fn extract_leaf_cert_sha1(pkcs7: &[u8]) -> Option<String> {
    // Heuristic: collect DER SEQUENCEs that contain OID rsaEncryption or ecPublicKey and are > 256 bytes.
    const RSA_OID: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];
    let mut candidates = Vec::new();
    let mut i = 0;
    while i + 4 < pkcs7.len() {
        if pkcs7[i] == 0x30 {
            if let Some((len, hdr)) = read_asn1_len(&pkcs7[i + 1..]) {
                let total = 1 + hdr + len;
                if total >= 256 && i + total <= pkcs7.len() {
                    let slice = &pkcs7[i..i + total];
                    if slice.windows(RSA_OID.len()).any(|w| w == RSA_OID)
                        || slice
                            .windows(7)
                            .any(|w| w == [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D])
                    {
                        candidates.push(slice);
                    }
                    i += 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    candidates.last().map(|c| hex::encode(Sha1::digest(c)))
}

/// Subset of Rich Header product IDs (CompID prod field) → human label.
fn rich_product_name(product: u16) -> &'static str {
    match product {
        0x0000 => "Imported objects (old)",
        0x0001 => "Imported objects",
        0x0002 => "Linker 5.10",
        0x0004 => "CVTRES 5.00",
        0x0006 => "VB 5.0 / 6.0",
        0x000A => "Linker 5.20",
        0x000E => "CVTRES 6.00",
        0x0015 => "CVTRES 7.00",
        0x0019 => "Linker 6.00",
        0x005A => "Utc1500_C",
        0x005C => "Utc1500_CPP",
        0x005E => "AliasObj 6.00",
        0x0064 => "Utc1500_LTCG_C",
        0x0065 => "Linker 7.00",
        0x0066 => "CVTRES 7.10",
        0x006B => "Utc1500_LTCG_CPP",
        0x006C => "Utc1500_POGO_I_C",
        0x006D => "Utc1500_POGO_I_CPP",
        0x006E => "Utc1500_POGO_O_C",
        0x006F => "Utc1500_POGO_O_CPP",
        0x0078 => "Linker 7.10",
        0x007A => "Cvtpgd 7.10",
        0x007C => "Utc1600_C",
        0x007D => "Utc1600_CPP",
        0x007E => "Utc1600_LTCG_C",
        0x007F => "Utc1600_LTCG_CPP",
        0x0080 => "Utc1600_POGO_I_C",
        0x0081 => "Utc1600_POGO_I_CPP",
        0x0082 => "Utc1600_POGO_O_C",
        0x0083 => "Utc1600_POGO_O_CPP",
        0x008D => "Linker 8.00",
        0x008F => "CVTRES 8.00",
        0x0090 => "Masm 8.00",
        0x0091 => "Utc1700_C",
        0x0092 => "Utc1700_CPP",
        0x0095 => "Utc1700_LTCG_C",
        0x0096 => "Utc1700_LTCG_CPP",
        0x009D => "Linker 9.00",
        0x009F => "CVTRES 9.00",
        0x00AA => "Utc1800_C",
        0x00AB => "Utc1800_CPP",
        0x00AC => "Utc1800_LTCG_C",
        0x00AD => "Utc1800_LTCG_CPP",
        0x00B7 => "Linker 10.00",
        0x00B9 => "CVTRES 10.00",
        0x00C8 => "Utc1900_C",
        0x00C9 => "Utc1900_CPP",
        0x00CA => "Utc1900_LTCG_C",
        0x00CB => "Utc1900_LTCG_CPP",
        0x00D3 => "Linker 11.00",
        0x00D5 => "CVTRES 11.00",
        0x00DE => "Utc1900_C (VS2013)",
        0x00DF => "Utc1900_CPP (VS2013)",
        0x00E0 => "Utc1900_LTCG_C (VS2013)",
        0x00E1 => "Utc1900_LTCG_CPP (VS2013)",
        0x00EB => "Linker 12.00",
        0x00ED => "CVTRES 12.00",
        0x00F6 => "Utc1900_C (VS2015+)",
        0x00F7 => "Utc1900_CPP (VS2015+)",
        0x00F8 => "Utc1900_LTCG_C (VS2015+)",
        0x00F9 => "Utc1900_LTCG_CPP (VS2015+)",
        0x0103 => "Linker 14.00",
        0x0105 => "CVTRES 14.00",
        0x010E => "Utc1900_C (VS2017+)",
        0x010F => "Utc1900_CPP (VS2017+)",
        0x011A => "Linker 14.10+",
        _ => "Unknown tool",
    }
}

/// Synthetic PE32 used by tests and `fixtures/minimal.exe`.
pub fn minimal_pe_fixture() -> Vec<u8> {
    let mut buf = vec![0u8; 0x600];

    // DOS header
    buf[0] = b'M';
    buf[1] = b'Z';
    // e_lfanew → PE at 0x80
    buf[0x3C] = 0x80;

    // Rich header between DOS stub and PE (offsets 0x40..0x80)
    let key: u32 = 0x12345678;
    let dans = 0x536E6144u32 ^ key; // "DanS"
    write_u32(&mut buf, 0x40, dans);
    write_u32(&mut buf, 0x44, key); // pad
    write_u32(&mut buf, 0x48, key);
    write_u32(&mut buf, 0x4C, key);
    // metadata: product=0x009D (Linker 9.00), build=30729, count=1
    let prod_build = ((0x009Du32) << 16) | 30729;
    write_u32(&mut buf, 0x50, prod_build ^ key);
    write_u32(&mut buf, 0x54, 1u32 ^ key);
    // metadata: product=0x009F (CVTRES 9.00), build=30729, count=1
    let prod_build2 = ((0x009Fu32) << 16) | 30729;
    write_u32(&mut buf, 0x58, prod_build2 ^ key);
    write_u32(&mut buf, 0x5C, 1u32 ^ key);
    write_u32(&mut buf, 0x60, 0x68636952); // "Rich"
    write_u32(&mut buf, 0x64, key);

    // PE signature at 0x80
    buf[0x80] = b'P';
    buf[0x81] = b'E';
    // COFF
    write_u16(&mut buf, 0x84, 0x014C); // i386
    write_u16(&mut buf, 0x86, 1); // 1 section
    write_u32(&mut buf, 0x88, 0x5F000000); // timestamp
    write_u16(&mut buf, 0x94, 0xE0); // optional header size
    write_u16(&mut buf, 0x96, 0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE

    // Optional header PE32
    let opt = 0x98usize;
    write_u16(&mut buf, opt, 0x10B); // PE32 magic
    buf[opt + 2] = 14; // major linker
    buf[opt + 3] = 0;
    write_u32(&mut buf, opt + 16, 0x1000); // entry point
    write_u32(&mut buf, opt + 28, 0x00400000); // image base
    write_u32(&mut buf, opt + 32, 0x1000); // section align
    write_u32(&mut buf, opt + 36, 0x200); // file align
    write_u16(&mut buf, opt + 40, 6); // major OS
    write_u16(&mut buf, opt + 44, 4); // major image
    write_u32(&mut buf, opt + 56, 0x2000); // size of image
    write_u32(&mut buf, opt + 60, 0x200); // size of headers
    write_u16(&mut buf, opt + 68, 3); // subsystem CONSOLE
    write_u32(&mut buf, opt + 92, 16); // number of RVA/sizes

    // Data directories: import table at index 1
    let dd = opt + 96;
    write_u32(&mut buf, dd + 8, 0x1020);
    write_u32(&mut buf, dd + 12, 40);

    // Section header after optional (0x98 + 0xE0 = 0x178)
    let sh = 0x178usize;
    buf[sh..sh + 5].copy_from_slice(b".text");
    write_u32(&mut buf, sh + 8, 0x200); // virtual size
    write_u32(&mut buf, sh + 12, 0x1000); // VA
    write_u32(&mut buf, sh + 16, 0x200); // raw size
    write_u32(&mut buf, sh + 20, 0x200); // raw ptr
    write_u32(&mut buf, sh + 36, 0x60000020); // CODE | EXECUTE | READ

    let idt = 0x220usize;
    write_u32(&mut buf, idt, 0x1040);
    write_u32(&mut buf, idt + 12, 0x1060);
    write_u32(&mut buf, idt + 16, 0x1050);

    write_u32(&mut buf, 0x240, 0x1070);
    write_u32(&mut buf, 0x250, 0x1070);
    let dll = b"kernel32.dll\0";
    buf[0x260..0x260 + dll.len()].copy_from_slice(dll);
    write_u16(&mut buf, 0x270, 0);
    let api = b"GetProcAddress\0";
    buf[0x272..0x272 + api.len()].copy_from_slice(api);

    buf
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze_buffer;
    use crate::types::AnalyzeOptions;

    #[test]
    fn minimal_pe_exposes_rich_sections_imports() {
        let pe = minimal_pe_fixture();
        let (secs, warns) = parse_pe(&pe);
        assert!(
            warns.iter().all(|w| !w.contains("parse failed")),
            "warns={warns:?}"
        );
        let ids: Vec<_> = secs.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"pe-header"), "{ids:?}");
        assert!(ids.contains(&"pe-rich"), "{ids:?}");
        assert!(ids.contains(&"pe-sections"), "{ids:?}");
        assert!(ids.contains(&"pe-imports"), "{ids:?}");

        let rich = secs.iter().find(|s| s.id == "pe-rich").unwrap();
        assert!(
            rich.fields.iter().any(|f| f.value.contains("Linker 9.00")),
            "{:?}",
            rich.fields
        );

        let imports = secs.iter().find(|s| s.id == "pe-imports").unwrap();
        assert!(
            imports
                .fields
                .iter()
                .any(|f| f.key.contains("kernel32") || f.value.contains("GetProcAddress")),
            "{:?}",
            imports.fields
        );
    }

    #[test]
    fn analyze_dispatches_pe_by_magic() {
        let pe = minimal_pe_fixture();
        let a = analyze_buffer(&pe, AnalyzeOptions::from_filename("tool.exe"));
        assert!(
            a.mime.contains("dosexec")
                || a.mime.contains("exe")
                || a.mime.contains("x-msdownload")
                || a.mime == "application/vnd.microsoft.portable-executable"
                || a.sections.iter().any(|s| s.id.starts_with("pe-")),
            "mime={} sections={:?}",
            a.mime,
            a.sections.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
        assert!(a
            .sections
            .iter()
            .any(|s| s.id == "pe-header" || s.id == "pe-rich"));
    }

    #[test]
    fn asn1_cn_extraction() {
        let mut der = Vec::new();
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        der.push(0x0C);
        der.push(11);
        der.extend_from_slice(b"MetaDissect");
        assert_eq!(extract_best_effort_cn(&der).as_deref(), Some("MetaDissect"));
    }

    #[test]
    fn rich_product_known() {
        assert_eq!(rich_product_name(0x009D), "Linker 9.00");
        assert_eq!(rich_product_name(0xFFFF), "Unknown tool");
    }
}

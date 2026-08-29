use crate::types::{Field, Section};

const TYPE_BYTE: u16 = 1;
const TYPE_ASCII: u16 = 2;
const TYPE_SHORT: u16 = 3;
const TYPE_LONG: u16 = 4;
const TYPE_RATIONAL: u16 = 5;
const TYPE_SBYTE: u16 = 6;
const TYPE_UNDEFINED: u16 = 7;
const TYPE_SSHORT: u16 = 8;
const TYPE_SLONG: u16 = 9;
const TYPE_SRATIONAL: u16 = 10;
const TYPE_FLOAT: u16 = 11;
const TYPE_DOUBLE: u16 = 12;

const TAG_EXIF_IFD: u16 = 0x8769;
const TAG_GPS_IFD: u16 = 0x8825;
const TAG_INTEROP_IFD: u16 = 0xA005;
const TAG_SUB_IFD: u16 = 0x014A;
const TAG_MAKER_NOTE: u16 = 0x927C;

#[derive(Clone, Copy)]
struct Endian(bool);

impl Endian {
    fn u16(self, b: &[u8]) -> Option<u16> {
        let a: [u8; 2] = b.get(..2)?.try_into().ok()?;
        Some(if self.0 {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }

    fn u32(self, b: &[u8]) -> Option<u32> {
        let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
        Some(if self.0 {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn i32(self, b: &[u8]) -> Option<i32> {
        let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
        Some(if self.0 {
            i32::from_le_bytes(a)
        } else {
            i32::from_be_bytes(a)
        })
    }
}

pub struct ParsedTiff {
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
}

pub fn parse_tiff(data: &[u8], base_offset: u64) -> ParsedTiff {
    let mut out = ParsedTiff {
        sections: Vec::new(),
        warnings: Vec::new(),
    };
    if data.len() < 8 {
        out.warnings.push("TIFF header too short".into());
        return out;
    }
    let le = match &data[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => {
            out.warnings
                .push("Not a TIFF header (missing II/MM)".into());
            return out;
        }
    };
    let en = Endian(le);
    let magic = en.u16(&data[2..4]).unwrap_or(0);
    if magic != 42 {
        out.warnings
            .push(format!("Unexpected TIFF magic {magic} (expected 42)"));
    }
    let ifd0 = en.u32(&data[4..8]).unwrap_or(0) as usize;
    walk_ifd(
        data,
        en,
        ifd0,
        base_offset,
        "EXIF:IFD0",
        "EXIF IFD0",
        0,
        &mut out,
        &mut Vec::new(),
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn walk_ifd(
    data: &[u8],
    en: Endian,
    offset: usize,
    base_offset: u64,
    ns: &str,
    label: &str,
    depth: u8,
    out: &mut ParsedTiff,
    seen: &mut Vec<usize>,
) {
    if depth > 6 || seen.contains(&offset) {
        return;
    }
    seen.push(offset);
    if offset + 2 > data.len() {
        out.warnings
            .push(format!("IFD offset {offset} out of range in {ns}"));
        return;
    }
    let count = match en.u16(&data[offset..]) {
        Some(c) => c as usize,
        None => return,
    };
    let mut section = Section::new(ns.to_ascii_lowercase().replace(':', "-"), label);
    let mut child_ifds: Vec<(u16, usize)> = Vec::new();
    let entries_start = offset + 2;

    for i in 0..count {
        let eoff = entries_start + i * 12;
        if eoff + 12 > data.len() {
            break;
        }
        let entry = &data[eoff..eoff + 12];
        let tag = en.u16(&entry[0..2]).unwrap_or(0);
        let typ = en.u16(&entry[2..4]).unwrap_or(0);
        let cnt = en.u32(&entry[4..8]).unwrap_or(0);
        let inline = &entry[8..12];
        let unit = type_size(typ);
        let nbytes = unit.saturating_mul(cnt as usize);
        let (val_off, val_bytes) = if nbytes <= 4 {
            (eoff + 8, &inline[..nbytes.min(4)])
        } else {
            let ptr = en.u32(inline).unwrap_or(0) as usize;
            if ptr >= data.len() {
                section.fields.push(
                    Field::new(tag_name(tag, ns), format!("<offset {ptr} out of range>"))
                        .with_namespace(ns)
                        .with_span(base_offset + eoff as u64, 12),
                );
                continue;
            }
            let end = (ptr + nbytes).min(data.len());
            (ptr, &data[ptr..end])
        };

        if matches!(
            tag,
            TAG_EXIF_IFD | TAG_GPS_IFD | TAG_INTEROP_IFD | TAG_SUB_IFD
        ) {
            if let Some(ptr) = pointer_value(en, typ, inline, val_bytes) {
                child_ifds.push((tag, ptr));
            }
        }

        let display = format_value(tag, typ, cnt, val_bytes, en);
        let raw = serde_json::json!({
            "tag": tag,
            "type": typ,
            "count": cnt,
            "value_offset": val_off,
        });
        section.fields.push(
            Field::new(tag_name(tag, ns), display)
                .with_namespace(ns)
                .with_raw(raw)
                .with_span(base_offset + eoff as u64, 12),
        );
    }

    let next_off_pos = entries_start + count * 12;
    if !section.is_empty() {
        out.sections.push(section);
    }

    for (tag, ptr) in child_ifds {
        let (cns, clabel) = match tag {
            TAG_EXIF_IFD => ("EXIF:ExifIFD", "EXIF ExifIFD"),
            TAG_GPS_IFD => ("EXIF:GPS", "EXIF GPS"),
            TAG_INTEROP_IFD => ("EXIF:Interop", "EXIF Interoperability"),
            TAG_SUB_IFD => ("EXIF:SubIFD", "EXIF SubIFD / Thumbnail"),
            _ => ("EXIF:IFD", "EXIF IFD"),
        };
        walk_ifd(
            data,
            en,
            ptr,
            base_offset,
            cns,
            clabel,
            depth + 1,
            out,
            seen,
        );
    }

    if next_off_pos + 4 <= data.len() {
        if let Some(next) = en.u32(&data[next_off_pos..]) {
            if next != 0 {
                walk_ifd(
                    data,
                    en,
                    next as usize,
                    base_offset,
                    "EXIF:IFD1",
                    "EXIF IFD1 (thumbnail)",
                    depth + 1,
                    out,
                    seen,
                );
            }
        }
    }

    let _ = TAG_MAKER_NOTE;
}

fn pointer_value(en: Endian, typ: u16, inline: &[u8], val_bytes: &[u8]) -> Option<usize> {
    match typ {
        TYPE_LONG | 13 => Some(en.u32(inline)? as usize),
        TYPE_SHORT => Some(en.u16(inline)? as usize),
        _ => {
            if val_bytes.len() >= 4 {
                en.u32(val_bytes).map(|v| v as usize)
            } else {
                None
            }
        }
    }
}

fn type_size(typ: u16) -> usize {
    match typ {
        TYPE_BYTE | TYPE_ASCII | TYPE_SBYTE | TYPE_UNDEFINED => 1,
        TYPE_SHORT | TYPE_SSHORT => 2,
        TYPE_LONG | TYPE_SLONG | TYPE_FLOAT | 13 => 4,
        TYPE_RATIONAL | TYPE_SRATIONAL | TYPE_DOUBLE => 8,
        _ => 1,
    }
}

fn format_value(tag: u16, typ: u16, count: u32, bytes: &[u8], en: Endian) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    match typ {
        TYPE_ASCII => {
            let s = String::from_utf8_lossy(bytes);
            s.trim_end_matches('\0').trim().to_string()
        }
        TYPE_BYTE | TYPE_UNDEFINED | TYPE_SBYTE => {
            if count <= 16 {
                bytes
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                format!(
                    "{} bytes: {}…",
                    count,
                    hex::encode(&bytes[..16.min(bytes.len())])
                )
            }
        }
        TYPE_SHORT => join_nums(count, 2, bytes, |c| en.u16(c).map(|v| v.to_string())),
        TYPE_SSHORT => join_nums(count, 2, bytes, |c| {
            let a: [u8; 2] = c.get(..2)?.try_into().ok()?;
            let v = if en.0 {
                i16::from_le_bytes(a)
            } else {
                i16::from_be_bytes(a)
            };
            Some(v.to_string())
        }),
        TYPE_LONG | 13 => join_nums(count, 4, bytes, |c| en.u32(c).map(|v| v.to_string())),
        TYPE_SLONG => join_nums(count, 4, bytes, |c| en.i32(c).map(|v| v.to_string())),
        TYPE_RATIONAL => format_rationals(count, bytes, en, false, tag),
        TYPE_SRATIONAL => format_rationals(count, bytes, en, true, tag),
        TYPE_FLOAT => join_nums(count, 4, bytes, |c| {
            let a: [u8; 4] = c.get(..4)?.try_into().ok()?;
            let bits = if en.0 {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            };
            Some(f32::from_bits(bits).to_string())
        }),
        TYPE_DOUBLE => join_nums(count, 8, bytes, |c| {
            let a: [u8; 8] = c.get(..8)?.try_into().ok()?;
            let bits = if en.0 {
                u64::from_le_bytes(a)
            } else {
                u64::from_be_bytes(a)
            };
            Some(f64::from_bits(bits).to_string())
        }),
        _ => hex::encode(bytes),
    }
}

fn join_nums(count: u32, size: usize, bytes: &[u8], f: impl Fn(&[u8]) -> Option<String>) -> String {
    let n = (count as usize).min(32);
    let mut parts = Vec::new();
    for i in 0..n {
        let start = i * size;
        if start + size > bytes.len() {
            break;
        }
        if let Some(s) = f(&bytes[start..]) {
            parts.push(s);
        }
    }
    parts.join(" ")
}

fn format_rationals(count: u32, bytes: &[u8], en: Endian, signed: bool, tag: u16) -> String {
    let n = (count as usize).min(8);
    let mut parts = Vec::new();
    for i in 0..n {
        let start = i * 8;
        if start + 8 > bytes.len() {
            break;
        }
        let chunk = &bytes[start..start + 8];
        if signed {
            let num = en.i32(&chunk[0..4]).unwrap_or(0);
            let den = en.i32(&chunk[4..8]).unwrap_or(1);
            if den != 0 {
                parts.push(format!("{} ({}/{})", num as f64 / den as f64, num, den));
            } else {
                parts.push(format!("{num}/{den}"));
            }
        } else {
            let num = en.u32(&chunk[0..4]).unwrap_or(0);
            let den = en.u32(&chunk[4..8]).unwrap_or(1);
            if is_gps_coord_tag(tag) && count == 3 {
                // collect later-style: still print component
                parts.push(if den != 0 {
                    format!("{}", num as f64 / den as f64)
                } else {
                    format!("{num}/{den}")
                });
            } else if den != 0 {
                parts.push(format!("{} ({}/{})", num as f64 / den as f64, num, den));
            } else {
                parts.push(format!("{num}/{den}"));
            }
        }
    }
    if is_gps_coord_tag(tag) && parts.len() == 3 {
        if let (Ok(d), Ok(m), Ok(s)) = (
            parts[0].parse::<f64>(),
            parts[1].parse::<f64>(),
            parts[2].parse::<f64>(),
        ) {
            let dec = d + m / 60.0 + s / 3600.0;
            return format!("{d}° {m}' {s}\" ({dec:.8})");
        }
    }
    parts.join(" ")
}

fn is_gps_coord_tag(tag: u16) -> bool {
    matches!(tag, 0x0002 | 0x0004)
}

pub fn tag_name(tag: u16, ns: &str) -> String {
    if let Some(name) = known_tag(tag, ns) {
        return name.to_string();
    }
    format!("Tag_0x{tag:04X}")
}

fn known_tag(tag: u16, ns: &str) -> Option<&'static str> {
    if ns.contains("GPS") {
        return gps_tag(tag);
    }
    match tag {
        0x00FE => Some("NewSubfileType"),
        0x00FF => Some("SubfileType"),
        0x0100 => Some("ImageWidth"),
        0x0101 => Some("ImageLength"),
        0x0102 => Some("BitsPerSample"),
        0x0103 => Some("Compression"),
        0x0106 => Some("PhotometricInterpretation"),
        0x010E => Some("ImageDescription"),
        0x010F => Some("Make"),
        0x0110 => Some("Model"),
        0x0111 => Some("StripOffsets"),
        0x0112 => Some("Orientation"),
        0x0115 => Some("SamplesPerPixel"),
        0x0116 => Some("RowsPerStrip"),
        0x0117 => Some("StripByteCounts"),
        0x011A => Some("XResolution"),
        0x011B => Some("YResolution"),
        0x011C => Some("PlanarConfiguration"),
        0x0128 => Some("ResolutionUnit"),
        0x012D => Some("TransferFunction"),
        0x0131 => Some("Software"),
        0x0132 => Some("DateTime"),
        0x013B => Some("Artist"),
        0x013E => Some("WhitePoint"),
        0x013F => Some("PrimaryChromaticities"),
        0x014A => Some("SubIFDs"),
        0x015B => Some("JPEGTables"),
        0x0201 => Some("JPEGInterchangeFormat"),
        0x0202 => Some("JPEGInterchangeFormatLength"),
        0x0211 => Some("YCbCrCoefficients"),
        0x0212 => Some("YCbCrSubSampling"),
        0x0213 => Some("YCbCrPositioning"),
        0x0214 => Some("ReferenceBlackWhite"),
        0x02BC => Some("XMLPacket"),
        0x8298 => Some("Copyright"),
        0x829A => Some("ExposureTime"),
        0x829D => Some("FNumber"),
        0x8769 => Some("ExifIFDPointer"),
        0x8822 => Some("ExposureProgram"),
        0x8824 => Some("SpectralSensitivity"),
        0x8825 => Some("GPSInfoIFDPointer"),
        0x8827 => Some("PhotographicSensitivity"),
        0x8828 => Some("OECF"),
        0x8830 => Some("SensitivityType"),
        0x8831 => Some("StandardOutputSensitivity"),
        0x8832 => Some("RecommendedExposureIndex"),
        0x8833 => Some("ISOSpeed"),
        0x9000 => Some("ExifVersion"),
        0x9003 => Some("DateTimeOriginal"),
        0x9004 => Some("DateTimeDigitized"),
        0x9010 => Some("OffsetTime"),
        0x9011 => Some("OffsetTimeOriginal"),
        0x9012 => Some("OffsetTimeDigitized"),
        0x9101 => Some("ComponentsConfiguration"),
        0x9102 => Some("CompressedBitsPerPixel"),
        0x9201 => Some("ShutterSpeedValue"),
        0x9202 => Some("ApertureValue"),
        0x9203 => Some("BrightnessValue"),
        0x9204 => Some("ExposureBiasValue"),
        0x9205 => Some("MaxApertureValue"),
        0x9206 => Some("SubjectDistance"),
        0x9207 => Some("MeteringMode"),
        0x9208 => Some("LightSource"),
        0x9209 => Some("Flash"),
        0x920A => Some("FocalLength"),
        0x9214 => Some("SubjectArea"),
        0x927C => Some("MakerNote"),
        0x9286 => Some("UserComment"),
        0x9290 => Some("SubSecTime"),
        0x9291 => Some("SubSecTimeOriginal"),
        0x9292 => Some("SubSecTimeDigitized"),
        0x9400 => Some("Temperature"),
        0x9401 => Some("Humidity"),
        0x9402 => Some("Pressure"),
        0x9403 => Some("WaterDepth"),
        0xA000 => Some("FlashpixVersion"),
        0xA001 => Some("ColorSpace"),
        0xA002 => Some("PixelXDimension"),
        0xA003 => Some("PixelYDimension"),
        0xA004 => Some("RelatedSoundFile"),
        0xA005 => Some("InteroperabilityIFDPointer"),
        0xA20E => Some("FocalPlaneXResolution"),
        0xA20F => Some("FocalPlaneYResolution"),
        0xA210 => Some("FocalPlaneResolutionUnit"),
        0xA214 => Some("SubjectLocation"),
        0xA215 => Some("ExposureIndex"),
        0xA217 => Some("SensingMethod"),
        0xA300 => Some("FileSource"),
        0xA301 => Some("SceneType"),
        0xA302 => Some("CFAPattern"),
        0xA401 => Some("CustomRendered"),
        0xA402 => Some("ExposureMode"),
        0xA403 => Some("WhiteBalance"),
        0xA404 => Some("DigitalZoomRatio"),
        0xA405 => Some("FocalLengthIn35mmFilm"),
        0xA406 => Some("SceneCaptureType"),
        0xA407 => Some("GainControl"),
        0xA408 => Some("Contrast"),
        0xA409 => Some("Saturation"),
        0xA40A => Some("Sharpness"),
        0xA40C => Some("SubjectDistanceRange"),
        0xA420 => Some("ImageUniqueID"),
        0xA430 => Some("CameraOwnerName"),
        0xA431 => Some("BodySerialNumber"),
        0xA432 => Some("LensSpecification"),
        0xA433 => Some("LensMake"),
        0xA434 => Some("LensModel"),
        0xA435 => Some("LensSerialNumber"),
        0xA436 => Some("ImageTitle"),
        0xA437 => Some("Photographer"),
        0xA438 => Some("ImageEditor"),
        0xA439 => Some("CameraFirmware"),
        0xA43A => Some("RAWDevelopingSoftware"),
        0xA43B => Some("ImageEditingSoftware"),
        0xA43C => Some("MetadataEditingSoftware"),
        0x828D => Some("CFARepeatPatternDim"),
        0x828E => Some("CFAPattern"),
        0x8290 => Some("IPTC/NAA"),
        0x83BB => Some("IPTC"),
        0x8649 => Some("ImageResources"),
        0x8773 => Some("InterColorProfile"),
        0xC4A5 => Some("PrintIM"),
        0xC6D2 => Some("PanasonicTitle"),
        0xEA1C => Some("Padding"),
        _ => None,
    }
}

fn gps_tag(tag: u16) -> Option<&'static str> {
    Some(match tag {
        0x0000 => "GPSVersionID",
        0x0001 => "GPSLatitudeRef",
        0x0002 => "GPSLatitude",
        0x0003 => "GPSLongitudeRef",
        0x0004 => "GPSLongitude",
        0x0005 => "GPSAltitudeRef",
        0x0006 => "GPSAltitude",
        0x0007 => "GPSTimeStamp",
        0x0008 => "GPSSatellites",
        0x0009 => "GPSStatus",
        0x000A => "GPSMeasureMode",
        0x000B => "GPSDOP",
        0x000C => "GPSSpeedRef",
        0x000D => "GPSSpeed",
        0x000E => "GPSTrackRef",
        0x000F => "GPSTrack",
        0x0010 => "GPSImgDirectionRef",
        0x0011 => "GPSImgDirection",
        0x0012 => "GPSMapDatum",
        0x0013 => "GPSDestLatitudeRef",
        0x0014 => "GPSDestLatitude",
        0x0015 => "GPSDestLongitudeRef",
        0x0016 => "GPSDestLongitude",
        0x0017 => "GPSDestBearingRef",
        0x0018 => "GPSDestBearing",
        0x0019 => "GPSDestDistanceRef",
        0x001A => "GPSDestDistance",
        0x001B => "GPSProcessingMethod",
        0x001C => "GPSAreaInformation",
        0x001D => "GPSDateStamp",
        0x001E => "GPSDifferential",
        0x001F => "GPSHPositioningError",
        _ => return None,
    })
}

pub fn extract_gps_decimal(sections: &[Section]) -> Option<(f64, f64)> {
    let gps = sections
        .iter()
        .find(|s| s.id.contains("gps") || s.label.contains("GPS"))?;
    let lat = parse_coord(field_val(gps, "GPSLatitude")?)?;
    let lon = parse_coord(field_val(gps, "GPSLongitude")?)?;
    let lat_ref = field_val(gps, "GPSLatitudeRef").unwrap_or("N");
    let lon_ref = field_val(gps, "GPSLongitudeRef").unwrap_or("E");
    let lat = if lat_ref.starts_with('S') { -lat } else { lat };
    let lon = if lon_ref.starts_with('W') { -lon } else { lon };
    Some((lat, lon))
}

fn field_val<'a>(section: &'a Section, key: &str) -> Option<&'a str> {
    section
        .fields
        .iter()
        .find(|f| f.key.eq_ignore_ascii_case(key))
        .map(|f| f.value.as_str())
}

fn parse_coord(value: &str) -> Option<f64> {
    if let Some(idx) = value.rfind('(') {
        let inner = value[idx + 1..].trim_end_matches(')');
        if let Ok(v) = inner.parse::<f64>() {
            return Some(v);
        }
    }
    let nums: Vec<f64> = value
        .split(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .filter_map(|p| p.parse().ok())
        .collect();
    match nums.as_slice() {
        [d] => Some(*d),
        [d, m] => Some(d + m / 60.0),
        [d, m, s, ..] => Some(d + m / 60.0 + s / 3600.0),
        _ => None,
    }
}

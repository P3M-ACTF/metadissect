//! Builder for a JPEG with a rich EXIF/XMP/IPTC payload (dozens of tags).

#[allow(dead_code)]
struct TiffBuf {
    le: bool,
    data: Vec<u8>,
}

impl TiffBuf {
    fn new() -> Self {
        let mut data = vec![b'I', b'I', 42, 0, 8, 0, 0, 0];
        // IFD0 offset written later
        data.clear();
        data.extend_from_slice(&[b'I', b'I', 42, 0]);
        data.extend_from_slice(&8u32.to_le_bytes());
        Self { le: true, data }
    }

    #[allow(dead_code)]
    fn write_ifd(&mut self, entries: &[IfdEntry]) -> usize {
        let start = self.data.len();
        self.data
            .extend_from_slice(&(entries.len() as u16).to_le_bytes());
        let entries_pos = self.data.len();
        self.data
            .resize(self.data.len() + entries.len() * 12 + 4, 0);
        // next IFD = 0 already
        let mut blobs = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            let slot = entries_pos + i * 12;
            self.patch_u16(slot, e.tag);
            self.patch_u16(slot + 2, e.typ);
            self.patch_u32(slot + 4, e.count);
            let nbytes = type_size(e.typ) * e.count as usize;
            if nbytes <= 4 {
                let mut inline = [0u8; 4];
                let n = e.bytes.len().min(4);
                inline[..n].copy_from_slice(&e.bytes[..n]);
                self.data[slot + 8..slot + 12].copy_from_slice(&inline);
            } else {
                blobs.push((slot + 8, e.bytes.clone()));
            }
        }
        for (slot, bytes) in blobs {
            let off = self.data.len() as u32;
            self.patch_u32(slot, off);
            self.data.extend_from_slice(&bytes);
            if self.data.len() % 2 == 1 {
                self.data.push(0);
            }
        }
        start
    }

    fn patch_u16(&mut self, at: usize, v: u16) {
        self.data[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn patch_u32(&mut self, at: usize, v: u32) {
        self.data[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

struct IfdEntry {
    tag: u16,
    typ: u16,
    count: u32,
    bytes: Vec<u8>,
}

fn type_size(t: u16) -> usize {
    match t {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 1,
    }
}

fn ascii(tag: u16, s: &str) -> IfdEntry {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    IfdEntry {
        tag,
        typ: 2,
        count: b.len() as u32,
        bytes: b,
    }
}

fn short(tag: u16, v: u16) -> IfdEntry {
    IfdEntry {
        tag,
        typ: 3,
        count: 1,
        bytes: v.to_le_bytes().to_vec(),
    }
}

fn long(tag: u16, v: u32) -> IfdEntry {
    IfdEntry {
        tag,
        typ: 4,
        count: 1,
        bytes: v.to_le_bytes().to_vec(),
    }
}

fn rational(tag: u16, num: u32, den: u32) -> IfdEntry {
    let mut b = Vec::new();
    b.extend(num.to_le_bytes());
    b.extend(den.to_le_bytes());
    IfdEntry {
        tag,
        typ: 5,
        count: 1,
        bytes: b,
    }
}

fn srational(tag: u16, num: i32, den: i32) -> IfdEntry {
    let mut b = Vec::new();
    b.extend(num.to_le_bytes());
    b.extend(den.to_le_bytes());
    IfdEntry {
        tag,
        typ: 10,
        count: 1,
        bytes: b,
    }
}

fn rationals3(tag: u16, vals: [(u32, u32); 3]) -> IfdEntry {
    let mut b = Vec::new();
    for (n, d) in vals {
        b.extend(n.to_le_bytes());
        b.extend(d.to_le_bytes());
    }
    IfdEntry {
        tag,
        typ: 5,
        count: 3,
        bytes: b,
    }
}

fn undef(tag: u16, b: &[u8]) -> IfdEntry {
    IfdEntry {
        tag,
        typ: 7,
        count: b.len() as u32,
        bytes: b.to_vec(),
    }
}

fn bytes_tag(tag: u16, b: &[u8]) -> IfdEntry {
    IfdEntry {
        tag,
        typ: 1,
        count: b.len() as u32,
        bytes: b.to_vec(),
    }
}

/// Minimal valid 8×8 JPEG (SOF0 + empty scan) plus APP1 Exif, XMP and APP13 IPTC.
pub fn rich_exif_jpeg() -> Vec<u8> {
    let (exif_tiff, _le) = build_rich_tiff();
    let _ = _le;
    let mut app1 = b"Exif\0\0".to_vec();
    app1.extend(exif_tiff);

    let xmp = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"><dc:creator>MetaDissect Fixture</dc:creator><dc:title>Rich EXIF JPEG</dc:title><dc:rights>Public domain test</dc:rights><xmp:CreatorTool>MetaDissect fixture builder</xmp:CreatorTool><xmp:CreateDate>2024-06-15T12:00:00</xmp:CreateDate><photoshop:City>Madrid</photoshop:City></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"#;
    let mut xmp_payload = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    xmp_payload.extend_from_slice(xmp);

    let iptc = build_iptc();
    let mut irb = b"Photoshop 3.0\0".to_vec();
    irb.extend_from_slice(b"8BIM");
    irb.extend_from_slice(&0x0404u16.to_be_bytes());
    irb.push(0); // empty name
    irb.push(0); // pad
    irb.extend_from_slice(&(iptc.len() as u32).to_be_bytes());
    irb.extend(iptc);
    if irb.len() % 2 == 1 {
        irb.push(0);
    }

    let mut jpeg = vec![0xFF, 0xD8];
    push_app(&mut jpeg, 0xE1, &app1);
    push_app(&mut jpeg, 0xE1, &xmp_payload);
    push_app(&mut jpeg, 0xED, &irb);
    jpeg.extend_from_slice(MINIMAL_JPEG_BODY);
    jpeg
}

fn push_app(jpeg: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    jpeg.push(0xFF);
    jpeg.push(marker);
    let len = (payload.len() + 2) as u16;
    jpeg.extend_from_slice(&len.to_be_bytes());
    jpeg.extend_from_slice(payload);
}

fn build_rich_tiff() -> (Vec<u8>, bool) {
    // We write IFDs from the end of a growable buffer using placeholders for pointers.
    // Strategy: reserve space sequentially.
    let mut buf = TiffBuf::new();
    // We'll write ExifIFD and GPS first as blobs after IFD0 by using a two-pass:
    // 1) write dummy IFD0 with placeholder longs
    // 2) append child IFDs and patch pointers.
    // Simpler: write child IFDs first at known offsets after a reserved IFD0.

    // Reserve IFD0: 2 + N*12 + 4. We'll use 18 IFD0 entries.
    let ifd0_entries_planned = 18u16;
    let ifd0_start = buf.data.len();
    assert_eq!(ifd0_start, 8);
    buf.data
        .extend_from_slice(&ifd0_entries_planned.to_le_bytes());
    let ifd0_entries_pos = buf.data.len();
    buf.data
        .resize(buf.data.len() + ifd0_entries_planned as usize * 12 + 4, 0);

    let mut gps_entries = vec![
        bytes_tag(0x0000, &[2, 3, 0, 0]),
        ascii(0x0001, "N"),
        rationals3(0x0002, [(40, 1), (25, 1), (0, 1)]),
        ascii(0x0003, "W"),
        rationals3(0x0004, [(3, 1), (42, 1), (13, 1)]),
        bytes_tag(0x0005, &[0]),
        rational(0x0006, 650, 1),
        ascii(0x0010, "T"),
        rational(0x0011, 90, 1),
        ascii(0x0012, "WGS-84"),
        ascii(0x001D, "2024:06:15"),
    ];
    let mut exif_entries = vec![
        rational(0x829A, 1, 200),
        rational(0x829D, 18, 5),
        short(0x8822, 2),
        short(0x8827, 100),
        undef(0x9000, b"0232"),
        ascii(0x9003, "2024:06:15 12:00:00"),
        ascii(0x9004, "2024:06:15 12:00:01"),
        ascii(0x9011, "+02:00"),
        undef(0x9101, &[1, 2, 3, 0]),
        srational(0x9201, 764, 100),
        rational(0x9202, 433, 100),
        srational(0x9204, -3, 10),
        short(0x9207, 5),
        short(0x9209, 16),
        rational(0x920A, 35, 1),
        undef(0x9286, b"\x00MetaDissect user comment"),
        undef(0xA000, b"0100"),
        short(0xA001, 1),
        long(0xA002, 4032),
        long(0xA003, 3024),
        short(0xA402, 0),
        short(0xA403, 0),
        short(0xA406, 0),
        ascii(0xA434, "RF 35mm F1.8"),
        ascii(0xA431, "BODY123456"),
        ascii(0xA430, "MetaDissect Tester"),
        ascii(0xA433, "Canon"),
        ascii(0xA435, "LENS98765"),
    ];

    // Write ExifIFD and GPS after current end
    let exif_off = write_ifd_appended(&mut buf, &mut exif_entries);
    let gps_off = write_ifd_appended(&mut buf, &mut gps_entries);

    let ifd0 = vec![
        short(0x0100, 4032),
        short(0x0101, 3024),
        short(0x0102, 8),
        short(0x0103, 6),
        short(0x0106, 2),
        ascii(0x010E, "Fixture photograph with exhaustive tags"),
        ascii(0x010F, "Canon"),
        ascii(0x0110, "Canon EOS R6"),
        short(0x0112, 1),
        rational(0x011A, 72, 1),
        rational(0x011B, 72, 1),
        short(0x0128, 2),
        ascii(0x0131, "MetaDissect-0.2.0"),
        ascii(0x0132, "2024:06:15 12:05:00"),
        ascii(0x013B, "P3M-ACTF"),
        ascii(0x8298, "CC0 / Public Domain"),
        long(0x8769, exif_off as u32),
        long(0x8825, gps_off as u32),
    ];
    assert_eq!(ifd0.len(), ifd0_entries_planned as usize);

    // encode IFD0 entries into reserved slots, appending oversized values
    for (i, e) in ifd0.iter().enumerate() {
        let slot = ifd0_entries_pos + i * 12;
        buf.patch_u16(slot, e.tag);
        buf.patch_u16(slot + 2, e.typ);
        buf.patch_u32(slot + 4, e.count);
        let nbytes = type_size(e.typ) * e.count as usize;
        if nbytes <= 4 {
            let mut inline = [0u8; 4];
            let n = e.bytes.len().min(4);
            inline[..n].copy_from_slice(&e.bytes[..n]);
            buf.data[slot + 8..slot + 12].copy_from_slice(&inline);
        } else {
            let off = buf.data.len() as u32;
            buf.patch_u32(slot + 8, off);
            buf.data.extend_from_slice(&e.bytes);
            if buf.data.len() % 2 == 1 {
                buf.data.push(0);
            }
        }
    }
    (buf.data, true)
}

fn write_ifd_appended(buf: &mut TiffBuf, entries: &mut [IfdEntry]) -> usize {
    let start = buf.data.len();
    buf.data
        .extend_from_slice(&(entries.len() as u16).to_le_bytes());
    let entries_pos = buf.data.len();
    buf.data.resize(buf.data.len() + entries.len() * 12 + 4, 0);
    for (i, e) in entries.iter().enumerate() {
        let slot = entries_pos + i * 12;
        buf.patch_u16(slot, e.tag);
        buf.patch_u16(slot + 2, e.typ);
        buf.patch_u32(slot + 4, e.count);
        let nbytes = type_size(e.typ) * e.count as usize;
        if nbytes <= 4 {
            let mut inline = [0u8; 4];
            let n = e.bytes.len().min(4);
            inline[..n].copy_from_slice(&e.bytes[..n]);
            buf.data[slot + 8..slot + 12].copy_from_slice(&inline);
        } else {
            let off = buf.data.len() as u32;
            buf.patch_u32(slot + 8, off);
            buf.data.extend_from_slice(&e.bytes);
            if buf.data.len() % 2 == 1 {
                buf.data.push(0);
            }
        }
    }
    start
}

fn build_iptc() -> Vec<u8> {
    let mut out = Vec::new();
    fn ds(out: &mut Vec<u8>, rec: u8, id: u8, val: &str) {
        out.push(0x1C);
        out.push(rec);
        out.push(id);
        let b = val.as_bytes();
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
    }
    ds(&mut out, 2, 5, "Rich EXIF fixture");
    ds(&mut out, 2, 25, "metadata");
    ds(&mut out, 2, 25, "forensics");
    ds(&mut out, 2, 80, "MetaDissect");
    ds(&mut out, 2, 90, "Madrid");
    ds(&mut out, 2, 101, "Spain");
    ds(&mut out, 2, 105, "Exhaustive EXIF test");
    ds(&mut out, 2, 116, "Public domain");
    ds(&mut out, 2, 120, "Generated for MetaDissect Rust tests");
    out
}

/// Tiny 8×8 grayscale JPEG body (DQT + SOF0 + DHT + SOS + EOI).
const MINIMAL_JPEG_BODY: &[u8] = &[
    0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D,
    0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C,
    0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
    0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01,
    0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0x1F, 0x10, 0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03,
    0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D, 0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12,
    0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F,
    0x00, 0x7F, 0xFF, 0xD9,
];

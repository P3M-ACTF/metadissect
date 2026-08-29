//! Write synthetic Phase 5 fixtures (WARC / MSG) used by docs and smoke tests.
fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    std::fs::create_dir_all(&dir).expect("fixtures dir");
    let warc = metadissect::parsers::warc::minimal_warc_fixture();
    let msg = metadissect::parsers::msg::minimal_msg_fixture();
    std::fs::write(dir.join("sample.warc"), &warc).expect("write warc");
    std::fs::write(dir.join("sample.msg"), &msg).expect("write msg");
    println!(
        "wrote {} bytes WARC, {} bytes MSG to {}",
        warc.len(),
        msg.len(),
        dir.display()
    );
}

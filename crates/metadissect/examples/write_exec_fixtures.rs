//! Write synthetic PE/ELF fixtures used by docs and manual smoke tests.
fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    std::fs::create_dir_all(&dir).expect("fixtures dir");
    let pe = metadissect::parsers::pe::minimal_pe_fixture();
    let elf = metadissect::parsers::elf::minimal_elf_fixture();
    std::fs::write(dir.join("minimal.exe"), &pe).expect("write pe");
    std::fs::write(dir.join("minimal.elf"), &elf).expect("write elf");
    println!(
        "wrote {} bytes PE, {} bytes ELF to {}",
        pe.len(),
        elf.len(),
        dir.display()
    );
}

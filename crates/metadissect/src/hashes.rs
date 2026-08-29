use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::types::Hashes;

pub fn compute_hashes(data: &[u8]) -> Hashes {
    let md5 = hex::encode(Md5::digest(data));
    let sha1 = hex::encode(Sha1::digest(data));
    let sha256 = hex::encode(sha2_256(data));
    let sha512 = hex::encode(sha2_512(data));
    let blake3 = blake3::hash(data).to_hex().to_string();
    Hashes {
        md5,
        sha1,
        sha256,
        sha512,
        blake3,
    }
}

fn sha2_256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn sha2_512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_empty_are_stable() {
        let h = compute_hashes(b"");
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(h.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.blake3.len(), 64);
        assert_eq!(h.sha512.len(), 128);
    }
}

/// Shannon entropy in bits per byte (0.0–8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let sample = if data.len() > 1_048_576 {
        &data[..1_048_576]
    } else {
        data
    };
    let mut counts = [0u64; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let len = sample.len() as f64;
    let mut entropy = 0.0;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_zero_entropy() {
        assert_eq!(shannon_entropy(&[0; 64]), 0.0);
    }

    #[test]
    fn mixed_bytes_are_higher() {
        let data: Vec<u8> = (0..=255).collect();
        assert!(shannon_entropy(&data) > 7.5);
    }
}

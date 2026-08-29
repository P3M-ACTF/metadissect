/// Truncate on UTF-8 character boundaries (never panic on multibyte input).
pub fn truncate_chars(s: &str, max: usize) -> String {
    let mut iter = s.chars();
    let taken: String = iter.by_ref().take(max).collect();
    if iter.next().is_some() {
        format!("{taken}…")
    } else {
        taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_split_multibyte() {
        let s = "á".repeat(80);
        let t = truncate_chars(&s, 10);
        assert!(t.ends_with('…'));
        assert_eq!(t.chars().count(), 11);
    }
}

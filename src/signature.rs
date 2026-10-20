//! Offline hex/AOB parsing and matching; does not access game memory.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern(pub Vec<Option<u8>>);

impl Pattern {
    pub fn parse(input: &str) -> Result<Self, &'static str> {
        let mut out = Vec::new();
        for token in input.split_whitespace() {
            if token == "??" || token == "?" {
                out.push(None);
            } else {
                let token = token.strip_prefix("0x").unwrap_or(token);
                if token.len() != 2 {
                    return Err("Use two hex digits per byte or ?? for a wildcard");
                }
                let byte = u8::from_str_radix(token, 16).map_err(|_| "Invalid hexadecimal byte")?;
                out.push(Some(byte));
            }
        }
        if out.is_empty() { return Err("Pattern must not be empty"); }
        if out.iter().all(Option::is_none) { return Err("Pattern cannot contain only wildcards"); }
        Ok(Self(out))
    }

    pub fn matches(&self, data: &[u8]) -> Vec<usize> {
        if data.len() < self.0.len() { return Vec::new(); }
        data.windows(self.0.len())
            .enumerate()
            .filter_map(|(offset, window)| {
                self.0.iter().zip(window.iter()).all(|(want, got)| want.is_none_or(|v| v == *got))
                    .then_some(offset)
            })
            .collect()
    }

    pub fn canonical(&self) -> String {
        self.0.iter()
            .map(|v| v.map_or_else(|| "??".to_owned(), |b| format!("{b:02X}")))
            .collect::<Vec<_>>().join(" ")
    }
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    let pattern = Pattern::parse(input)?;
    if pattern.0.iter().any(Option::is_none) {
        return Err("The test buffer cannot contain wildcards");
    }
    Ok(pattern.0.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_and_overlapping_matches() {
        let p = Pattern::parse("AA ?? AA").unwrap();
        assert_eq!(p.matches(&[0xAA, 1, 0xAA, 2, 0xAA]), vec![0, 2]);
        assert_eq!(p.canonical(), "AA ?? AA");
    }
    #[test]
    fn rejects_invalid_or_unsafe_input() {
        assert!(Pattern::parse("?? ??").is_err());
        assert!(Pattern::parse("G1").is_err());
        assert!(decode_hex("12 ?? 34").is_err());
    }
}

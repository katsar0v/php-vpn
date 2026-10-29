use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 32-byte WireGuard private or preshared key. Wiped on drop and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses a base64 key. The error never contains the input.
    pub fn from_base64(text: &str) -> Option<Self> {
        decode_key(text).map(|k| Self(*k))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Decodes a base64 WireGuard key (44 characters, 32 bytes). The intermediate
/// buffer is wiped.
pub fn decode_key(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let text = text.trim();
    if text.len() != 44 {
        return None;
    }
    let mut buf = Zeroizing::new([0u8; 33]);
    let n = STANDARD.decode_slice(text, &mut buf[..]).ok()?;
    if n != 32 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&buf[..32]);
    Some(out)
}

pub fn encode_key(key: &[u8; 32]) -> String {
    STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let text = encode_key(&key);
        assert_eq!(*decode_key(&text).unwrap(), key);
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(decode_key("").is_none());
        assert!(decode_key("AAAA").is_none());
        assert!(decode_key(&"A".repeat(43)).is_none());
        assert!(decode_key("not base64 at all, but forty-four chars long").is_none());
    }

    #[test]
    fn debug_is_redacted() {
        let k = SecretKey::from_bytes([1; 32]);
        assert_eq!(format!("{k:?}"), "SecretKey(<redacted>)");
    }
}

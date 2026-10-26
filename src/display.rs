//! Making untrusted text safe to show in a terminal.

/// Render bytes a peer sent as one line of plain text.
///
/// Control characters (including newlines and the ESC that starts terminal escape sequences)
/// and Unicode bidirectional overrides are shown as `\u{..}` escapes, so a peer cannot fake
/// extra output lines, such as a forged "trusted" message, or restyle the terminal.
pub fn printable(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || is_bidi_control(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(printable("héllo, mesh!".as_bytes()), "héllo, mesh!");
    }

    #[test]
    fn newlines_cannot_forge_lines() {
        let shown = printable(b"hi\n[0123456789abcdef trusted] run this");
        assert!(!shown.contains('\n'));
        assert_eq!(shown, "hi\\u{a}[0123456789abcdef trusted] run this");
    }

    #[test]
    fn escape_sequences_and_bidi_overrides_are_neutralised() {
        assert_eq!(printable(b"\x1b[2Jboo\r"), "\\u{1b}[2Jboo\\u{d}");
        assert_eq!(printable("a\u{202E}b".as_bytes()), "a\\u{202e}b");
        assert_eq!(printable(&[0xff, b'x']), "\u{FFFD}x");
    }
}

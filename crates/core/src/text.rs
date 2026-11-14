//! Making untrusted text safe to show.
//!
//! App file names and publisher names come from the programs being watched,
//! so a hostile program chooses them. Shown as they are, control characters
//! could rewrite the terminal (escape sequences), and invisible Unicode
//! formatting characters could make one name look like another (for example
//! a right-to-left override turning `gpj.exe` into `exe.jpg`).

/// Returns `text` with control characters and invisible formatting
/// characters (direction overrides, zero-width characters) replaced by `?`.
pub fn display_safe(text: &str) -> String {
    text.chars()
        .map(|c| if is_hidden(c) { '?' } else { c })
        .collect()
}

/// Whether `c` is a control character or an invisible formatting character.
fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'                    // soft hyphen
                | '\u{061C}'              // Arabic letter mark
                | '\u{180E}'              // Mongolian vowel separator
                | '\u{200B}'..='\u{200F}' // zero-width characters, LTR/RTL marks
                | '\u{2028}'..='\u{202E}' // line/paragraph separators, embeddings, overrides
                | '\u{2060}'..='\u{206F}' // word joiner, isolates, other invisible formatting
                | '\u{FEFF}'              // zero-width no-break space
                | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_text_is_unchanged() {
        for text in [
            "chrome.exe",
            "Google LLC",
            "Société Générale",
            "微软",
            "Zoom Video",
        ] {
            assert_eq!(display_safe(text), text);
        }
    }

    #[test]
    fn control_and_invisible_characters_are_replaced() {
        assert_eq!(display_safe("evil\x1b[2Jcorp"), "evil?[2Jcorp");
        assert_eq!(display_safe("a\r\nb\tc"), "a??b?c");
        assert_eq!(display_safe("gpj\u{202E}.exe"), "gpj?.exe");
        assert_eq!(display_safe("Micro\u{200B}soft"), "Micro?soft");
        assert_eq!(display_safe("x\u{2066}y\u{2069}"), "x?y?");
        assert_eq!(display_safe("\u{FEFF}name"), "?name");
    }
}

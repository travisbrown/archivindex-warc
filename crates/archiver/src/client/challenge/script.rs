//! The string literals a challenge page's script states its data in.

/// Parse a single- or double-quoted string literal, returning it and what follows its close.
///
/// The literal must be ASCII, and `\\`, `\'`, `\"`, `\n`, `\r`, and `\t` are the only escapes
/// read: nothing a challenge page emits needs more, and a literal outside this grammar is not
/// recognized.
pub fn parse_string(input: &str) -> Option<(String, &str)> {
    let bytes = input.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }

    let mut output = String::new();
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == quote {
            return Some((output, &input[index + 1..]));
        }
        if byte == b'\\' {
            index += 1;
            let escaped = *bytes.get(index)?;
            output.push(match escaped {
                b'\\' => '\\',
                b'\'' => '\'',
                b'"' => '"',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                _ => return None,
            });
        } else if byte.is_ascii() {
            output.push(char::from(byte));
        } else {
            return None;
        }
        index += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::parse_string;

    #[test]
    fn literals_are_read_up_to_their_own_quote() {
        assert_eq!(
            parse_string(r#""a'b\"c\n",D=1;"#),
            Some(("a'b\"c\n".to_owned(), ",D=1;"))
        );
        assert_eq!(parse_string("'x';"), Some(("x".to_owned(), ";")));
    }

    #[test]
    fn literals_outside_the_grammar_are_not_read() {
        assert_eq!(parse_string("x"), None);
        assert_eq!(parse_string("'unterminated"), None);
        assert_eq!(parse_string(r"'\A'"), None);
        assert_eq!(parse_string("'caf\u{e9}'"), None);
    }
}

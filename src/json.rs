//! Minimal JSON parser for bounded, untrusted analyzer output.
//!
//! Analyzer output is untrusted data, so parsing is strict: duplicate keys are
//! allowed to overwrite, but input is depth-limited and rejects non-JSON
//! syntax. Only the subset needed to read Semgrep's JSON report is exposed.

use std::collections::BTreeMap;

const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(number)
                if number.is_finite()
                    && *number >= 0.0
                    && number.fract() == 0.0
                    && *number <= u64::MAX as f64 =>
            {
                Some(*number as u64)
            }
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        input: input.as_bytes(),
        position: 0,
        depth: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.position != parser.input.len() {
        return Err(format!("trailing data at byte {}", parser.position));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => {
                self.expect_literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.expect_literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.expect_literal("null")?;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(format!(
                "unexpected byte {:?} at {}",
                other as char, self.position
            )),
            None => Err("unexpected end of input".into()),
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.enter()?;
        self.position += 1;
        let mut map = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            self.depth -= 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.position)),
            }
        }
        self.depth -= 1;
        Ok(Value::Object(map))
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.enter()?;
        self.position += 1;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            self.depth -= 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.position)),
            }
        }
        self.depth -= 1;
        Ok(Value::Array(values))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut output = Vec::new();
        loop {
            let byte = self
                .next()
                .ok_or_else(|| "unterminated string".to_string())?;
            match byte {
                b'"' => {
                    return String::from_utf8(output)
                        .map_err(|_| "invalid UTF-8 in string".to_string())
                }
                b'\\' => self.parse_escape(&mut output)?,
                control if control < 0x20 => {
                    return Err(format!(
                        "control character in string at byte {}",
                        self.position - 1
                    ))
                }
                other => output.push(other),
            }
        }
    }

    fn parse_escape(&mut self, output: &mut Vec<u8>) -> Result<(), String> {
        match self
            .next()
            .ok_or_else(|| "unterminated escape".to_string())?
        {
            b'"' => output.push(b'"'),
            b'\\' => output.push(b'\\'),
            b'/' => output.push(b'/'),
            b'b' => output.push(0x08),
            b'f' => output.push(0x0c),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'u' => {
                let first = self.parse_hex4()?;
                let code = if (0xd800..=0xdbff).contains(&first) {
                    if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                        return Err("unpaired high surrogate".into());
                    }
                    let second = self.parse_hex4()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err("invalid low surrogate".into());
                    }
                    0x10000 + ((first as u32 - 0xd800) << 10) + (second as u32 - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err("unexpected low surrogate".into());
                } else {
                    first as u32
                };
                let character =
                    char::from_u32(code).ok_or_else(|| "invalid unicode escape".to_string())?;
                let mut buffer = [0u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
            other => return Err(format!("invalid escape '\\{}'", other as char)),
        }
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        let mut value = 0u16;
        for _ in 0..4 {
            let byte = self
                .next()
                .ok_or_else(|| "truncated unicode escape".to_string())?;
            let digit = (byte as char)
                .to_digit(16)
                .ok_or_else(|| "invalid unicode escape".to_string())?;
            value = value * 16 + digit as u16;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(format!("invalid number at byte {start}")),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            let digits = self.digits()?;
            if digits == 0 {
                return Err(format!("invalid fraction at byte {}", self.position));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if self.digits()? == 0 {
                return Err(format!("invalid exponent at byte {}", self.position));
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| format!("invalid number at byte {start}"))?;
        text.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| format!("invalid number at byte {start}"))
    }

    fn digits(&mut self) -> Result<usize, String> {
        let mut count = 0;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
            count += 1;
        }
        Ok(count)
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), String> {
        let end = self.position + literal.len();
        if self.input.get(self.position..end) == Some(literal.as_bytes()) {
            self.position = end;
            Ok(())
        } else {
            Err(format!("invalid literal at byte {}", self.position))
        }
    }

    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(format!("nesting exceeds {MAX_DEPTH} levels"))
        } else {
            Ok(())
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(format!(
                "expected {:?} at byte {}",
                byte as char, self.position
            ))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek();
        if byte.is_some() {
            self.position += 1;
        }
        byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_structures() {
        let value = parse(r#"{"results":[{"path":"a","start":{"line":3}}],"ok":true}"#).unwrap();
        assert_eq!(value.get("ok"), Some(&Value::Bool(true)));
        let results = value.get("results").unwrap().as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get("path").unwrap().as_str(), Some("a"));
        assert_eq!(
            results[0]
                .get("start")
                .unwrap()
                .get("line")
                .unwrap()
                .as_u64(),
            Some(3)
        );
    }

    #[test]
    fn parses_string_escapes_and_surrogate_pairs() {
        let value =
            parse(r#""quote:\" slash:\\ tab:\t unicode:\u00e9 pair:\ud83d\ude00""#).unwrap();
        assert_eq!(
            value.as_str(),
            Some("quote:\" slash:\\ tab:\t unicode:é pair:😀")
        );
    }

    #[test]
    fn parses_numbers_strictly() {
        assert_eq!(parse("0").unwrap().as_u64(), Some(0));
        assert_eq!(parse("-12").unwrap(), Value::Number(-12.0));
        assert_eq!(parse("1.5e2").unwrap(), Value::Number(150.0));
        assert!(parse("01").is_err());
        assert!(parse("+1").is_err());
        assert!(parse("1.").is_err());
        assert!(parse("1e").is_err());
        assert!(parse(".5").is_err());
    }

    #[test]
    fn rejects_malformed_documents() {
        for input in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\" 1}",
            "tru",
            "\"unterminated",
            "\"bad \\q escape\"",
            "\"\u{1}\"",
            "{} trailing",
            "\"\\ud800\"",
        ] {
            assert!(parse(input).is_err(), "expected rejection for {input:?}");
        }
    }

    #[test]
    fn rejects_excessive_nesting() {
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn handles_empty_containers_and_whitespace() {
        assert_eq!(
            parse(" \n\t{ } \r\n").unwrap(),
            Value::Object(BTreeMap::new())
        );
        assert_eq!(parse("[ ]").unwrap(), Value::Array(Vec::new()));
        assert_eq!(parse("null").unwrap(), Value::Null);
    }
}

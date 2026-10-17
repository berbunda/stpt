//! CBOR (RFC 8949) subset of STPT messages (PROTOCOL.md §7.3, §7.4).
//!
//! Only the data model STPT uses: integers, byte and text strings, arrays, maps,
//! `false`, `true` and `null`. The encoder writes deterministic encoding (RFC 8949
//! §4.2.1). The decoder accepts nothing else: no indefinite lengths, tags,
//! floating-point or other simple values, no argument longer than needed, map keys in
//! strictly ascending bytewise order of their encoding (so no duplicates), valid UTF-8,
//! bounded nesting and exactly one data item.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Negative integer `-1 - n` (major type 1).
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map entries in any order; the encoder sorts them.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn is_int(&self) -> bool {
        matches!(self, Self::Uint(_) | Self::Nint(_))
    }
}

/// Nesting depth every Endpoint accepts (§13.4); the outermost array of a message is
/// at depth 1.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    TrailingBytes,
    Indefinite,
    ReservedInfo,
    NotShortest,
    Tag,
    Float,
    Simple,
    InvalidUtf8,
    TooDeep,
    MapKeyOrder,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "data item is truncated",
            Self::TrailingBytes => "bytes after the data item",
            Self::Indefinite => "indefinite length",
            Self::ReservedInfo => "reserved additional information",
            Self::NotShortest => "argument not in its shortest form",
            Self::Tag => "tag",
            Self::Float => "floating-point number",
            Self::Simple => "simple value other than false, true, null",
            Self::InvalidUtf8 => "text string is not valid UTF-8",
            Self::TooDeep => "nesting too deep",
            Self::MapKeyOrder => "map keys not in ascending order or duplicate",
        })
    }
}

impl std::error::Error for Error {}

const UINT: u8 = 0;
const NINT: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;
const TAG: u8 = 6;
const SIMPLE: u8 = 7;

const FALSE: u8 = 20;
const TRUE: u8 = 21;
const NULL: u8 = 22;

/// Deterministic encoding of `value`.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => head(UINT, *n, out),
        Value::Nint(n) => head(NINT, *n, out),
        Value::Bytes(b) => {
            head(BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(TEXT, t.len() as u64, out);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(ARRAY, items.len() as u64, out);
            items.iter().for_each(|item| write(item, out));
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, v)| (encode(k), v)).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            debug_assert!(
                encoded.windows(2).all(|w| w[0].0 != w[1].0),
                "duplicate map key"
            );
            head(MAP, entries.len() as u64, out);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                write(value, out);
            }
        }
        Value::Bool(false) => out.push(SIMPLE << 5 | FALSE),
        Value::Bool(true) => out.push(SIMPLE << 5 | TRUE),
        Value::Null => out.push(SIMPLE << 5 | NULL),
    }
}

/// Initial byte and argument in the shortest form.
fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match arg {
        0..=23 => out.push(major | arg as u8),
        24..=0xFF => out.extend_from_slice(&[major | 24, arg as u8]),
        0x100..=0xFFFF => {
            out.push(major | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(major | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Decodes exactly one data item.
pub fn decode(bytes: &[u8]) -> Result<Value, Error> {
    let mut decoder = Decoder { bytes, pos: 0 };
    let value = decoder.item(1)?;
    if decoder.pos != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], Error> {
        if n > self.remaining() as u64 {
            return Err(Error::Truncated);
        }
        let start = self.pos;
        self.pos += n as usize;
        Ok(&self.bytes[start..self.pos])
    }

    /// Major type and argument of the next data item.
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1F);
        if major == SIMPLE {
            return match info {
                FALSE | TRUE | NULL => Ok((SIMPLE, u64::from(info))),
                25..=27 => Err(Error::Float),
                28..=30 => Err(Error::ReservedInfo),
                31 => Err(Error::Indefinite),
                _ => Err(Error::Simple),
            };
        }
        let (arg, min) = match info {
            0..=23 => return Ok((major, u64::from(info))),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            28..=30 => return Err(Error::ReservedInfo),
            _ => return Err(Error::Indefinite),
        };
        if arg < min {
            return Err(Error::NotShortest);
        }
        Ok((major, arg))
    }

    fn item(&mut self, depth: usize) -> Result<Value, Error> {
        let (major, arg) = self.head()?;
        match major {
            UINT => Ok(Value::Uint(arg)),
            NINT => Ok(Value::Nint(arg)),
            BYTES => Ok(Value::Bytes(self.take(arg)?.to_vec())),
            TEXT => {
                let text = std::str::from_utf8(self.take(arg)?).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            ARRAY => {
                if depth > MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                // Every item takes at least one byte: no allocation beyond the input.
                if arg > self.remaining() as u64 {
                    return Err(Error::Truncated);
                }
                let mut items = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            MAP => {
                if depth > MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                if u128::from(arg) * 2 > self.remaining() as u128 {
                    return Err(Error::Truncated);
                }
                let mut entries = Vec::with_capacity(arg as usize);
                let mut previous: Option<&[u8]> = None;
                for _ in 0..arg {
                    let start = self.pos;
                    let key = self.item(depth + 1)?;
                    let encoded = &self.bytes[start..self.pos];
                    if previous.is_some_and(|p| p >= encoded) {
                        return Err(Error::MapKeyOrder);
                    }
                    previous = Some(encoded);
                    entries.push((key, self.item(depth + 1)?));
                }
                Ok(Value::Map(entries))
            }
            TAG => Err(Error::Tag),
            _ => Ok(match arg as u8 {
                FALSE => Value::Bool(false),
                TRUE => Value::Bool(true),
                _ => Value::Null,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    /// Examples of RFC 8949 Appendix A within the subset.
    #[test]
    fn rfc8949_examples() {
        use Value::*;
        let cases = [
            ("00", Uint(0)),
            ("17", Uint(23)),
            ("1818", Uint(24)),
            ("1903e8", Uint(1000)),
            ("1a000f4240", Uint(1_000_000)),
            ("1b000000e8d4a51000", Uint(1_000_000_000_000)),
            ("1bffffffffffffffff", Uint(u64::MAX)),
            ("20", Nint(0)),
            ("3863", Nint(99)),
            ("3bffffffffffffffff", Nint(u64::MAX)),
            ("f4", Bool(false)),
            ("f5", Bool(true)),
            ("f6", Null),
            ("40", Bytes(vec![])),
            ("4401020304", Bytes(vec![1, 2, 3, 4])),
            ("60", text("")),
            ("6449455446", text("IETF")),
            ("62c3bc", text("\u{fc}")),
            ("80", Array(vec![])),
            (
                "8301820203820405",
                Array(vec![
                    Uint(1),
                    Array(vec![Uint(2), Uint(3)]),
                    Array(vec![Uint(4), Uint(5)]),
                ]),
            ),
            ("a0", Map(vec![])),
            (
                "a201020304",
                Map(vec![(Uint(1), Uint(2)), (Uint(3), Uint(4))]),
            ),
            (
                "a26161016162820203",
                Map(vec![
                    (text("a"), Uint(1)),
                    (text("b"), Array(vec![Uint(2), Uint(3)])),
                ]),
            ),
        ];
        for (encoded, value) in cases {
            assert_eq!(decode(&hex(encoded)), Ok(value.clone()), "{encoded}");
            assert_eq!(encode(&value), hex(encoded), "{encoded}");
        }
    }

    #[test]
    fn map_keys_are_sorted_bytewise() {
        use Value::*;
        // Encodings: 10 = 0a, 100 = 1864, -1 = 20, "z" = 617a.
        let value = Map(vec![
            (text("z"), Null),
            (Nint(0), Null),
            (Uint(100), Null),
            (Uint(10), Null),
        ]);
        let encoded = encode(&value);
        assert_eq!(encoded, hex("a40af61864f620f6617af6"));
        assert!(decode(&encoded).is_ok());
    }

    #[test]
    fn rejected_encodings() {
        let cases = [
            ("", Error::Truncated),
            ("18", Error::Truncated),
            ("62c3", Error::Truncated),
            ("82010203", Error::TrailingBytes),
            ("9f01ff", Error::Indefinite),
            ("bf01f6ff", Error::Indefinite),
            ("5f4101ff", Error::Indefinite),
            ("7f6161ff", Error::Indefinite),
            ("ff", Error::Indefinite),
            ("1c", Error::ReservedInfo),
            ("fc", Error::ReservedInfo),
            ("1801", Error::NotShortest),
            ("190017", Error::NotShortest),
            ("1a0000ffff", Error::NotShortest),
            ("1b00000000ffffffff", Error::NotShortest),
            ("5801", Error::NotShortest),
            ("c074323031332d30332d32315432303a30343a30305a", Error::Tag),
            ("f93c00", Error::Float),
            ("fa47c35000", Error::Float),
            ("fb3ff199999999999a", Error::Float),
            ("f7", Error::Simple),
            ("f0", Error::Simple),
            ("f820", Error::Simple),
            ("62c328", Error::InvalidUtf8),
            ("a203040102", Error::MapKeyOrder),
            ("a201020103", Error::MapKeyOrder),
        ];
        for (encoded, error) in cases {
            assert_eq!(decode(&hex(encoded)), Err(error), "{encoded}");
        }
    }

    #[test]
    fn huge_counts_do_not_allocate() {
        for encoded in [
            "9bffffffffffffffff",
            "bbffffffffffffffff",
            "5bffffffffffffffff",
            "9a7fffffff00",
        ] {
            assert_eq!(decode(&hex(encoded)), Err(Error::Truncated), "{encoded}");
        }
    }

    #[test]
    fn nesting_limit() {
        let nested = |depth: usize| {
            let mut bytes = vec![0x81; depth - 1];
            bytes.push(0x80);
            bytes
        };
        assert!(decode(&nested(MAX_DEPTH)).is_ok());
        assert_eq!(decode(&nested(MAX_DEPTH + 1)), Err(Error::TooDeep));
        let mut maps = [0xa1, 0x00].repeat(MAX_DEPTH);
        maps.push(0xa0);
        assert_eq!(decode(&maps), Err(Error::TooDeep));
        let mut maps = [0xa1, 0x00].repeat(MAX_DEPTH - 1);
        maps.push(0xa0);
        assert!(decode(&maps).is_ok());
    }
}

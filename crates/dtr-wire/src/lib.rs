//! S03 canonical typed JSON and exact arithmetic. No ambient clock, IC calls, or entropy.
#![forbid(unsafe_code)]
use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{Signed, Zero};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
const SAFE: i64 = 9_007_199_254_740_991;

/// Unlike an ordinary JSON integer, this must retain its explicit BigInt tag.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Int(pub BigInt);
impl From<i64> for Int {
    fn from(n: i64) -> Self {
        Self(n.into())
    }
}
impl Serialize for Int {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        json!({"$integer": self.0.to_string()}).serialize(s)
    }
}
impl<'de> Deserialize<'de> for Int {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let value = Value::deserialize(d)?;
        let text = value
            .as_object()
            .filter(|o| o.len() == 1)
            .and_then(|o| o.get("$integer"))
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("integer tag"))?;
        if !integer_text(text) {
            return Err(serde::de::Error::custom("integer encoding"));
        }
        text.parse::<BigInt>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// Exactly reduced arbitrary-precision fraction; its wire form is two tagged integers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rat(pub BigRational);
impl Rat {
    pub fn integer(n: i64) -> Self {
        Self(BigRational::from_integer(n.into()))
    }
    pub fn new(n: BigInt, d: BigInt) -> Result<Self> {
        if d.is_zero() {
            return Err("zero denominator".into());
        }
        Ok(Self(BigRational::new(n, d)))
    }
    pub fn check(&self) -> Result<()> {
        if self.0.numer().to_string().len() > 900 || self.0.denom().to_string().len() > 900 {
            return Err("fraction capacity".into());
        }
        Ok(())
    }
    pub fn add(&self, other: &Self) -> Result<Self> {
        Ok(Self(&self.0 + &other.0))
    }
    pub fn sub(&self, other: &Self) -> Result<Self> {
        Ok(Self(&self.0 - &other.0))
    }
    pub fn mul_i(&self, n: i64) -> Result<Self> {
        Ok(Self(&self.0 * BigInt::from(n)))
    }
    pub fn abs(&self) -> Self {
        Self(self.0.abs())
    }
}
impl Serialize for Rat {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        [Int(self.0.numer().clone()), Int(self.0.denom().clone())].serialize(s)
    }
}
impl<'de> Deserialize<'de> for Rat {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let [n, den] = <[Int; 2]>::deserialize(d)?;
        if den.0 <= BigInt::zero() {
            return Err(serde::de::Error::custom("fraction denominator"));
        }
        let r = Rat::new(n.0.clone(), den.0.clone()).map_err(serde::de::Error::custom)?;
        if r.0.numer() != &n.0 || r.0.denom() != &den.0 {
            return Err(serde::de::Error::custom("unreduced fraction"));
        }
        Ok(r)
    }
}
impl fmt::Display for Rat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.0.numer(), self.0.denom())
    }
}
fn integer_text(s: &str) -> bool {
    if s.is_empty() || s.len() > 1000 {
        return false;
    }
    if s == "0" {
        return true;
    }
    let t = s.strip_prefix('-').unwrap_or(s);
    !t.is_empty() && matches!(t.as_bytes()[0], b'1'..=b'9') && t.bytes().all(|b| b.is_ascii_digit())
}
fn key_ok(k: &str) -> bool {
    !matches!(k, "constructor" | "prototype" | "__proto__")
        && k.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn validate(v: &Value, depth: usize, count: &mut usize) -> Result<()> {
    *count += 1;
    if depth > 48 || *count > 300_000 {
        return Err("canonical structural limit".into());
    }
    match v {
        Value::Null | Value::Bool(_) | Value::String(_) => {}
        Value::Number(n) => {
            let x = n.as_i64().ok_or("non-integer JSON number")?;
            if !(-SAFE..=SAFE).contains(&x) {
                return Err("unsafe JSON integer".into());
            }
        }
        Value::Array(a) => {
            for x in a {
                validate(x, depth + 1, count)?;
            }
        }
        Value::Object(o) => {
            if let Some(n) = o.get("$integer") {
                if o.len() != 1 || !n.as_str().is_some_and(integer_text) {
                    return Err("integer tag".into());
                }
            } else {
                for (key, x) in o {
                    if !key_ok(key) {
                        return Err("reserved/noncanonical key".into());
                    }
                    validate(x, depth + 1, count)?;
                }
            }
        }
    }
    Ok(())
}
// Explicitly sort recursively even if a future host dependency enables serde_json's
// preserve_order feature through Cargo feature unification.
#[cfg(test)]
fn sorted(value: Value) -> Value {
    match value {
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        Value::Object(o) => {
            let mut pairs: Vec<_> = o.into_iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (key, value) in pairs {
                out.insert(key, sorted(value));
            }
            Value::Object(out)
        }
        other => other,
    }
}
// Write the validated value without rebuilding its entire object/array tree.
// Preserve exact serde_json primitive/string escaping and explicit key ordering,
// including when a consumer enables serde_json/preserve_order.
fn write_canonical(value: &Value, out: &mut Vec<u8>) -> serde_json::Result<()> {
    match value {
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(items) => {
            out.push(b'{');
            let mut pair = |i: usize, key: &String, value: &Value| -> serde_json::Result<()> {
                if i != 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                write_canonical(value, out)
            };
            if items.keys().is_sorted() {
                for (i, (key, value)) in items.iter().enumerate() {
                    pair(i, key, value)?;
                }
            } else {
                let mut ordered: Vec<_> = items.iter().collect();
                ordered.sort_unstable_by(|a, b| a.0.cmp(b.0));
                for (i, (key, value)) in ordered.into_iter().enumerate() {
                    pair(i, key, value)?;
                }
            }
            out.push(b'}');
        }
        _ => serde_json::to_writer(out, value)?,
    }
    Ok(())
}
pub fn encode<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(v).map_err(|e| e.to_string())?;
    validate(&value, 0, &mut 0)?;
    // Sorting does not rely on the dependency graph preserving a default map feature.
    let mut bytes = Vec::new();
    write_canonical(&value, &mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("canonical byte limit".into());
    }
    Ok(bytes)
}
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_BYTES {
        return Err("canonical byte limit".into());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if encode(&value)? != bytes {
        return Err("noncanonical bytes".into());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}
pub fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().checked_mul(2).expect("hex capacity"));
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("canonical hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let n = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok((n(p[0]) << 4) | n(p[1]))
        })
        .collect()
}
pub fn object(v: &Value) -> Result<&serde_json::Map<String, Value>> {
    v.as_object().ok_or_else(|| "object required".into())
}

#[cfg(test)]
mod tests {

    fn reference_encode(value: &serde_json::Value) -> super::Result<Vec<u8>> {
        super::validate(value, 0, &mut 0)?;
        let bytes = serde_json::to_vec(&super::sorted(value.clone())).unwrap();
        if bytes.len() > super::MAX_BYTES {
            return Err("canonical byte limit".into());
        }
        Ok(bytes)
    }
    #[test]
    fn canonical_writer_matches_stateless_oracle_and_rejections() {
        use serde_json::{json, Value};
        let mut corpus = vec![
            Value::Null,
            json!(true),
            json!(0),
            json!(-1),
            json!({"z":["\\\"\n\t\r\u{0000} é 🟡",null,false],"a":{"zz":1,"aa":2}}),
            json!({"$integer":"123456789012345678901234567890"}),
            json!({"$integer":"-0"}),
            json!({"$integer":"01"}),
            json!({"$integer":"1","a":0}),
            json!({"__proto__":0}),
            json!({"constructor":0}),
            json!({"bad-key":0}),
            json!(1.5),
            json!(9007199254740992u64),
        ];
        let mut deep = json!(0);
        for _ in 0..50 {
            deep = json!([deep]);
        }
        corpus.push(deep);
        corpus.push(Value::Array(vec![Value::Null; 300001]));
        for value in corpus {
            assert_eq!(super::encode(&value), reference_encode(&value));
        }
        for bytes in [
            b"{\"a\":1,\"a\":2}".as_slice(),
            b"{\"z\":1,\"a\":2}",
            b" {\"a\":1}",
            b"-0",
            b"1.0",
            b"\"\\u0061\"",
            b"[",
            b"\xff",
        ] {
            assert!(super::decode::<Value>(bytes).is_err(), "accepted {bytes:?}");
        }
        let mut map = serde_json::Map::new();
        map.insert("z".into(), json!(1));
        map.insert("a".into(), json!(2));
        assert_eq!(
            super::encode(&Value::Object(map)).unwrap(),
            b"{\"a\":2,\"z\":1}"
        );
    }
    #[test]
    fn hex_lookup_preserves_every_byte_and_large_fields() {
        for n in [0, 1, 32, 256, 65536] {
            let bytes: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let reference: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(super::hex(&bytes), reference);
            assert_eq!(super::unhex(&reference).unwrap(), bytes);
        }
    }
    use super::*;
    #[test]
    fn tagged_roundtrip() {
        let x = Int(BigInt::from(1u8) << 200usize);
        let bytes = encode(&x).unwrap();
        assert_eq!(decode::<Int>(&bytes).unwrap(), x);
    }
    #[test]
    fn malformed_encodings_fail() {
        for s in [
            "{\"a\":1,\"a\":1}",
            "-0",
            "1.0",
            "9007199254740992",
            "{\"$integer\":\"01\"}",
            " {\"a\":1}",
            "{\"b\":1,\"a\":2}",
        ] {
            assert!(decode::<Value>(s.as_bytes()).is_err(), "{s}");
        }
    }
    #[test]
    fn reduced_exact_arithmetic() {
        let a = Rat::new(BigInt::from(1) << 180usize, 3.into()).unwrap();
        let b = Rat::new(1.into(), 7.into()).unwrap();
        assert_eq!(a.add(&b).unwrap().sub(&b).unwrap(), a);
        assert!(decode::<Rat>(br#"[{"$integer":"2"},{"$integer":"4"}]"#).is_err());
    }
}

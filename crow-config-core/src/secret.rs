//! Values of `secret` fields (API tokens, passwords).
//!
//! A [`SecretValue`] can be moved around like any other value, but it never
//! shows itself by accident: `Debug`, `Display` and serialization all print
//! `[secret]`. The only way to read it is [`SecretValue::expose`], which the
//! host app calls at the moment it hands the value to its vault or to the
//! request that needs it.
//!
//! Documents never keep secret values. Their IR only says whether a secret
//! is set (see [`secret_state`]).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// What secrets print as, everywhere.
pub const REDACTED: &str = "[secret]";

/// A secret value that doesn't leak through `Debug`, `Display` or serde.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value itself. Call this only where the value is used (vault,
    /// outgoing request), never to display or log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Serializes as `"[secret]"`, so an edit or change record written to disk
/// or a log never carries the value.
impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Deserializes from a plain string, so a UI or RPC layer can hand one in.
impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for SecretValue {
    /// Overwrites the bytes before the memory is freed.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The IR value of a secret field: `{"set": true}` or `{"set": false}`.
pub fn secret_state(is_set: bool) -> serde_json::Value {
    serde_json::json!({ "set": is_set })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_or_serializes_the_value() {
        let s = SecretValue::new("tok-123");
        assert_eq!(format!("{s:?}"), "[secret]");
        assert_eq!(format!("{s}"), "[secret]");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"[secret]\"");
        assert_eq!(format!("{:?}", Some(vec![s.clone()])), "Some([[secret]])");
        assert_eq!(s.expose(), "tok-123");
    }

    #[test]
    fn deserializes_from_a_plain_string() {
        let s: SecretValue = serde_json::from_str("\"tok-123\"").unwrap();
        assert_eq!(s.expose(), "tok-123");
    }
}

//! Opt-in JSON-object boundaries for nested MCP argument structs.
//!
//! Serde's derived named structs also accept positional sequences. Use
//! `#[serde(deserialize_with = "crate::mcp::object::deserialize")]` for an
//! object field or `object::vec` for an array of object records. Keep
//! `deny_unknown_fields` on the nested type. This is not a schema validator:
//! the adapter still owns required fields, defaults, and semantic validation.
//!
//! Maps are passed directly to the typed deserializer, never collected into a
//! JSON Value, so duplicate fields and borrowed text retain their semantics.
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::marker::PhantomData;

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(PhantomData<fn() -> T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON object")
        }
        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(ObjectVisitor(PhantomData))
}

struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize(deserializer).map(Self)
    }
}

/// Deserialize an ordinary JSON array whose individual entries must be maps.
/// Add `serde(default)` at the field only when omission is valid for that tool.
pub fn vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Vec::<Object<T>>::deserialize(deserializer)
        .map(|values| values.into_iter().map(|value| value.0).collect())
}

/// Nullable object field. Add `serde(default)` when omission is also valid.
pub fn optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Object<T>>::deserialize(deserializer).map(|value| value.map(|value| value.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Record {
        #[serde(default)]
        text: String,
        #[serde(default)]
        count: u64,
    }
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Arguments {
        #[serde(default, deserialize_with = "super::deserialize")]
        record: Record,
        #[serde(default, deserialize_with = "super::vec")]
        records: Vec<Record>,
        #[serde(default, deserialize_with = "super::optional")]
        nullable: Option<Record>,
    }

    #[test]
    fn maps_keep_literal_text_defaults_and_borrowing() {
        let args: Arguments = serde_json::from_str(
            r#"{"record":{"text":"@-","count":7},"records":[{"text":"@/host/path"},{}]}"#,
        )
        .unwrap();
        assert_eq!(
            args.record,
            Record {
                text: "@-".into(),
                count: 7
            }
        );
        assert_eq!(args.records[0].text, "@/host/path");
        assert_eq!(args.records[1], Record::default());
        let defaults: Arguments = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults.record, Record::default());
        assert!(defaults.records.is_empty());
        assert!(defaults.nullable.is_none());
        let null: Arguments = serde_json::from_str(r#"{"nullable":null}"#).unwrap();
        assert!(null.nullable.is_none());
        let nullable: Arguments = serde_json::from_str(r#"{"nullable":{"text":"@-"}}"#).unwrap();
        assert_eq!(nullable.nullable.unwrap().text, "@-");

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Borrowed<'a> {
            text: &'a str,
        }
        let input = r#"{"text":"literal"}"#;
        let mut decoder = serde_json::Deserializer::from_str(input);
        let borrowed: Borrowed<'_> = super::deserialize(&mut decoder).unwrap();
        assert_eq!(borrowed.text, "literal");
        assert!(std::ptr::eq(borrowed.text.as_ptr(), input[9..].as_ptr()));
    }

    #[test]
    fn positional_sequences_scalars_and_null_are_not_objects() {
        for input in [
            r#"{"record":[]}"#,
            r#"{"record":["position",7]}"#,
            r#"{"record":null}"#,
            r#"{"record":"@-"}"#,
            r#"{"record":1}"#,
            r#"{"records":[[]]}"#,
            r#"{"records":[["position",7]]}"#,
            r#"{"records":[null]}"#,
            r#"{"records":["@-"]}"#,
            r#"{"records":[1]}"#,
            r#"{"records":{}}"#,
            r#"{"records":null}"#,
            r#"{"nullable":[]}"#,
            r#"{"nullable":["position",7]}"#,
            r#"{"nullable":"@-"}"#,
        ] {
            assert!(serde_json::from_str::<Arguments>(input).is_err(), "{input}");
        }
    }

    #[test]
    fn typed_maps_still_reject_duplicate_unknown_and_wrong_type_fields() {
        for input in [
            r#"{"record":{"text":"first","text":"second"}}"#,
            r#"{"records":[{"text":"first","text":"second"}]}"#,
            r#"{"record":{"unknown":"@-"}}"#,
            r#"{"records":[{"unknown":"@-"}]}"#,
            r#"{"record":{"count":"7"}}"#,
            r#"{"records":[{"count":"7"}]}"#,
            r#"{"nullable":{"text":"first","text":"second"}}"#,
            r#"{"nullable":{"unknown":"@-"}}"#,
            r#"{"nullable":{"count":"7"}}"#,
            r#"{"record":{},"record":{}}"#,
            r#"{"records":[],"records":[]}"#,
        ] {
            assert!(serde_json::from_str::<Arguments>(input).is_err(), "{input}");
        }
    }
}

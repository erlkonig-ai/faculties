//! Every object-shaped nested faculty argument stays a JSON map, never a
//! positional serde struct. Invalid inputs must stop before storage or output.
use anybytes::Bytes;
use faculties::mcp::{Faculty, InvalidArguments, Server};
use faculties::out::Out;
use std::path::Path;

fn adapters(pile: &Path) -> Vec<Box<dyn Faculty>> {
    vec![
        Box::new(faculties::mail::mcp::Mail::new(pile.into(), None)),
        Box::new(faculties::archive::mcp::Archive::new(pile.into(), None)),
        Box::new(faculties::planner::mcp::Planner::new(pile.into(), None)),
        Box::new(faculties::posture::mcp::Posture::new(pile.into(), None)),
        Box::new(faculties::relations::mcp::Relations::new(pile.into(), None)),
        Box::new(faculties::wiki::mcp::Wiki::new(pile.into(), None)),
        Box::new(faculties::linkedin::mcp::LinkedIn::new(pile.into(), None)),
    ]
}

struct Case {
    adapter: usize,
    tool: &'static str,
    prefix: &'static str,
    suffix: &'static str,
    record: &'static str,
    positional: &'static str,
    duplicate: &'static str,
}
impl Case {
    fn arguments(&self, record: &str) -> String {
        format!("{}{record}{}", self.prefix, self.suffix)
    }
    fn with_member(&self, member: &str) -> String {
        format!("{},{member}}}", self.record.strip_suffix('}').unwrap())
    }
}

/// Covers ten production fields and all nine distinct nested record types.
fn cases() -> Vec<Case> {
    vec![
        Case {
            adapter: 0,
            tool: "mail_draft",
            prefix: r#"{"account":"unopened","to":["to@example.test"],"subject":"subject","body":"@-","attachments":["#,
            suffix: "]}",
            record: r#"{"name":"@-","mime":"text/plain","data":"YQ=="}"#,
            positional: r#"["@-","text/plain","YQ=="]"#,
            duplicate: r#""name":"second""#,
        },
        Case {
            adapter: 1,
            tool: "archive_import",
            prefix: r#"{"source":"chatgpt","source_name":"resident.json","content":"[]","attachments":["#,
            suffix: "]}",
            record: r#"{"name":"@-","data":"YQ=="}"#,
            positional: r#"["@-","YQ=="]"#,
            duplicate: r#""name":"second""#,
        },
        Case {
            adapter: 2,
            tool: "planner_ingest",
            prefix: r#"{"documents":["#,
            suffix: "]}",
            record: r#"{"name":"@-","text":"BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR"}"#,
            positional: r#"["@-","BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR"]"#,
            duplicate: r#""name":"second""#,
        },
        Case {
            adapter: 3,
            tool: "posture_scan",
            prefix: r#"{"label":"resident","dry_run":true,"documents":["#,
            suffix: "]}",
            record: r#"{"name":"@-","data_base64":"YQ=="}"#,
            positional: r#"["@-","YQ=="]"#,
            duplicate: r#""name":"second""#,
        },
        Case {
            adapter: 3,
            tool: "posture_semantic",
            prefix: r#"{"channel":"github-public","documents":["#,
            suffix: "]}",
            record: r#"{"name":"@-","text":"@/host/path"}"#,
            positional: r#"["@-","@/host/path"]"#,
            duplicate: r#""name":"second""#,
        },
        Case {
            adapter: 4,
            tool: "relations_add",
            prefix: r#"{"label":"Ada","profile":"#,
            suffix: "}",
            record: r#"{"first_name":"@-","emails":["literal@example.test"]}"#,
            positional: "[]",
            duplicate: r#""first_name":"second""#,
        },
        Case {
            adapter: 4,
            tool: "relations_set",
            prefix: r#"{"person":"ab","patch":"#,
            suffix: "}",
            record: r#"{"note":"@-","clear":["company"]}"#,
            positional: "[]",
            duplicate: r#""note":"second""#,
        },
        Case {
            adapter: 4,
            tool: "relations_reconcile",
            prefix: r#"{"person":"ab","patch":"#,
            suffix: "}",
            record: r#"{"note":"@-","clear":["company"]}"#,
            positional: "[]",
            duplicate: r#""note":"second""#,
        },
        Case {
            adapter: 5,
            tool: "wiki_import",
            prefix: r#"{"documents":["#,
            suffix: "]}",
            record: r#"{"title":"@-","content":"= Literal"}"#,
            positional: r#"["@-","= Literal"]"#,
            duplicate: r#""title":"second""#,
        },
        Case {
            adapter: 6,
            tool: "linkedin_import",
            prefix: r#"{"connections":["#,
            suffix: "]}",
            record: r#"{"first_name":"@-","profile_url":"linkedin.com/in/literal"}"#,
            positional: "[]",
            duplicate: r#""first_name":"second""#,
        },
    ]
}

#[test]
fn nested_positional_arrays_scalars_and_null_fail_before_any_operation() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("never-created.pile");
    let adapters = adapters(&pile);
    for case in cases() {
        for record in [case.positional, "[]", "null", "42", r#""@-""#, "true"] {
            let arguments = case.arguments(record);
            let mut emitted = 0;
            let error = adapters[case.adapter]
                .call(
                    case.tool,
                    Bytes::from(arguments.into_bytes()),
                    &mut Out::new(&mut |_| {
                        emitted += 1;
                        Ok(())
                    }),
                )
                .unwrap_err();
            assert!(
                error.is::<InvalidArguments>(),
                "{} {record}: {error:#}",
                case.tool
            );
            assert!(
                error.to_string().contains("object"),
                "{} {record}: {error:#}",
                case.tool
            );
            assert_eq!(emitted, 0);
            assert!(!pile.exists());
        }
    }
}

#[test]
fn map_deserialization_keeps_duplicate_and_unknown_field_errors() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("never-created.pile");
    let adapters = adapters(&pile);
    for case in cases() {
        for (member, message) in [
            (case.duplicate, "duplicate field"),
            (r#""unexpected":"@-""#, "unknown field"),
        ] {
            let arguments = case.arguments(&case.with_member(member));
            let mut emitted = 0;
            let error = adapters[case.adapter]
                .call(
                    case.tool,
                    Bytes::from(arguments.into_bytes()),
                    &mut Out::new(&mut |_| {
                        emitted += 1;
                        Ok(())
                    }),
                )
                .unwrap_err();
            assert!(error.is::<InvalidArguments>(), "{}: {error:#}", case.tool);
            assert!(
                error.to_string().contains(message),
                "{}: {error:#}",
                case.tool
            );
            assert_eq!(emitted, 0);
            assert!(!pile.exists());
        }
    }
}

fn request(server: &mut Server<'_>, raw: &str) -> Option<serde_json::Value> {
    server
        .dispatch(Bytes::from(raw.as_bytes().to_vec()))
        .unwrap()
        .map(|response| serde_json::from_str(&response).unwrap())
}

#[test]
fn malformed_nested_objects_are_json_rpc_invalid_params_not_handler_errors() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("never-created.pile");
    let adapters = adapters(&pile);
    let references = adapters
        .iter()
        .map(|adapter| adapter.as_ref())
        .collect::<Vec<_>>();
    let mut server = Server::new(&references).unwrap();
    request(&mut server, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#).unwrap();
    assert!(request(
        &mut server,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )
    .is_none());
    for (index, case) in cases().into_iter().enumerate() {
        let id = index + 2;
        // The original nested argument bytes go straight into the wire frame;
        // no intermediate Value can normalize a malformed array or erase keys.
        let raw = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{}","arguments":{}}}}}"#,
            case.tool,
            case.arguments(case.positional),
        );
        let response = request(&mut server, &raw).unwrap();
        assert_eq!(response["id"], id, "{}: {response}", case.tool);
        assert_eq!(
            response["error"]["code"], -32602,
            "{}: {response}",
            case.tool
        );
        assert!(
            response.get("result").is_none(),
            "{}: {response}",
            case.tool
        );
        assert!(!pile.exists());
    }
}

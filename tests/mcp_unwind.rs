use faculties::mcp::{Faculty, Server, Tool};
use faculties::out::Out;
use std::cell::Cell;

struct Unwinding {
    calls: Cell<usize>,
}
impl Faculty for Unwinding {
    fn tools(&self) -> &[Tool] {
        &[Tool {
            name: "test_unwind",
            description: "Synthetic ordinary unwind",
            input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
        }]
    }
    fn call(
        &self,
        _name: &str,
        _arguments: anybytes::Bytes,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        self.calls.set(self.calls.get() + 1);
        out.line("already accepted")?;
        panic!("synthetic private loader detail");
    }
}
#[test]
fn ordinary_handler_unwind_retains_partial_output_and_never_repeats_side_effects() {
    let adapter = Unwinding {
        calls: Cell::new(0),
    };
    let mut server = Server::new(&[&adapter]).unwrap();
    server.dispatch(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#.to_owned().into()).unwrap();
    server
        .dispatch(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
                .to_owned()
                .into(),
        )
        .unwrap();
    let response = server.dispatch(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test_unwind","arguments":{}}}"#.to_owned().into()).unwrap().unwrap();
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["result"]["isError"], true);
    assert_eq!(json["result"]["content"][0]["text"], "already accepted\n");
    assert!(response.contains("side effects may already exist"));
    assert!(!response.contains("synthetic private loader detail"));
    assert_eq!(adapter.calls.get(), 1);
    let ping = server
        .dispatch(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#.to_owned().into())
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ping).unwrap()["result"],
        serde_json::json!({})
    );
    assert_eq!(adapter.calls.get(), 1);
}

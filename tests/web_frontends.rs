//! Provider requests use a loopback fixture, never real credentials or services.
use faculties::mcp::{Faculty, InvalidArguments};
use faculties::out::{Out, Part};
use faculties::storage::{discover_target, initialize_signer, load_signer, open_pile_strict};
use faculties::web::{self, ApiKeys, Endpoints, Provider, Web};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread::JoinHandle;

fn provider(response: Value) -> (String, JoinHandle<(String, Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let task = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(client) => break client,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(error) => panic!("provider did not receive request: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut headers = String::new();
        let mut length = None;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            headers.push_str(&line);
        }
        let mut body = vec![0; length.unwrap()];
        reader.read_exact(&mut body).unwrap();
        let bytes = serde_json::to_vec(&response).unwrap();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).unwrap();
        stream.write_all(&bytes).unwrap();
        (headers, serde_json::from_slice(&body).unwrap())
    });
    (url, task)
}
fn configured(pile: PathBuf, key: Option<PathBuf>, base: String) -> Web {
    Web::new(pile, key)
        .with_api_keys(ApiKeys {
            tavily: Some("fixture-tavily".into()),
            exa: Some("fixture-exa".into()),
        })
        .with_endpoints(Endpoints {
            tavily: base.clone(),
            exa: base,
        })
}

#[test]
fn literal_search_roundtrips_through_native_provider_and_records_one_observation() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("web.pile");
    let key = directory.path().join("web.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let (base, task) = provider(
        json!({"results":[{"url":"https://result.test", "title":"title", "content":"summary"}]}),
    );
    let adapter = web::mcp::Web::from_operations(configured(pile.clone(), Some(key.clone()), base));
    let mut text = String::new();
    adapter
        .call(
            "web_search",
            serde_json::to_vec(&json!({"query":"@/not-a-file", "max_results":3}))
                .unwrap()
                .into(),
            &mut Out::new(&mut |part| {
                let Part::Text { text: value } = part else {
                    panic!("expected interpreted search text")
                };
                text.push_str(&value);
                Ok(())
            }),
        )
        .unwrap();
    let (headers, request) = task.join().unwrap();
    assert!(headers.starts_with("POST /search "));
    assert!(headers
        .to_lowercase()
        .contains("authorization: bearer fixture-tavily"));
    assert_eq!(request["query"], "@/not-a-file");
    assert_eq!(request["max_results"], 3);
    assert!(text.contains("provider: tavily\nquery: @/not-a-file"));
    assert!(text.contains("https://result.test"));
    let signer = load_signer(&pile, Some(&key)).unwrap();
    let mut storage = open_pile_strict(&pile).unwrap();
    let observations = discover_target(
        &mut storage,
        faculties::schemas::web::DEFAULT_SCOPE_ID,
        signer.verifying_key(),
    )
    .unwrap();
    assert_eq!(observations.commits().len(), 1);
    storage.close().unwrap();
}

#[test]
fn auto_fetch_uses_exa_and_no_record_does_not_touch_storage() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let (base, task) =
        provider(json!({"results":[{"url":"https://example.test", "text":"interpreted body"}]}));
    let adapter = web::mcp::Web::from_operations(configured(pile.clone(), None, base));
    let mut parts = Vec::new();
    adapter
        .call(
            "web_fetch",
            serde_json::to_vec(
                &json!({"url":"https://example.test", "max_characters":42, "record":false}),
            )
            .unwrap()
            .into(),
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
    let (headers, request) = task.join().unwrap();
    assert!(headers.starts_with("POST /contents "));
    assert!(headers.to_lowercase().contains("x-api-key: fixture-exa"));
    assert_eq!(request["text"]["maxCharacters"], 42);
    assert_eq!(
        parts,
        [Part::Text {
            text: "interpreted body\n".into()
        }]
    );
    assert!(!pile.exists());
}

#[test]
fn direct_fetch_needs_no_frontend_and_tavily_falls_back_to_content() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let (base, task) = provider(
        json!({"results":[{"url":"https://example.test", "raw_content":"", "content":"fallback"}]}),
    );
    let report = configured(pile.clone(), None, base)
        .fetch(Provider::Tavily, "https://example.test", 1)
        .unwrap();
    assert_eq!(report.content, "fallback");
    assert_eq!(report.provider, Provider::Tavily);
    assert!(!pile.exists());
    assert!(task.join().unwrap().0.starts_with("POST /extract "));
}

#[test]
fn failed_emission_does_not_repeat_provider_or_store_the_result() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let (base, task) = provider(json!({"results":[]}));
    let adapter = web::mcp::Web::from_operations(configured(pile.clone(), None, base));
    let error = adapter
        .call(
            "web_search",
            serde_json::to_vec(&json!({"query":"once", "provider":"exa"}))
                .unwrap()
                .into(),
            &mut Out::new(&mut |_| anyhow::bail!("emission failed")),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("emission failed"));
    task.join().unwrap();
    assert!(!pile.exists());
}

#[test]
fn invalid_requests_are_rejected_before_credentials_or_network() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("absent.pile");
    let adapter = web::mcp::Web::new(pile.clone(), None);
    assert_eq!(adapter.tools().len(), 2);
    for (tool, input) in [
        (
            "web_search",
            r#"{"query":"x","api_key":"must-not-be-a-tool-field"}"#,
        ),
        ("web_search", r#"{"query":"x","provider":"made-up"}"#),
        ("web_search", r#"{"query":"x","query":"y"}"#),
        (
            "web_fetch",
            r#"{"url":"https://example.test","max_characters":-1}"#,
        ),
        ("web_fetch", "[]"),
    ] {
        let error = adapter
            .call(
                tool,
                input.to_owned().into(),
                &mut Out::new(&mut |_| panic!("invalid input emitted")),
            )
            .unwrap_err();
        assert!(
            error.downcast_ref::<InvalidArguments>().is_some(),
            "{error:#}"
        );
        assert!(!pile.exists());
    }
    let debug = format!("{:?}", configured(pile, None, "http://127.0.0.1".into()));
    assert!(!debug.contains("fixture-tavily"));
    assert!(!debug.contains("fixture-exa"));
}

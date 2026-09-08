//! LinkedIn's external export format and the one explicit finite network boundary.
//! This adapter owns upstream field names; neither the native model nor MCP
//! arguments inherit the snapshot's JSON grammar.
use super::operations::Connection;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

const SNAPSHOT_BASE: &str = "https://api.linkedin.com/rest/memberSnapshotData";

#[derive(Deserialize, Default)]
struct ExportConnection {
    #[serde(rename = "First Name", default)]
    first_name: String,
    #[serde(rename = "Last Name", default)]
    last_name: String,
    #[serde(rename = "Company", default)]
    company: String,
    #[serde(rename = "Position", default)]
    position: String,
    #[serde(rename = "URL", default)]
    profile_url: String,
    #[serde(rename = "Email Address", default)]
    email: String,
}
impl From<ExportConnection> for Connection {
    fn from(value: ExportConnection) -> Self {
        Self {
            first_name: value.first_name,
            last_name: value.last_name,
            company: value.company,
            position: value.position,
            profile_url: value.profile_url,
            email: value.email,
        }
    }
}

/// Decode a resident LinkedIn CONNECTIONS export array. Unknown upstream
/// metadata is ignored, as in the original importer; this is not the MCP schema.
pub fn parse_snapshot(bytes: &[u8]) -> Result<Vec<Connection>> {
    let rows: Vec<ExportConnection> =
        serde_json::from_slice(bytes).context("parse snapshot JSON")?;
    Ok(rows.into_iter().map(Connection::from).collect())
}

#[derive(Debug)]
pub(super) struct FetchedSnapshot {
    pub connections: Vec<Connection>,
    pub notices: Vec<String>,
}
struct Page {
    status: reqwest::StatusCode,
    body: String,
}

fn snapshot_url(domain: &str, start: u32) -> reqwest::Url {
    let mut url = reqwest::Url::parse(SNAPSHOT_BASE).expect("fixed LinkedIn snapshot URL");
    url.query_pairs_mut()
        .append_pair("q", "criteria")
        .append_pair("domain", domain)
        .append_pair("start", &start.to_string());
    url
}

/// Production errors are scrubbed at the credential boundary, including
/// upstream error bodies that might echo an Authorization value.
pub(super) fn fetch_snapshot(
    token: &str,
    domain: &str,
    api_version: &str,
) -> Result<FetchedSnapshot> {
    if token.trim().is_empty()
        || reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).is_err()
    {
        bail!("LinkedIn token must be a nonempty HTTP header value");
    }
    let result = (|| {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("create LinkedIn HTTP client")?;
        fetch_snapshot_pages(
            |start| {
                let response = client
                    .get(snapshot_url(domain, start))
                    .bearer_auth(token)
                    .header("Linkedin-Version", api_version)
                    .header("Content-Type", "application/json")
                    .send()
                    .with_context(|| format!("request LinkedIn {domain} start={start}"))?;
                let status = response.status();
                let body = response.text().context("read LinkedIn snapshot response")?;
                let body = redact_error_body(status, body, token);
                Ok(Page { status, body })
            },
            || std::thread::sleep(std::time::Duration::from_millis(300)),
        )
    })();
    result.map_err(|error| redact_error(error, token))
}

fn redact_error(error: anyhow::Error, token: &str) -> anyhow::Error {
    anyhow!(format!("{error:#}").replace(token, "[redacted]"))
}

fn redact_error_body(status: reqwest::StatusCode, body: String, token: &str) -> String {
    // Redact before bounding a diagnostic: truncating first could retain only
    // a token prefix, which whole-token replacement can no longer recognize.
    if status.is_success() {
        body
    } else {
        body.replace(token, "[redacted]")
    }
}

fn body_preview(body: &str) -> &str {
    let mut end = body.len().min(300);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

/// Source seam for fixture tests: page numbers are generated locally; neither
/// a server-supplied next URL nor an MCP argument can redirect the credentials.
fn fetch_snapshot_pages(
    mut fetch: impl FnMut(u32) -> Result<Page>,
    mut pace: impl FnMut(),
) -> Result<FetchedSnapshot> {
    let mut connections = Vec::new();
    let mut notices = Vec::new();
    let mut start = 0u32;
    loop {
        let Page { status, body } = fetch(start)?;
        if status.as_u16() == 404 || body.contains("No data found") {
            break;
        }
        if !status.is_success() {
            bail!(
                "LinkedIn API {status} at start={start}: {}",
                body_preview(&body)
            );
        }
        let value: serde_json::Value =
            serde_json::from_str(&body).with_context(|| format!("parse page {start}"))?;
        for element in value["elements"].as_array().into_iter().flatten() {
            for item in element["snapshotData"].as_array().into_iter().flatten() {
                match serde_json::from_value::<ExportConnection>(item.clone()) {
                    Ok(connection) => connections.push(connection.into()),
                    Err(error) => {
                        notices.push(format!("[linkedin] skip malformed record: {error}"))
                    }
                }
            }
        }
        let has_next = value["paging"]["links"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|link| link["rel"] == "next");
        if !has_next {
            break;
        }
        start = start
            .checked_add(1)
            .ok_or_else(|| anyhow!("LinkedIn snapshot page count overflow"))?;
        pace();
    }
    Ok(FetchedSnapshot {
        connections,
        notices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn export_format_is_separate_from_resident_connection_values() {
        let rows = parse_snapshot(br#"[{"First Name":"@-","Last Name":"Literal","Company":"@/host/path","URL":"https://linkedin.com/in/literal/","Email Address":"Ada@example.test","Extra metadata":7}]"#).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].first_name, "@-");
        assert_eq!(rows[0].company, "@/host/path");
        assert!(parse_snapshot(br#"[{"First Name":42}]"#).is_err());
    }

    #[test]
    fn pagination_uses_local_indices_and_keeps_malformed_record_notices() {
        let mut starts = Vec::new();
        let mut pauses = 0;
        let result = fetch_snapshot_pages(|start| {
            starts.push(start);
            let body = match start {
                0 => json!({
                    "elements":[{"snapshotData":[{"First Name":"Ada"},{"First Name":42}]}],
                    "paging":{"links":[{"rel":"next","href":"https://not-the-service.invalid/"}]}
                }),
                1 => json!({"elements":[{"snapshotData":[{"First Name":"Grace"}]}],"paging":{"links":[]}}),
                _ => panic!("unexpected page"),
            }.to_string();
            Ok(Page { status: reqwest::StatusCode::OK, body })
        }, || pauses += 1).unwrap();
        assert_eq!(starts, [0, 1]);
        assert_eq!(pauses, 1);
        assert_eq!(result.connections.len(), 2);
        assert_eq!(result.connections[0].first_name, "Ada");
        assert_eq!(result.connections[1].first_name, "Grace");
        assert_eq!(result.notices.len(), 1);
        assert!(result.notices[0].contains("skip malformed record"));
    }

    #[test]
    fn missing_domain_terminates_and_non_ascii_api_error_is_bounded() {
        for (status, body) in [
            (reqwest::StatusCode::NOT_FOUND, "missing".to_owned()),
            (reqwest::StatusCode::OK, "No data found".to_owned()),
        ] {
            let result = fetch_snapshot_pages(
                |_| {
                    Ok(Page {
                        status,
                        body: body.clone(),
                    })
                },
                || panic!("no next page"),
            )
            .unwrap();
            assert!(result.connections.is_empty());
        }
        let body = "é".repeat(200);
        let error = fetch_snapshot_pages(
            |_| {
                Ok(Page {
                    status: reqwest::StatusCode::BAD_REQUEST,
                    body: body.clone(),
                })
            },
            || panic!("no next page"),
        )
        .unwrap_err();
        assert!(error.to_string().contains(&"é".repeat(150)));
        assert!(!error.to_string().contains(&"é".repeat(151)));
    }

    #[test]
    fn query_values_cannot_inject_parameters_and_errors_redact_token() {
        let url = snapshot_url("CONNECTIONS&start=99#secret", 4);
        assert_eq!(url.host_str(), Some("api.linkedin.com"));
        assert_eq!(url.fragment(), None);
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[1].1, "CONNECTIONS&start=99#secret");
        assert_eq!(pairs[2].1, "4");
        let error = redact_error(anyhow!("upstream echoed token-fixture"), "token-fixture");
        assert!(!error.to_string().contains("token-fixture"));
        assert!(error.to_string().contains("[redacted]"));
        let body = redact_error_body(
            reqwest::StatusCode::BAD_REQUEST,
            format!("{}token-fixture-crossing-preview-boundary", "x".repeat(290)),
            "token-fixture-crossing-preview-boundary",
        );
        assert!(!body_preview(&body).contains("token-"));
        assert!(body_preview(&body).contains("[redacted]"));
    }
}

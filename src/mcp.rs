//! A finite, local stdio MCP boundary over explicit faculty MCP adapters.
//!
//! This implements MCP 2025-06-18 initialization, ping, tool discovery and
//! calls. Each faculty supplies its own tool schemas and decodes its arguments
//! before calling shared library operations. No CLI grammar, process, or stdout
//! parser is involved. Results are emitted as native Parts.
//!
//! Dispatch is deliberately blocking and sequential. Register finite commands,
//! not watchers such as `orient wait`. A future asynchronous frontend must run
//! native handlers at its blocking-work boundary (for example `spawn_blocking`)
//! and construct Out there; this adapter supplies no async runtime or workers.
//! Handler allocation/computation is outside the transport budget. The adapter
//! bounds incoming frames, JSON nesting, and encoded responses, including media
//! expansion. It closes the transport on an oversized frame rather than trying
//! to identify or reply to a possibly truncated notification.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{BufRead, Write};

use anybytes::Bytes;
use anyhow::{anyhow, bail, Result};
use base64::Engine as _;
use serde::de::DeserializeOwned;
use triblespace::core::import::scanner as sc;

use crate::archive_source::{canonical_json_string as quote, string};
use crate::out::{Out, Part};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
const ERROR_RESERVE: usize = 2048;

/// An explicit MCP tool, independent of any CLI declaration. The input schema
/// is a JSON object with `type: "object"`; it is checked and compacted once when
/// a server registers this tool. Argument validation belongs to the adapter.
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: &'static str,
}

/// A faculty's MCP entrypoint. Store trusted launcher configuration in the
/// implementing value, not among caller-supplied arguments. Decode and validate
/// all arguments before performing an operation or emitting output.
pub trait Faculty {
    fn tools(&self) -> &[Tool];
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()>;
}

/// Typed argument-decoding failure, reported as JSON-RPC invalid params rather
/// than as a failed tool operation. An anyhow context preserves this marker.
#[derive(Debug)]
pub struct InvalidArguments(serde_json::Error);

impl std::fmt::Display for InvalidArguments {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Invalid tool arguments: {}", self.0)
    }
}

impl std::error::Error for InvalidArguments {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Decode the original argument bytes directly into an MCP-specific type. Use
/// `#[serde(deny_unknown_fields)]` on argument structs (including nested ones):
/// serde then rejects unknown fields, duplicates, and incorrect types before
/// the adapter calls its library operations. Deserializing through a JSON map
/// first would silently erase duplicate fields and must be avoided.
pub fn decode_arguments<T: DeserializeOwned>(bytes: Bytes) -> Result<T> {
    serde_json::from_slice(bytes.as_ref()).map_err(|error| InvalidArguments(error).into())
}

/// Mark a semantic constraint failure detected by an MCP adapter before it
/// invokes an operation (for example, an invalid recipient byte budget).
pub fn invalid_arguments(message: impl std::fmt::Display) -> anyhow::Error {
    InvalidArguments(<serde_json::Error as serde::de::Error>::custom(message)).into()
}

struct RegisteredTool<'a> {
    name: &'static str,
    descriptor: String,
    faculty: &'a dyn Faculty,
}

/// Wire budgets, excluding the newline delimiter. Defaults permit modest
/// inline media while keeping one request/result bounded in this local server.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub json_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_bytes: 1024 * 1024,
            response_bytes: 8 * 1024 * 1024,
            json_depth: 64,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    New,
    AwaitingInitialized,
    Ready,
}

/// One stdio connection. Only tools are advertised; there are no server-side
/// requests, subscriptions, task execution, or tool-list change notifications.
pub struct Server<'a> {
    tools: Vec<RegisteredTool<'a>>,
    limits: Limits,
    state: State,
}

impl<'a> Server<'a> {
    pub fn new(faculties: &[&'a dyn Faculty]) -> Result<Self> {
        Self::with_limits(faculties, Limits::default())
    }

    pub fn with_limits(faculties: &[&'a dyn Faculty], limits: Limits) -> Result<Self> {
        if limits.request_bytes == 0 || limits.response_bytes < 4096 || limits.json_depth == 0 {
            bail!("MCP requires a positive input/depth budget and at least 4096 output bytes");
        }
        // The scanner is recursive; configuration must not undo the stack bound.
        if limits.json_depth > 64 {
            bail!("MCP JSON nesting limit cannot exceed 64");
        }
        let mut names = BTreeSet::new();
        let mut tools = Vec::new();
        for &faculty in faculties {
            for tool in faculty.tools() {
                if !names.insert(tool.name) {
                    bail!("duplicate MCP tool name {:?}", tool.name);
                }
                tools.push(RegisteredTool {
                    name: tool.name,
                    descriptor: tool_descriptor(tool)?,
                    faculty,
                });
            }
        }
        Ok(Self {
            tools,
            limits,
            state: State::New,
        })
    }

    /// Serve newline-delimited messages until EOF. Nothing except JSON-RPC
    /// responses is written to `output`; each response is flushed promptly.
    pub fn serve(&mut self, mut input: impl BufRead, mut output: impl Write) -> Result<()> {
        loop {
            let Some(line) = read_frame(&mut input, self.limits.request_bytes)? else {
                return Ok(());
            };
            if let Some(response) = self.dispatch(Bytes::from(line))? {
                output.write_all(response.as_bytes())?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
    }

    /// Dispatch one complete frame without its delimiter. Notifications and
    /// unsolicited responses produce None. Resource-limit errors are fatal to
    /// this transport; ordinary JSON-RPC errors are encoded response messages.
    pub fn dispatch(&mut self, bytes: Bytes) -> Result<Option<String>> {
        if bytes.len() > self.limits.request_bytes {
            bail!("MCP request exceeds {} bytes", self.limits.request_bytes);
        }
        let request = match envelope(bytes, self.limits.json_depth) {
            Ok(request) => request,
            Err(error) => return self.error("null", error.code, &error.message).map(Some),
        };

        // We never send requests, so unsolicited responses have no destination.
        // In particular, never generate a response-to-response loop.
        if request.method.is_none() && request.response {
            return Ok(None);
        }
        let notification = request.id.is_none() && request.method.is_some();
        let version = request.version.and_then(|value| decoded(value).ok());
        let method = request.method.and_then(|value| decoded(value).ok());
        if notification {
            if !request.duplicate
                && !request.response
                && version.as_deref() == Some("2.0")
                && method.as_deref() == Some("notifications/initialized")
                && request.params.as_ref().is_none_or(is_object)
                && self.state == State::AwaitingInitialized
            {
                self.state = State::Ready;
            }
            // Even call-shaped notifications can never invoke a native handler.
            return Ok(None);
        }

        let id = match request.id.and_then(|value| request_id(value).ok()) {
            Some(id) if !request.duplicate => id,
            _ => {
                return self
                    .error("null", -32600, "Invalid request ID or envelope")
                    .map(Some)
            }
        };
        // Reserve enough space to echo the ID and return a bounded tool error.
        if id.len()
            > self
                .limits
                .response_bytes
                .saturating_sub(ERROR_RESERVE + 256)
        {
            bail!("MCP request ID does not fit the response budget");
        }
        if request.response || version.as_deref() != Some("2.0") || method.is_none() {
            return self
                .error(&id, -32600, "Invalid JSON-RPC request")
                .map(Some);
        }
        if request
            .params
            .as_ref()
            .is_some_and(|value| !is_object(value))
        {
            return self
                .error(&id, -32602, "params must be an object")
                .map(Some);
        }
        let method = method.expect("checked above");
        let result = match method.as_str() {
            "initialize" => self.initialize(request.params),
            "ping" => Ok("{}".to_owned()),
            "tools/list" | "tools/call" if self.state != State::Ready => {
                Err(RpcError::new(-32000, "MCP initialization is not complete"))
            }
            "tools/list" => self.list(request.params, self.result_budget(&id)),
            "tools/call" => self.call(request.params, self.result_budget(&id)),
            _ => Err(RpcError::new(-32601, "Method not found")),
        };
        match result {
            Ok(result) => self.result(&id, &result).map(Some),
            Err(error) => self.error(&id, error.code, &error.message).map(Some),
        }
    }

    fn initialize(&mut self, params: Option<Bytes>) -> std::result::Result<String, RpcError> {
        if self.state != State::New {
            return Err(RpcError::new(-32600, "MCP is already initialized"));
        }
        let params = fields::<3>(
            required_params(params)?,
            ["protocolVersion", "capabilities", "clientInfo"],
        )?;
        let _requested_version = required_string(params[0].clone(), "protocolVersion")?;
        if !params[1].as_ref().is_some_and(is_object) {
            return Err(RpcError::params("capabilities must be an object"));
        }
        let client_info = params[2]
            .clone()
            .ok_or_else(|| RpcError::params("clientInfo is required"))?;
        let client = fields::<2>(client_info, ["name", "version"])?;
        required_string(client[0].clone(), "clientInfo.name")?;
        required_string(client[1].clone(), "clientInfo.version")?;
        // If the client's version is unsupported, MCP negotiation returns a
        // supported version; the client decides whether it can continue.
        self.state = State::AwaitingInitialized;
        Ok(format!(
            "{{\"protocolVersion\":{},\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"faculties\",\"version\":{}}}}}",
            quote(PROTOCOL_VERSION), quote(crate::GIT_VERSION)
        ))
    }

    fn list(&self, params: Option<Bytes>, budget: usize) -> std::result::Result<String, RpcError> {
        if let Some(params) = params {
            let cursor = fields::<1>(params, ["cursor"])?;
            if cursor[0].is_some() {
                return Err(RpcError::params(
                    "This tool list has no continuation cursor",
                ));
            }
        }
        let mut result = String::from("{\"tools\":[");
        let mut first = true;
        for tool in &self.tools {
            let additional = tool.descriptor.len() + usize::from(!first) + 2;
            if additional > budget.saturating_sub(result.len()) {
                return Err(RpcError::new(
                    -32603,
                    "Tool list exceeds the response budget",
                ));
            }
            if !first {
                result.push(',');
            }
            first = false;
            result.push_str(&tool.descriptor);
        }
        result.push_str("]}");
        Ok(result)
    }

    fn call(&self, params: Option<Bytes>, budget: usize) -> std::result::Result<String, RpcError> {
        let params = fields::<2>(required_params(params)?, ["name", "arguments"])?;
        let name = required_string(params[0].clone(), "name")?;
        let tool = self
            .tools
            .iter()
            .find(|tool| name == tool.name)
            .ok_or_else(|| RpcError::params("Unknown tool"))?;
        let arguments = params[1]
            .clone()
            .unwrap_or_else(|| Bytes::from(b"{}".to_vec()));
        if !is_object(&arguments) {
            return Err(RpcError::params("arguments must be an object"));
        }

        let mut content = String::new();
        let content_budget = budget.saturating_sub(ERROR_RESERVE + 64);
        let mut rejected = false;
        let result = {
            let mut emit = |part| {
                if rejected {
                    bail!("MCP output emission previously failed");
                }
                let separator = usize::from(!content.is_empty());
                match encode_part(
                    part,
                    content_budget.saturating_sub(content.len() + separator),
                ) {
                    Ok(encoded) => {
                        if separator != 0 {
                            content.push(',');
                        }
                        content.push_str(&encoded);
                        Ok(())
                    }
                    Err(error) => {
                        rejected = true;
                        Err(error)
                    }
                }
            };
            tool.faculty
                .call(&name, arguments, &mut Out::new(&mut emit))
        };
        if let Err(error) = &result {
            if error.is::<InvalidArguments>() {
                return Err(RpcError::params(&brief(error)));
            }
        }
        let failed = result.is_err() || rejected;
        if failed {
            let message = if rejected {
                "MCP output exceeded the response budget".to_owned()
            } else {
                brief(&result.expect_err("failed invocation"))
            };
            let error_part = encode_part(Part::Text { text: message }, ERROR_RESERVE)
                .expect("bounded diagnostic fits its reserved space");
            if !content.is_empty() {
                content.push(',');
            }
            content.push_str(&error_part);
        }
        Ok(format!("{{\"content\":[{content}],\"isError\":{failed}}}"))
    }

    fn result_budget(&self, id: &str) -> usize {
        self.limits.response_bytes.saturating_sub(id.len() + 64)
    }

    fn result(&self, id: &str, result: &str) -> Result<String> {
        let response = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}");
        if response.len() > self.limits.response_bytes {
            bail!("MCP response exceeds the output budget");
        }
        Ok(response)
    }

    fn error(&self, id: &str, code: i32, message: &str) -> Result<String> {
        let message = quote(message);
        let response = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":{message}}}}}");
        if response.len() > self.limits.response_bytes {
            bail!("MCP error response exceeds the output budget");
        }
        Ok(response)
    }
}

fn read_frame(input: &mut impl BufRead, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            bail!("MCP input ended before the newline delimiter");
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.unwrap_or(available.len());
        // One trailing CR is allowed for a CRLF delimiter.
        if length > limit.saturating_add(1).saturating_sub(frame.len()) {
            bail!("MCP request exceeds {limit} bytes");
        }
        frame.extend_from_slice(&available[..length]);
        input.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            if frame.len() > limit {
                bail!("MCP request exceeds {limit} bytes");
            }
            return Ok(Some(frame));
        }
    }
}

struct RpcError {
    code: i32,
    message: String,
}

impl RpcError {
    fn new(code: i32, message: &str) -> Self {
        Self {
            code,
            message: message.to_owned(),
        }
    }

    fn params(message: &str) -> Self {
        Self::new(-32602, message)
    }
}

#[derive(Default)]
struct Envelope {
    version: Option<Bytes>,
    id: Option<Bytes>,
    method: Option<Bytes>,
    params: Option<Bytes>,
    response: bool,
    duplicate: bool,
}

fn envelope(mut bytes: Bytes, depth_limit: usize) -> std::result::Result<Envelope, RpcError> {
    let invalid = || RpcError::new(-32700, "Parse error");
    std::str::from_utf8(bytes.as_ref()).map_err(|_| invalid())?;
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    // The scanner's recursive skipper is safe only after this non-recursive
    // bound. It ignores brackets inside strings, including escaped quotes.
    for byte in bytes.iter().copied() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > depth_limit {
                        return Err(RpcError::new(
                            -32700,
                            "JSON nesting exceeds the input limit",
                        ));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                b'\n' | b'\r' => return Err(invalid()),
                _ => {}
            }
        }
    }
    sc::skip_ws(&mut bytes);
    let raw = sc::take_value(&mut bytes).map_err(|_| invalid())?;
    sc::skip_ws(&mut bytes);
    if !bytes.is_empty() {
        return Err(invalid());
    }
    if !is_object(&raw) {
        return Err(RpcError::new(
            -32600,
            "Expected one JSON-RPC object; batches are unsupported",
        ));
    }
    sc::object(
        &mut raw.clone(),
        Envelope::default(),
        |mut envelope, key, value| {
            let key = key
                .view::<str>()
                .map_err(|_| sc::ScanError::Syntax("invalid key".into()))?;
            let slot = match key.as_ref() {
                "jsonrpc" => Some(&mut envelope.version),
                "id" => Some(&mut envelope.id),
                "method" => Some(&mut envelope.method),
                "params" => Some(&mut envelope.params),
                "result" | "error" => {
                    envelope.response = true;
                    None
                }
                _ => None,
            };
            if let Some(slot) = slot {
                envelope.duplicate |= slot.replace(sc::take_value(value)?).is_some();
            } else {
                sc::skip_value(value)?;
            }
            Ok(envelope)
        },
    )
    .map_err(|_| invalid())
}

fn is_object(value: &Bytes) -> bool {
    value.first() == Some(&b'{')
}

fn decoded(mut value: Bytes) -> std::result::Result<String, sc::ScanError> {
    let text = string(&mut value)?;
    if !value.is_empty() {
        return Err(sc::ScanError::Syntax("trailing string data".into()));
    }
    Ok(text.as_ref().to_owned())
}

fn request_id(value: Bytes) -> Result<String> {
    if value.first() == Some(&b'"') {
        decoded(value.clone())?;
    } else {
        let mut number = value.clone();
        sc::parse_number(&mut number)?;
        if !number.is_empty() || value.iter().any(|byte| matches!(*byte, b'.' | b'e' | b'E')) {
            bail!("MCP IDs must be strings or integers");
        }
    }
    // Echo the raw, already-validated spelling; never round integer IDs through
    // floating point or truncate them to a machine-sized integer.
    Ok(std::str::from_utf8(value.as_ref())?.to_owned())
}

fn required_params(params: Option<Bytes>) -> std::result::Result<Bytes, RpcError> {
    params.ok_or_else(|| RpcError::params("params are required"))
}

fn required_string(value: Option<Bytes>, name: &str) -> std::result::Result<String, RpcError> {
    value
        .and_then(|value| decoded(value).ok())
        .ok_or_else(|| RpcError::params(&format!("{name} must be a string")))
}

/// Project only the requested fields; unknown protocol extensions are skipped.
fn fields<const N: usize>(
    mut bytes: Bytes,
    names: [&str; N],
) -> std::result::Result<[Option<Bytes>; N], RpcError> {
    sc::object(
        &mut bytes,
        std::array::from_fn(|_| None),
        |mut fields, key, value| {
            let key = key
                .view::<str>()
                .map_err(|_| sc::ScanError::Syntax("invalid key".into()))?;
            if let Some(index) = names.iter().position(|name| *name == key.as_ref()) {
                if fields[index].replace(sc::take_value(value)?).is_some() {
                    return Err(sc::ScanError::Syntax("duplicate parameter".into()));
                }
            } else {
                sc::skip_value(value)?;
            }
            Ok(fields)
        },
    )
    .map_err(|_| RpcError::params("Expected an object without duplicate parameters"))
}

fn tool_descriptor(tool: &Tool) -> Result<String> {
    let schema: serde_json::Value = serde_json::from_str(tool.input_schema)
        .map_err(|error| anyhow!("invalid input schema for MCP tool {:?}: {error}", tool.name))?;
    if !schema.is_object()
        || schema.get("type").and_then(serde_json::Value::as_str) != Some("object")
    {
        bail!(
            "input schema for MCP tool {:?} must declare type object",
            tool.name
        );
    }
    // Compact at registration, not on every tools/list. Literal newlines in a
    // readable schema must never introduce extra newline-delimited wire frames.
    Ok(serde_json::to_string(&serde_json::json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": schema,
    }))?)
}

fn quoted_len(value: &str) -> usize {
    value.bytes().fold(2_usize, |length, byte| {
        length.saturating_add(match byte {
            b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
            0..=0x1f => 6,
            _ => 1,
        })
    })
}

fn encode_part(part: Part, budget: usize) -> Result<String> {
    match part {
        Part::Text { text } => {
            if quoted_len(&text).saturating_add(23) > budget {
                bail!("MCP text output exceeds the response budget");
            }
            Ok(format!("{{\"type\":\"text\",\"text\":{}}}", quote(&text)))
        }
        Part::Image { bytes, mime_type } => encode_media("image", bytes, mime_type, budget),
        Part::Audio { bytes, mime_type } => encode_media("audio", bytes, mime_type, budget),
        Part::Blob {
            bytes,
            mime_type,
            uri,
        } => {
            let encoded_len = bytes
                .len()
                .checked_add(2)
                .and_then(|length| (length / 3).checked_mul(4))
                .ok_or_else(|| anyhow!("MCP blob length overflow"))?;
            let overhead = r#"{"type":"resource","resource":{"uri":,"mimeType":,"blob":""}}"#.len();
            if encoded_len
                .saturating_add(quoted_len(&uri))
                .saturating_add(quoted_len(&mime_type))
                .saturating_add(overhead)
                > budget
            {
                bail!("MCP blob output exceeds the response budget");
            }
            let data = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
            Ok(format!(
                "{{\"type\":\"resource\",\"resource\":{{\"uri\":{},\"mimeType\":{},\"blob\":\"{data}\"}}}}",
                quote(&uri),
                quote(&mime_type),
            ))
        }
    }
}

fn encode_media(kind: &str, bytes: Bytes, mime_type: String, budget: usize) -> Result<String> {
    let encoded_len = bytes
        .len()
        .checked_add(2)
        .and_then(|length| (length / 3).checked_mul(4))
        .ok_or_else(|| anyhow!("MCP media length overflow"))?;
    if encoded_len
        .saturating_add(quoted_len(&mime_type))
        .saturating_add(43)
        > budget
    {
        bail!("MCP media output exceeds the response budget");
    }
    let data = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
    Ok(format!(
        "{{\"type\":\"{kind}\",\"data\":\"{data}\",\"mimeType\":{}}}",
        quote(&mime_type)
    ))
}

fn brief(error: &anyhow::Error) -> String {
    struct Truncated(String);
    impl std::fmt::Write for Truncated {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let remaining = 256_usize.saturating_sub(self.0.len());
            let mut end = remaining.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            if end < text.len() {
                Err(std::fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut message = Truncated(String::new());
    let _ = write!(&mut message, "{error:#}");
    message.0
}

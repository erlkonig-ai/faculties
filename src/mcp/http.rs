//! Streamable HTTP (MCP 2025-06-18) for one launcher-owned faculty context.
//!
//! POST returns the same bounded native JSON-RPC output as stdio; accepted
//! notifications return 202. GET returns 405 (no standalone SSE stream), and
//! DELETE closes a transport session. There is no event replay or automatic
//! retry. Losing an HTTP connection does not cancel an admitted operation.
//!
//! Native adapters can be blocking and need not be Send/Sync. They execute
//! sequentially on the calling thread, outside the dedicated HTTP I/O runtime.
//! A bounded channel connects the two; admission includes body reads, queued
//! work and running work, including work whose client has disconnected.
//!
//! This is an authenticated internal hop, not another OAuth server. A hosting
//! edge (such as Playground) must authenticate the user and select that user's
//! fixed worker/pile/key before forwarding. Do not switch process environment
//! or trust a caller-supplied tenant/path. Even loopback needs authentication:
//! some jail deployments share the parent's network stack. TLS and public
//! OAuth discovery belong to the existing hosting edge.

use std::collections::HashMap;
use std::future::Future;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::any, Router};
use rand_core::RngCore;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use super::{decoded, envelope, Faculty, Limits, Server, PROTOCOL_VERSION};

const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";

/// Only a constant-time-comparable digest is retained; never printed or
/// included in discovery. Use an independently generated random token for
/// each worker, not a colleague's public OAuth access token or signing key.
#[derive(Clone)]
pub struct BearerToken(blake3::Hash);

impl BearerToken {
    pub fn new(token: &str) -> Result<Self> {
        if !(32..=1024).contains(&token.len())
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            bail!("MCP HTTP token must contain 32..=1024 ASCII bearer-token characters");
        }
        Ok(Self(blake3::hash(token.as_bytes())))
    }

    /// Bounded read; permits one ordinary final LF/CRLF. The plaintext buffer
    /// is zeroized on every return path. File permissions are launcher-owned.
    pub fn from_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).context("open MCP HTTP token file")?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(1027)
            .read_to_end(&mut bytes)
            .context("read MCP HTTP token file")?;
        let text = std::str::from_utf8(&bytes).context("MCP HTTP token file must be UTF-8")?;
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        Self::new(text)
    }

    fn accepts(&self, value: &str) -> bool {
        // blake3::Hash equality uses constant_time_eq_32, also for bad lengths.
        self.0 == blake3::hash(value.as_bytes())
    }
}

pub struct Config {
    pub bind: SocketAddr,
    pub token: BearerToken,
    /// Exact serialized origins, e.g. https://mcp.example.com (no final slash).
    /// Absent Origin is allowed for server-to-server clients. Every present
    /// Origin must be allowed; no CORS or wildcard access is installed.
    pub allowed_origins: Vec<String>,
    pub limits: Limits,
    pub max_sessions: usize,
    pub session_idle_timeout: Duration,
    pub max_requests: usize,
    pub body_timeout: Duration,
}

impl Config {
    pub fn new(bind: SocketAddr, token: BearerToken) -> Self {
        Self {
            bind,
            token,
            allowed_origins: Vec::new(),
            limits: Limits::default(),
            max_sessions: 64,
            session_idle_timeout: Duration::from_secs(30 * 60),
            max_requests: 16,
            body_timeout: Duration::from_secs(30),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_sessions == 0
            || self.max_requests == 0
            || self.max_requests > Semaphore::MAX_PERMITS
            || self.session_idle_timeout.is_zero()
            || self.body_timeout.is_zero()
        {
            bail!("MCP HTTP session/admission limits and timeouts must be positive");
        }
        Server::with_limits(&[], self.limits)?;
        for origin in &self.allowed_origins {
            let parsed = reqwest::Url::parse(origin).context("parse allowed MCP HTTP origin")?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.origin().ascii_serialization() != *origin
            {
                bail!("MCP HTTP origins must be exact HTTP(S) origins without paths or wildcards");
            }
        }
        Ok(())
    }
}

/// Bind separately from serving so embedders/tests can select an OS-assigned
/// port, inspect its address, and supply their own shutdown signal.
pub struct Endpoint {
    listener: TcpListener,
    config: Config,
}

impl Endpoint {
    pub fn bind(config: Config) -> Result<Self> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind).context("bind MCP HTTP listener")?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("read MCP HTTP listening address")
    }

    pub fn serve(self, faculties: &[&dyn Faculty]) -> Result<()> {
        self.serve_until(faculties, shutdown_signal())
    }

    /// Graceful shutdown stops accepting connections and drains admitted work.
    /// Native calls are not forcibly interruptible; effects may already exist.
    /// Invoke outside a Tokio runtime, as for the blocking stdio frontend.
    pub fn serve_until(
        self,
        faculties: &[&dyn Faculty],
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        Server::with_limits(faculties, self.config.limits)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("create MCP HTTP I/O runtime")?;
        let (tx, mut rx) = mpsc::channel(self.config.max_requests);
        let state = Arc::new(HttpState {
            token: self.config.token,
            origins: self.config.allowed_origins,
            body_timeout: self.config.body_timeout,
            response_bytes: self.config.limits.response_bytes,
            admission: Arc::new(Semaphore::new(self.config.max_requests)),
            tx,
        });
        let app = Router::new()
            .route("/", any(handle))
            .layer(DefaultBodyLimit::max(self.config.limits.request_bytes))
            .with_state(state);
        let mut worker = Worker {
            faculties: faculties.to_vec(),
            limits: self.config.limits,
            sessions: HashMap::new(),
            max_sessions: self.config.max_sessions,
            idle_timeout: self.config.session_idle_timeout,
        };
        std::thread::scope(|scope| {
            let io = scope.spawn(move || {
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(self.listener)?;
                    axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown)
                        .await
                        .context("serve MCP HTTP")
                })
            });
            while let Some(work) = rx.blocking_recv() {
                // A closed reply receiver is not cancellation. Never skip or
                // repeat an admitted write because the HTTP client went away.
                let response = worker.dispatch(work.command, work.session);
                let _ = work.reply.send((response, work.admission));
            }
            io.join()
                .map_err(|_| anyhow::anyhow!("MCP HTTP I/O thread panicked"))?
        })
    }
}

pub fn serve(faculties: &[&dyn Faculty], config: Config) -> Result<()> {
    let endpoint = Endpoint::bind(config)?;
    eprintln!("faculties MCP HTTP: http://{}/ (authenticated internal hop; public TLS/OAuth belong to the hosting edge)", endpoint.local_addr()?);
    endpoint.serve(faculties)
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = interrupt => {}, _ = terminate => {} }
}

struct HttpState {
    token: BearerToken,
    origins: Vec<String>,
    body_timeout: Duration,
    response_bytes: usize,
    admission: Arc<Semaphore>,
    tx: mpsc::Sender<Work>,
}

enum Command {
    Post(anybytes::Bytes),
    Get,
    Delete,
}

struct Work {
    command: Command,
    session: Option<String>,
    reply: oneshot::Sender<(Response, OwnedSemaphorePermit)>,
    admission: OwnedSemaphorePermit,
}

async fn handle(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let mut response = handle_request(state, request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn handle_request(state: Arc<HttpState>, request: Request) -> Response {
    let headers = request.headers();
    match single_header(headers, header::ORIGIN.as_str()) {
        Ok(None) => {}
        Ok(Some(origin)) if state.origins.iter().any(|allowed| allowed == origin) => {}
        _ => return error(StatusCode::FORBIDDEN, "Origin is not allowed"),
    }
    let authorized = single_header(headers, header::AUTHORIZATION.as_str())
        .ok()
        .flatten()
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("Bearer")
                && state.token.accepts(token.trim_start_matches(' '))
        });
    if !authorized {
        let mut response = error(
            StatusCode::UNAUTHORIZED,
            "MCP HTTP bearer authentication required",
        );
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }
    match single_header(headers, VERSION_HEADER) {
        Ok(None) | Ok(Some(PROTOCOL_VERSION)) => {}
        _ => return error(StatusCode::BAD_REQUEST, "Unsupported MCP-Protocol-Version"),
    }
    let session = match single_header(headers, SESSION_HEADER) {
        Ok(None) => None,
        Ok(Some(value))
            if !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|b| (0x21..=0x7e).contains(&b)) =>
        {
            Some(value.to_owned())
        }
        _ => return error(StatusCode::BAD_REQUEST, "Invalid Mcp-Session-Id header"),
    };
    let method = request.method().clone();
    if method != Method::POST && method != Method::GET && method != Method::DELETE {
        return method_not_allowed();
    }
    if method == Method::POST {
        let json = single_header(headers, header::CONTENT_TYPE.as_str())
            .ok()
            .flatten()
            .and_then(|value| value.parse::<mime::Mime>().ok())
            .is_some_and(|value| value.essence_str() == "application/json");
        if !json
            || !matches!(
                single_header(headers, header::CONTENT_ENCODING.as_str()),
                Ok(None) | Ok(Some("identity"))
            )
        {
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "MCP POST requires uncompressed application/json",
            );
        }
        if !accepts(headers, "application/json") || !accepts(headers, "text/event-stream") {
            return error(
                StatusCode::NOT_ACCEPTABLE,
                "MCP POST Accept must include application/json and text/event-stream",
            );
        }
    }
    let admission = match state.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "MCP HTTP admission limit reached; request was not dispatched",
            )
        }
    };
    let command = if method == Method::POST {
        let body = match tokio::time::timeout(state.body_timeout, Bytes::from_request(request, &()))
            .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(rejection)) => return rejection.into_response(),
            Err(_) => {
                return error(
                    StatusCode::REQUEST_TIMEOUT,
                    "MCP HTTP request body timed out",
                )
            }
        };
        Command::Post(body.to_vec().into())
    } else if method == Method::GET {
        Command::Get
    } else {
        Command::Delete
    };
    let (reply, response) = oneshot::channel();
    if state
        .tx
        .try_send(Work {
            command,
            session,
            reply,
            admission,
        })
        .is_err()
    {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP HTTP worker is unavailable; request was not dispatched",
        );
    }
    match response.await {
        Ok((response, admission)) => {
            let (parts, body) = response.into_parts();
            // Worker responses are bounded, resident bodies. Carry admission
            // in the Bytes owner so it lasts through slow socket writes and
            // clones of the outgoing frame, not just until this handler returns.
            let bytes = match to_bytes(body, state.response_bytes).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "MCP HTTP response exceeded transport limits",
                    )
                }
            };
            let bytes = Bytes::from_owner(AdmittedBody {
                bytes,
                _admission: admission,
            });
            Response::from_parts(parts, Body::from(bytes))
        }
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP HTTP worker stopped; operation outcome may be unknown; it was not retried",
        ),
    }
}

struct AdmittedBody {
    bytes: Bytes,
    _admission: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for AdmittedBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> std::result::Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()
}

fn accepts(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.trim().parse::<mime::Mime>().ok())
        .any(|value| {
            value.essence_str() == expected
                && value.get_param("q").is_none_or(|q| {
                    q.as_str()
                        .parse::<f32>()
                        .is_ok_and(|q| q.is_finite() && q > 0.0 && q <= 1.0)
                })
        })
}

struct Session<'a> {
    rpc: Server<'a>,
    touched: Instant,
}

struct Worker<'a> {
    faculties: Vec<&'a dyn Faculty>,
    limits: Limits,
    sessions: HashMap<String, Session<'a>>,
    max_sessions: usize,
    idle_timeout: Duration,
}

impl Worker<'_> {
    fn dispatch(&mut self, command: Command, session_id: Option<String>) -> Response {
        let now = Instant::now();
        self.sessions
            .retain(|_, session| now.duration_since(session.touched) < self.idle_timeout);
        if let Some(id) = &session_id {
            if !self.sessions.contains_key(id) {
                return error(
                    StatusCode::NOT_FOUND,
                    "MCP session is unknown or expired; initialize a new session",
                );
            }
        }
        match command {
            Command::Get => method_not_allowed(),
            Command::Delete => match session_id {
                Some(id) => {
                    self.sessions.remove(&id);
                    StatusCode::NO_CONTENT.into_response()
                }
                None => error(StatusCode::BAD_REQUEST, "Mcp-Session-Id is required"),
            },
            Command::Post(bytes) => {
                if let Some(id) = session_id {
                    let session = self.sessions.get_mut(&id).expect("validated above");
                    let response = session.rpc.dispatch(bytes);
                    session.touched = Instant::now();
                    match response {
                        Ok(response) => rpc_response(response),
                        Err(_) => {
                            self.sessions.remove(&id);
                            error(
                                StatusCode::BAD_REQUEST,
                                "MCP request exceeded protocol limits; initialize a new session",
                            )
                        }
                    }
                } else {
                    self.initialize(bytes)
                }
            }
        }
    }

    fn initialize(&mut self, bytes: anybytes::Bytes) -> Response {
        let frame = match envelope(bytes.clone(), self.limits.json_depth) {
            Ok(frame) => frame,
            Err(_) => return error(StatusCode::BAD_REQUEST, "Invalid JSON-RPC message"),
        };
        if frame
            .method
            .and_then(|method| decoded(method).ok())
            .as_deref()
            != Some("initialize")
        {
            return error(
                StatusCode::BAD_REQUEST,
                "Mcp-Session-Id is required after initialization",
            );
        }
        if self.sessions.len() >= self.max_sessions {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "MCP session limit reached; close or expire an existing session",
            );
        }
        let mut rpc = match Server::with_limits(&self.faculties, self.limits) {
            Ok(rpc) => rpc,
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "MCP registry is unavailable",
                )
            }
        };
        let response = match rpc.dispatch(bytes) {
            Ok(response) => response,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "MCP initialization exceeded protocol limits",
                )
            }
        };
        let mut response = rpc_response(response);
        // Invalid params/envelopes and notifications never reserve sessions.
        if rpc.state == super::State::AwaitingInitialized {
            let id = loop {
                let mut entropy = [0_u8; 32];
                if rand_core::OsRng.try_fill_bytes(&mut entropy).is_err() {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Could not allocate MCP session identity",
                    );
                }
                let id = hex::encode(entropy);
                if !self.sessions.contains_key(&id) {
                    break id;
                }
            };
            response.headers_mut().insert(
                SESSION_HEADER,
                HeaderValue::from_str(&id).expect("hex header"),
            );
            self.sessions.insert(
                id,
                Session {
                    rpc,
                    touched: Instant::now(),
                },
            );
        }
        response
    }
}

fn rpc_response(response: Option<String>) -> Response {
    match response {
        Some(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "error": message }).to_string(),
    )
        .into_response()
}

fn method_not_allowed() -> Response {
    let mut response = error(
        StatusCode::METHOD_NOT_ALLOWED,
        "No standalone SSE stream; use POST or DELETE",
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "unit-test-only-token-0123456789abcdef";

    #[test]
    fn bearer_file_is_bounded_and_accepts_only_one_final_line_ending() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("http.token");
        for ending in ["", "\n", "\r\n"] {
            std::fs::write(&path, format!("{TOKEN}{ending}")).unwrap();
            let token = BearerToken::from_file(&path).unwrap();
            assert!(token.accepts(TOKEN));
            assert!(!token.accepts("different-token-0123456789abcdef"));
        }
        for invalid in [
            "short".to_owned(),
            format!("{TOKEN}\n\n"),
            format!(" {TOKEN}"),
            "x".repeat(4096),
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(BearerToken::from_file(&path).is_err());
        }
        std::fs::write(&path, [0xff; 32]).unwrap();
        assert!(BearerToken::from_file(&path).is_err());
    }

    #[test]
    fn output_admission_lives_with_every_clone_of_the_outgoing_bytes() {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let bytes = Bytes::from_owner(AdmittedBody {
            bytes: Bytes::from_static(b"native-response"),
            _admission: permit,
        });
        let outgoing = bytes.clone();
        drop(bytes);
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(&outgoing[..], b"native-response");
        drop(outgoing);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[test]
    fn invalid_configuration_fails_before_binding() {
        let config = || {
            Config::new(
                "127.0.0.1:0".parse().unwrap(),
                BearerToken::new(TOKEN).unwrap(),
            )
        };
        for origin in [
            "*",
            "null",
            "https://example.test/",
            "https://example.test/path",
            "file:///tmp",
        ] {
            let mut candidate = config();
            candidate.allowed_origins.push(origin.into());
            assert!(Endpoint::bind(candidate).is_err());
        }
        let mut candidate = config();
        candidate.max_requests = usize::MAX;
        assert!(Endpoint::bind(candidate).is_err());
        let mut candidate = config();
        candidate.max_sessions = 0;
        assert!(Endpoint::bind(candidate).is_err());
        let mut candidate = config();
        candidate.body_timeout = Duration::ZERO;
        assert!(Endpoint::bind(candidate).is_err());
    }

    #[test]
    fn stdio_still_rejects_embedded_carriage_returns_at_its_framing_boundary() {
        let mut server = Server::new(&[]).unwrap();
        let mut output = Vec::new();
        let input = std::io::Cursor::new(b"{\r\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        assert!(server.serve(input, &mut output).is_err());
        assert!(output.is_empty());
    }
}

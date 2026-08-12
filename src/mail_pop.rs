//! Small, synchronous, octet-safe POP3 transport.
//!
//! POP message numbers are valid only for the current account session.  A
//! [`PopItem`] therefore carries both that ephemeral number and the stable,
//! maildrop-scoped UIDL.  Deciding which account a UIDL belongs to remains the
//! caller's responsibility.
//!
//! Deletions are committed by POP only when `QUIT` succeeds.  [`PopSession::quit`]
//! is consequently explicit and consuming.  Merely dropping a session closes
//! its transport and deliberately emits no protocol command.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};

/// A message named by a POP account session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PopItem {
    /// The ephemeral message number assigned by this POP session.
    pub session_seq: u32,
    /// The case-sensitive, maildrop-scoped unique-id listing returned by POP.
    pub uidl: String,
}

/// The text following a successful `+OK` response, represented as protocol
/// octets rather than assuming UTF-8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositiveResponse(Vec<u8>);

impl PositiveResponse {
    /// Return the response text after `+OK` and its optional separating space.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Failure from the POP transport.
#[derive(Debug)]
pub enum PopError {
    /// The underlying stream failed.
    Io(io::Error),
    /// TLS setup or transport failed.
    Tls(rustls::Error),
    /// The configured host is not a valid TLS server name.
    InvalidServerName,
    /// No usable native trust anchor could be loaded.
    NoTrustAnchors,
    /// A credential could inject an additional POP command.
    InvalidCredential,
    /// A POP message sequence number must be non-zero.
    InvalidSequence,
    /// The server rejected a command.  The reply is intentionally omitted so
    /// even a server that echoes credentials cannot put a password in errors.
    Rejected(&'static str),
    /// The server sent a malformed or truncated protocol response.
    Protocol(&'static str),
    /// A UIDL listing repeated a session sequence number.
    DuplicateSequence(u32),
    /// A UIDL listing repeated a case-sensitive UIDL.
    DuplicateUidl(String),
}

impl fmt::Display for PopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "POP transport I/O failed: {error}"),
            Self::Tls(error) => write!(f, "POP TLS failed: {error}"),
            Self::InvalidServerName => f.write_str("invalid POP TLS server name"),
            Self::NoTrustAnchors => f.write_str("no usable native TLS trust anchors found"),
            Self::InvalidCredential => {
                f.write_str("POP credential contains a forbidden CR or LF byte")
            }
            Self::InvalidSequence => f.write_str("POP session sequence number must be non-zero"),
            Self::Rejected(command) => write!(f, "POP server rejected {command}"),
            Self::Protocol(message) => write!(f, "malformed POP response: {message}"),
            Self::DuplicateSequence(sequence) => {
                write!(f, "POP UIDL response repeats session sequence {sequence}")
            }
            Self::DuplicateUidl(uidl) => write!(f, "POP UIDL response repeats UIDL {uidl:?}"),
        }
    }
}

impl std::error::Error for PopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Tls(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PopError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustls::Error> for PopError {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}

/// A synchronous POP session over any bidirectional byte stream.
pub struct PopSession<S: Read + Write> {
    stream: BufReader<S>,
}

impl<S: Read + Write> PopSession<S> {
    /// Start a session over an established stream and consume its greeting.
    pub fn new(stream: S) -> Result<Self, PopError> {
        let mut session = Self {
            stream: BufReader::new(stream),
        };
        session.read_positive("greeting")?;
        Ok(session)
    }

    /// Authenticate with the POP `USER` and `PASS` commands.
    pub fn login(&mut self, username: &str, password: &str) -> Result<(), PopError> {
        // Validate both first: a bad password must not leave a successfully sent
        // USER command behind as a partial login attempt.
        validate_command_argument(username.as_bytes())?;
        validate_command_argument(password.as_bytes())?;

        self.single_line_command(b"USER", Some(username.as_bytes()), "USER")?;
        self.single_line_command(b"PASS", Some(password.as_bytes()), "PASS")?;
        Ok(())
    }

    /// Enumerate the current maildrop's `(session sequence, UIDL)` pairs.
    pub fn uidl(&mut self) -> Result<Vec<PopItem>, PopError> {
        self.write_command(b"UIDL", None)?;
        self.read_positive("UIDL")?;

        // Drain the complete response before validating it.  A duplicate or
        // malformed item therefore cannot leave the stream positioned halfway
        // through a multiline response.
        let lines = self.read_multiline_lines()?;
        let mut sequences = HashSet::with_capacity(lines.len());
        let mut uidls = HashSet::with_capacity(lines.len());
        let mut items = Vec::with_capacity(lines.len());

        for line in lines {
            let line = line
                .strip_suffix(b"\r\n")
                .ok_or(PopError::Protocol("UIDL item lacks CRLF"))?;
            let separator = line
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or(PopError::Protocol("UIDL item lacks separator"))?;
            let (sequence, uidl_with_space) = line.split_at(separator);
            let uidl = &uidl_with_space[1..];

            if sequence.is_empty() || !sequence.iter().all(u8::is_ascii_digit) {
                return Err(PopError::Protocol("UIDL sequence is not decimal"));
            }
            let sequence = std::str::from_utf8(sequence)
                .map_err(|_| PopError::Protocol("UIDL sequence is not ASCII"))?
                .parse::<u32>()
                .map_err(|_| PopError::Protocol("UIDL sequence is out of range"))?;
            if sequence == 0 {
                return Err(PopError::Protocol("UIDL sequence is zero"));
            }
            if uidl.is_empty() || !uidl.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
                return Err(PopError::Protocol("UIDL is not visible ASCII"));
            }
            let uidl = String::from_utf8(uidl.to_vec())
                .map_err(|_| PopError::Protocol("UIDL is not ASCII"))?;

            if !sequences.insert(sequence) {
                return Err(PopError::DuplicateSequence(sequence));
            }
            if !uidls.insert(uidl.clone()) {
                return Err(PopError::DuplicateUidl(uidl));
            }
            items.push(PopItem {
                session_seq: sequence,
                uidl,
            });
        }

        Ok(items)
    }

    /// Retrieve one RFC 5322 message exactly as POP transmits it after
    /// terminator removal and dot unstuffing.
    pub fn retr(&mut self, session_seq: u32) -> Result<Vec<u8>, PopError> {
        let sequence = checked_sequence(session_seq)?;
        self.write_command(b"RETR", Some(sequence.as_bytes()))?;
        self.read_positive("RETR")?;

        let mut message = Vec::new();
        while let Some(line) = self.read_multiline_line()? {
            message.extend_from_slice(&line);
        }
        Ok(message)
    }

    /// Mark one message for deletion in the current transaction.
    pub fn dele(&mut self, session_seq: u32) -> Result<PositiveResponse, PopError> {
        let sequence = checked_sequence(session_seq)?;
        self.single_line_command(b"DELE", Some(sequence.as_bytes()), "DELE")
    }

    /// Commit the POP transaction and close it.
    ///
    /// This is the only method that sends `QUIT`.  It consumes the session so
    /// dropping either a live session or a failed `QUIT` cannot send it again.
    pub fn quit(mut self) -> Result<PositiveResponse, PopError> {
        self.single_line_command(b"QUIT", None, "QUIT")
    }

    fn single_line_command(
        &mut self,
        command: &'static [u8],
        argument: Option<&[u8]>,
        label: &'static str,
    ) -> Result<PositiveResponse, PopError> {
        self.write_command(command, argument)?;
        self.read_positive(label)
    }

    fn write_command(
        &mut self,
        command: &'static [u8],
        argument: Option<&[u8]>,
    ) -> Result<(), PopError> {
        debug_assert!(command
            .iter()
            .all(|byte| byte.is_ascii_uppercase() && *byte != b'\r' && *byte != b'\n'));
        if let Some(argument) = argument {
            validate_command_argument(argument)?;
        }

        let stream = self.stream.get_mut();
        stream.write_all(command)?;
        if let Some(argument) = argument {
            stream.write_all(b" ")?;
            stream.write_all(argument)?;
        }
        stream.write_all(b"\r\n")?;
        stream.flush()?;
        Ok(())
    }

    fn read_positive(&mut self, command: &'static str) -> Result<PositiveResponse, PopError> {
        let line = self.read_crlf_line()?;
        let content = &line[..line.len() - 2];

        if let Some(rest) = content.strip_prefix(b"+OK") {
            return match rest {
                b"" => Ok(PositiveResponse(Vec::new())),
                [b' ', message @ ..] => Ok(PositiveResponse(message.to_vec())),
                _ => Err(PopError::Protocol("invalid +OK status boundary")),
            };
        }
        if let Some(rest) = content.strip_prefix(b"-ERR") {
            return match rest {
                b"" | [b' ', ..] => Err(PopError::Rejected(command)),
                _ => Err(PopError::Protocol("invalid -ERR status boundary")),
            };
        }
        Err(PopError::Protocol("status line is neither +OK nor -ERR"))
    }

    fn read_multiline_lines(&mut self) -> Result<Vec<Vec<u8>>, PopError> {
        let mut lines = Vec::new();
        while let Some(line) = self.read_multiline_line()? {
            lines.push(line);
        }
        Ok(lines)
    }

    fn read_multiline_line(&mut self) -> Result<Option<Vec<u8>>, PopError> {
        let mut line = self.read_crlf_line()?;
        if line == b".\r\n" {
            return Ok(None);
        }
        if line.first() == Some(&b'.') {
            // RFC 1939 dot transparency: the server inserts one leading dot;
            // remove exactly that one byte, never more.
            line.remove(0);
        }
        Ok(Some(line))
    }

    fn read_crlf_line(&mut self) -> Result<Vec<u8>, PopError> {
        let mut line = Vec::new();
        let read = self.stream.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Err(PopError::Protocol("unexpected end of stream"));
        }
        if !line.ends_with(b"\r\n") {
            return Err(PopError::Protocol("line is not CRLF-terminated"));
        }
        Ok(line)
    }
}

/// The concrete session returned by [`connect_implicit_tls`].
pub type ImplicitTlsPopSession = PopSession<StreamOwned<ClientConnection, TcpStream>>;

/// Connect to a POP server using implicit TLS and authenticate the account.
pub fn connect_implicit_tls(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<ImplicitTlsPopSession, PopError> {
    // Validate before opening a socket or writing a partial login.
    validate_command_argument(username.as_bytes())?;
    validate_command_argument(password.as_bytes())?;

    // Faculties selects rustls's ring backend.  Installation is process-global
    // and idempotent; an already selected provider is not an error here.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (usable, _) = roots.add_parsable_certificates(native.certs);
    if usable == 0 {
        return Err(PopError::NoTrustAnchors);
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| PopError::InvalidServerName)?;
    let connection = ClientConnection::new(Arc::new(config), server_name)?;
    let tcp = TcpStream::connect((host, port))?;
    let tls = StreamOwned::new(connection, tcp);

    let mut session = PopSession::new(tls)?;
    session.login(username, password)?;
    Ok(session)
}

fn validate_command_argument(argument: &[u8]) -> Result<(), PopError> {
    if argument.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(PopError::InvalidCredential);
    }
    Ok(())
}

fn checked_sequence(sequence: u32) -> Result<String, PopError> {
    if sequence == 0 {
        return Err(PopError::InvalidSequence);
    }
    Ok(sequence.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    #[derive(Clone)]
    struct WriteLog(Rc<RefCell<Vec<u8>>>);

    impl WriteLog {
        fn bytes(&self) -> Vec<u8> {
            self.0.borrow().clone()
        }
    }

    struct ScriptedStream {
        reads: Cursor<Vec<u8>>,
        writes: WriteLog,
    }

    impl ScriptedStream {
        fn new(reads: Vec<u8>) -> (Self, WriteLog) {
            let writes = WriteLog(Rc::new(RefCell::new(Vec::new())));
            (
                Self {
                    reads: Cursor::new(reads),
                    writes: writes.clone(),
                },
                writes,
            )
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.read(buffer)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.writes.0.borrow_mut().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn scripted_session(script: &[u8]) -> (PopSession<ScriptedStream>, WriteLog) {
        let (stream, writes) = ScriptedStream::new(script.to_vec());
        (PopSession::new(stream).unwrap(), writes)
    }

    #[test]
    fn retr_preserves_non_utf8_crlf_long_lines_and_unstuffs_one_dot() {
        let long_line = vec![b'x'; 16 * 1024];
        let mut script = b"+OK ready\r\n+OK message follows\r\nBinary: \xff\xfe\r\n".to_vec();
        script.extend_from_slice(&long_line);
        script.extend_from_slice(b"\r\n..one\r\n...two\r\n.\r\n");

        let (mut session, writes) = scripted_session(&script);
        let message = session.retr(42).unwrap();

        let mut expected = b"Binary: \xff\xfe\r\n".to_vec();
        expected.extend_from_slice(&long_line);
        expected.extend_from_slice(b"\r\n.one\r\n..two\r\n");
        assert_eq!(message, expected);
        assert_eq!(writes.bytes(), b"RETR 42\r\n");
    }

    #[test]
    fn multiline_terminator_must_be_exact_crlf_line() {
        let (mut session, _) = scripted_session(b"+OK\r\n+OK\r\nnot done\r\n.\n");
        assert!(matches!(
            session.retr(1),
            Err(PopError::Protocol("line is not CRLF-terminated"))
        ));
    }

    #[test]
    fn uidl_pairs_sequences_and_preserves_case() {
        let (mut session, writes) =
            scripted_session(b"+OK ready\r\n+OK listing\r\n1 AbC-123\r\n27 abc-123\r\n.\r\n");
        assert_eq!(
            session.uidl().unwrap(),
            vec![
                PopItem {
                    session_seq: 1,
                    uidl: "AbC-123".into(),
                },
                PopItem {
                    session_seq: 27,
                    uidl: "abc-123".into(),
                },
            ]
        );
        assert_eq!(writes.bytes(), b"UIDL\r\n");
    }

    #[test]
    fn uidl_duplicate_sequences_fail_closed_after_draining_response() {
        let (mut session, writes) =
            scripted_session(b"+OK\r\n+OK\r\n1 first\r\n1 second\r\n.\r\n+OK deleted\r\n");
        assert!(matches!(
            session.uidl(),
            Err(PopError::DuplicateSequence(1))
        ));
        assert!(session.dele(1).is_ok());
        assert_eq!(writes.bytes(), b"UIDL\r\nDELE 1\r\n");
    }

    #[test]
    fn uidl_duplicate_values_fail_case_sensitively() {
        let (mut session, _) = scripted_session(b"+OK\r\n+OK\r\n1 same\r\n2 same\r\n.\r\n");
        assert!(matches!(
            session.uidl(),
            Err(PopError::DuplicateUidl(uidl)) if uidl == "same"
        ));
    }

    #[test]
    fn uidl_rejects_non_visible_ascii() {
        let (mut session, _) = scripted_session(b"+OK\r\n+OK\r\n1 bad\tuid\r\n.\r\n");
        assert!(matches!(session.uidl(), Err(PopError::Protocol(_))));
    }

    #[test]
    fn dele_then_explicit_quit_has_exact_order_and_returns_responses() {
        let (mut session, writes) = scripted_session(b"+OK ready\r\n+OK marked\r\n+OK goodbye\r\n");
        assert_eq!(session.dele(7).unwrap().as_bytes(), b"marked");
        assert_eq!(session.quit().unwrap().as_bytes(), b"goodbye");
        assert_eq!(writes.bytes(), b"DELE 7\r\nQUIT\r\n");
    }

    #[test]
    fn dele_and_quit_rejections_are_command_specific_and_secret_free() {
        let (mut session, writes) = scripted_session(b"+OK\r\n-ERR cannot delete\r\n");
        let error = session.dele(3).unwrap_err();
        assert!(matches!(error, PopError::Rejected("DELE")));
        assert_eq!(writes.bytes(), b"DELE 3\r\n");
        drop(session);
        assert_eq!(writes.bytes(), b"DELE 3\r\n");

        let (session, writes) = scripted_session(b"+OK\r\n-ERR cannot quit\r\n");
        let error = session.quit().unwrap_err();
        assert!(matches!(error, PopError::Rejected("QUIT")));
        assert_eq!(writes.bytes(), b"QUIT\r\n");
    }

    #[test]
    fn login_validates_all_credentials_before_writing_and_never_echoes_password() {
        let password = "secret\r\nDELE 1";
        let (mut session, writes) = scripted_session(b"+OK\r\n");
        let error = session.login("person@example.test", password).unwrap_err();
        assert!(matches!(error, PopError::InvalidCredential));
        assert!(!error.to_string().contains("secret"));
        assert!(writes.bytes().is_empty());

        let (mut session, writes) = scripted_session(b"+OK\r\n+OK user\r\n-ERR bad password\r\n");
        let error = session
            .login("person@example.test", "very-secret")
            .unwrap_err();
        assert!(matches!(error, PopError::Rejected("PASS")));
        assert!(!error.to_string().contains("very-secret"));
        assert_eq!(
            writes.bytes(),
            b"USER person@example.test\r\nPASS very-secret\r\n"
        );
    }

    #[test]
    fn dropping_authenticated_session_never_sends_quit() {
        let (mut session, writes) = scripted_session(b"+OK\r\n+OK user\r\n+OK pass\r\n");
        session.login("user", "password").unwrap();
        drop(session);
        assert_eq!(writes.bytes(), b"USER user\r\nPASS password\r\n");
    }

    #[test]
    fn zero_sequence_never_emits_a_command() {
        let (mut session, writes) = scripted_session(b"+OK\r\n");
        assert!(matches!(session.retr(0), Err(PopError::InvalidSequence)));
        assert!(matches!(session.dele(0), Err(PopError::InvalidSequence)));
        assert!(writes.bytes().is_empty());
    }
}

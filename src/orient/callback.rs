//! The daemon CLI's single best-effort delivery boundary.
//!
//! No shell interprets the report or argv. Callback stdout is deliberately
//! discarded: the callback must deliver through its chosen transport, not a
//! second tool-output channel. Successful process exit accepts a complete
//! stdin handoff; it is not an acknowledgement that the news was handled.

use anyhow::{bail, Result};
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
pub(super) fn deliver(
    executable: &Path,
    args: &[OsString],
    timeout: Duration,
    report: &str,
) -> Result<()> {
    use anyhow::Context;
    use std::io::{ErrorKind, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    // Nonblocking stdin avoids a writer thread that could outlive its timeout
    // when an uncooperative child (or its descendant) holds the pipe open.
    // A separate process group lets timeout/error cleanup stop that subtree.
    struct OwnedChild {
        child: Child,
        accepted: bool,
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !self.accepted {
                // SAFETY: process_group(0) below creates a group owned by this
                // child; only that group's members are targeted, never ours.
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    if timeout.is_zero() {
        bail!("Orient callback timeout must be greater than zero");
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("Orient callback timeout is out of range")?;
    let child = Command::new(executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .context("could not start Orient delivery callback")?;
    let mut owned = OwnedChild {
        child,
        accepted: false,
    };
    let input = owned
        .child
        .stdin
        .take()
        .context("callback stdin is unavailable")?;
    let fd = input.as_raw_fd();
    // SAFETY: input owns a live pipe descriptor throughout both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not make callback stdin nonblocking");
    }
    let bytes = report.as_bytes();
    let mut written = 0;
    let mut input = Some(input);
    loop {
        if written == bytes.len() {
            // EOF is part of the callback protocol; do not wait for exit with
            // stdin held open even when the report is empty.
            input.take();
        }
        if let Some(status) = owned
            .child
            .try_wait()
            .context("could not observe callback exit")?
        {
            if !status.success() {
                bail!("Orient delivery callback failed ({status})");
            }
            if written != bytes.len() {
                bail!("Orient delivery callback exited before its complete input was written");
            }
            owned.accepted = true;
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            bail!("Orient delivery callback timed out");
        }
        if let Some(input) = input.as_mut() {
            match input.write(&bytes[written..]) {
                Ok(0) => bail!("Orient delivery callback stdin closed before input completed"),
                Ok(count) => {
                    written += count;
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error).context("could not write Orient callback input"),
            }
        }
        std::thread::sleep(Duration::from_millis(5).min(deadline.saturating_duration_since(now)));
    }
}

#[cfg(not(unix))]
pub(super) fn deliver(_: &Path, _: &[OsString], _: Duration, _: &str) -> Result<()> {
    bail!("Orient daemon callbacks currently require a Unix host");
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;

    fn shell(script: &str, args: &[OsString], timeout: Duration, report: &str) -> Result<()> {
        let mut argv = vec![
            OsString::from("-c"),
            OsString::from(script),
            OsString::from("callback"),
        ];
        argv.extend_from_slice(args);
        deliver(Path::new("/bin/sh"), &argv, timeout, report)
    }

    #[test]
    fn callback_accepts_exact_utf8_stdin_and_literal_argv() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("report");
        let arg_output = dir.path().join("arg");
        let report = "News: café\n'\"$(not-a-command)\\\n\n";
        shell(
            "cat > \"$1\"; printf %s \"$3\" > \"$2\"; printf 'discarded callback stdout'",
            &[
                output.clone().into_os_string(),
                arg_output.clone().into_os_string(),
                OsString::from("$(literal argument)"),
            ],
            Duration::from_secs(3),
            report,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(output).unwrap(), report);
        assert_eq!(
            std::fs::read_to_string(arg_output).unwrap(),
            "$(literal argument)"
        );
    }

    #[test]
    fn callback_nonzero_and_missing_executable_fail() {
        let error = shell(
            "cat >/dev/null; exit 7",
            &[],
            Duration::from_secs(3),
            "news",
        )
        .unwrap_err();
        assert!(error.to_string().contains("callback failed"));
        let dir = tempfile::tempdir().unwrap();
        assert!(deliver(
            &dir.path().join("missing"),
            &[],
            Duration::from_secs(1),
            "news"
        )
        .is_err());
    }

    #[test]
    fn callback_early_exit_does_not_accept_unwritten_report() {
        assert!(shell(
            "exit 0",
            &[],
            Duration::from_secs(3),
            &"x".repeat(4 * 1024 * 1024)
        )
        .is_err());
    }

    #[test]
    fn callback_timeout_bounds_blocked_stdin_and_reaps_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let started = Instant::now();
        let error = shell(
            "printf %s $$ > \"$1\"; exec sleep 20",
            &[pid_file.clone().into_os_string()],
            Duration::from_millis(300),
            &"x".repeat(4 * 1024 * 1024),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid: i32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "callback must be reaped");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn callback_timeout_also_bounds_wait_after_input_eof() {
        let started = Instant::now();
        let error = shell(
            "cat >/dev/null; exec sleep 20",
            &[],
            Duration::from_millis(100),
            "news",
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

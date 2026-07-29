//! The root secret that unlocks the `secrets` store.
//!
//! # Why this exists
//!
//! A credential store needs a root key, and the root key cannot live inside
//! the store — so something outside the pile has to hold it. Until now that
//! was `FACULTIES_SECRETS_PW` and nothing else, which forces the password
//! into a shell profile: the only place a value is reliably visible to the
//! *non-interactive* shells that `orient --persona … wait` and `mail fetch`
//! run under. (`.zshrc` is not read there; `.zshenv` is. Getting that wrong
//! yields a watcher that silently cannot fetch mail while the same command
//! works when typed by hand.)
//!
//! An environment variable is a poor container for a root secret. It is
//! inherited by *every* child process, so it lands in the environment of
//! each subagent, codex invocation, and build script the session spawns —
//! none of which need it. A file read on demand is the same exposure at
//! rest and strictly narrower in use.
//!
//! So: env first (unchanged, still the documented path), then a mode-checked
//! file. Nothing that worked before stops working.
//!
//! # The permission check is not decoration
//!
//! A root secret readable by other local users is not a secret. If the file
//! is group- or world-readable this refuses to read it and says so, rather
//! than proceeding with a credential that has already leaked. Failing loudly
//! on a bad mode is the whole value of having a dedicated path — an
//! environment variable cannot be checked this way at all.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

/// Default location, under `$XDG_CONFIG_HOME` or `~/.config`.
fn default_path() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x).join("faculties").join("secrets-pw"));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".config/faculties/secrets-pw"))
}

/// Where the password would be read from, for diagnostics.
pub fn path() -> Option<PathBuf> {
    match std::env::var("FACULTIES_SECRETS_PW_FILE") {
        Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => default_path(),
    }
}

/// Read the root secret: `FACULTIES_SECRETS_PW`, else the password file.
///
/// `what` names the caller's purpose so the error tells the operator what
/// they were trying to unlock.
pub fn read(what: &str) -> Result<Vec<u8>> {
    if let Ok(v) = std::env::var("FACULTIES_SECRETS_PW") {
        if !v.is_empty() {
            return Ok(v.into_bytes());
        }
    }

    let Some(p) = path() else {
        return Err(anyhow!(
            "set FACULTIES_SECRETS_PW to {what} (no HOME or XDG_CONFIG_HOME, so no password file either)"
        ));
    };
    if !p.exists() {
        return Err(anyhow!(
            "set FACULTIES_SECRETS_PW to {what}, or write it to {} (chmod 600)",
            p.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p)
            .with_context(|| format!("stat {}", p.display()))?
            .permissions()
            .mode()
            & 0o077;
        if mode != 0 {
            return Err(anyhow!(
                "{} is readable by group/other (mode {:03o}); refusing to use it — `chmod 600 {}`",
                p.display(),
                std::fs::metadata(&p)?.permissions().mode() & 0o777,
                p.display()
            ));
        }
    }

    let raw = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    // A password file is written by `echo`/editor as often as not, so a
    // single trailing newline is expected and must not become part of the
    // key — that failure mode is a wrong-password error with no hint.
    let mut v = raw;
    while matches!(v.last(), Some(b'\n') | Some(b'\r')) {
        v.pop();
    }
    if v.is_empty() {
        return Err(anyhow!("{} is empty", p.display()));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests mutate PROCESS-GLOBAL environment variables, and Rust
    /// runs tests in parallel threads by default — so without serializing
    /// them one test's `set_var` races another's `remove_var` and the suite
    /// passes or fails on timing. A green run under a race is not evidence.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A trailing newline must not become part of the key. Writing the file
    /// with `echo` is the common case, and the resulting failure is an
    /// indistinguishable "wrong password".
    #[test]
    fn trailing_newline_is_stripped() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("fac-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("secrets-pw");
        std::fs::write(&f, b"hunter2\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::env::remove_var("FACULTIES_SECRETS_PW");
        std::env::set_var("FACULTIES_SECRETS_PW_FILE", &f);
        assert_eq!(read("test").unwrap(), b"hunter2".to_vec());
        std::env::remove_var("FACULTIES_SECRETS_PW_FILE");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A world-readable root secret is not a secret; reading it anyway would
    /// hide the leak behind a working command.
    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_is_refused() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fac-pw-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("secrets-pw");
        std::fs::write(&f, b"hunter2").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::env::remove_var("FACULTIES_SECRETS_PW");
        std::env::set_var("FACULTIES_SECRETS_PW_FILE", &f);
        let e = read("test").unwrap_err().to_string();
        assert!(e.contains("group/other"), "expected a mode complaint, got: {e}");
        std::env::remove_var("FACULTIES_SECRETS_PW_FILE");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The env var keeps precedence — nothing that worked before changes.
    #[test]
    fn env_wins_over_file() {
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FACULTIES_SECRETS_PW", "from-env");
        std::env::set_var("FACULTIES_SECRETS_PW_FILE", "/nonexistent/nope");
        assert_eq!(read("test").unwrap(), b"from-env".to_vec());
        std::env::remove_var("FACULTIES_SECRETS_PW");
        std::env::remove_var("FACULTIES_SECRETS_PW_FILE");
    }
}

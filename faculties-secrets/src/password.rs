//! Loading the root password that unlocks the secrets store.
//!
//! The password cannot live in the store it unlocks. An environment variable
//! remains supported for ephemeral use, while a mode-checked file avoids
//! exporting the root secret to every child process.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

pub const PASSWORD_ENV: &str = "FACULTIES_SECRETS_PW";
pub const PASSWORD_FILE_ENV: &str = "FACULTIES_SECRETS_PW_FILE";

fn default_path() -> Option<PathBuf> {
    if let Ok(root) = std::env::var("XDG_CONFIG_HOME") {
        if !root.is_empty() {
            return Some(PathBuf::from(root).join("faculties/secrets-pw"));
        }
    }

    std::env::var("HOME")
        .ok()
        .filter(|root| !root.is_empty())
        .map(|root| PathBuf::from(root).join(".config/faculties/secrets-pw"))
}

/// The configured password-file path, including the platform default.
pub fn path() -> Option<PathBuf> {
    match std::env::var(PASSWORD_FILE_ENV) {
        Ok(path) if !path.is_empty() => Some(PathBuf::from(path)),
        _ => default_path(),
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "{} is readable by group or others (mode {mode:03o}); refusing to use it — chmod 600 {}",
                path.display(),
                path.display()
            ));
        }
    }

    let mut password = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    while matches!(password.last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    if password.is_empty() {
        return Err(anyhow!("{} is empty", path.display()));
    }
    Ok(password)
}

/// Read the root password from `FACULTIES_SECRETS_PW`, then from the
/// configured/default password file.
///
/// `purpose` is included in configuration errors so a non-interactive caller
/// says what it was trying to unlock.
pub fn read(purpose: &str) -> Result<Vec<u8>> {
    if let Ok(password) = std::env::var(PASSWORD_ENV) {
        if !password.is_empty() {
            return Ok(password.into_bytes());
        }
    }

    let Some(path) = path() else {
        return Err(anyhow!(
            "set {PASSWORD_ENV} to {purpose}; no HOME or XDG_CONFIG_HOME is available for a password file"
        ));
    };
    if !path.exists() {
        return Err(anyhow!(
            "set {PASSWORD_ENV} to {purpose}, or write it to {} and chmod 600 it",
            path.display()
        ));
    }
    read_file(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_line_endings_from_password_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets-pw");
        std::fs::write(&path, b"correct horse battery staple\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert_eq!(read_file(&path).unwrap(), b"correct horse battery staple");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_or_world_readable_password_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets-pw");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let error = read_file(&path).unwrap_err().to_string();
        assert!(error.contains("readable by group or others"), "{error}");
    }
}

//! Single-instance service lease shared by the server and the reset commands.
//!
//! The server holds an exclusive advisory lock on `<data_dir>/sito.pid` for its
//! whole lifetime and writes its PID into the file for diagnostics. The file
//! name makes the purpose obvious to operators, but the *lock* (not the file's
//! existence) is authoritative: a stale file left by a crash is harmless and
//! does not block a reset.
//!
//! `reset-admin` and `reset-sessions` inspect this lease before touching disk.
//! An advisory lock works across containers that share the data volume and
//! cannot be fooled by a recycled PID, unlike a bare pidfile.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Name of the service lease inside `server.data_dir`.
pub const SERVICE_LOCK_FILE: &str = "sito.pid";

/// Whether a server currently holds the lease for a data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// The lease is held by a live server. `pid` is `None` when the holder has
    /// not finished writing its PID yet (startup race) or the file is empty.
    Running { pid: Option<u32> },
    /// No process holds the lease. A leftover `sito.pid` file is stale.
    Stopped,
}

/// Held by the running server for its entire lifetime.
#[derive(Debug)]
pub struct ServiceLease {
    file: File,
    path: PathBuf,
}

impl ServiceLease {
    /// Acquires the exclusive service lease for `data_dir`.
    ///
    /// Returns an error with [`io::ErrorKind::WouldBlock`] when another process
    /// (or another server instance in this process) already holds it.
    pub fn acquire(data_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(SERVICE_LOCK_FILE);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "another sito server already holds the service lease '{}'",
                        path.display()
                    ),
                ));
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }

        // Only overwrite the PID after the lock is ours: another instance's
        // PID must never be replaced by a failed contender.
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", std::process::id())?;
        file.flush()?;
        Ok(Self { file, path })
    }
}

impl Drop for ServiceLease {
    fn drop(&mut self) {
        // Keep holding the lock while removing the path so a successor cannot
        // lock the old inode and then have it unlinked underneath it.
        let _ = std::fs::remove_file(&self.path);
        let _ = self.file.unlock();
    }
}

/// Reports whether a server is running for `data_dir` without disturbing it.
///
/// IO errors other than a missing lease file are propagated so callers can
/// fail closed instead of assuming the service is stopped.
pub fn status(data_dir: &Path) -> io::Result<ServiceStatus> {
    let path = data_dir.join(SERVICE_LOCK_FILE);
    let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ServiceStatus::Stopped),
        Err(e) => return Err(e),
    };

    match file.try_lock() {
        // We got the lock, so nobody is serving. Drop releases it immediately.
        Ok(()) => Ok(ServiceStatus::Stopped),
        Err(TryLockError::WouldBlock) => {
            let mut raw = String::new();
            let pid = file
                .seek(SeekFrom::Start(0))
                .and_then(|_| file.read_to_string(&mut raw))
                .ok()
                .and_then(|_| raw.trim().parse::<u32>().ok());
            Ok(ServiceStatus::Running { pid })
        }
        Err(TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito_service_lock_{label}_{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lease_detects_running_and_stopped() {
        let dir = temp_dir("status");
        assert_eq!(status(&dir).unwrap(), ServiceStatus::Stopped);

        let lease = ServiceLease::acquire(&dir).unwrap();
        assert_eq!(
            status(&dir).unwrap(),
            ServiceStatus::Running {
                pid: Some(std::process::id())
            }
        );

        drop(lease);
        assert_eq!(status(&dir).unwrap(), ServiceStatus::Stopped);
        assert!(
            !dir.join(SERVICE_LOCK_FILE).exists(),
            "graceful release removes the lease file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_pidfile_without_lock_does_not_look_running() {
        let dir = temp_dir("stale");
        std::fs::write(dir.join(SERVICE_LOCK_FILE), "999999\n").unwrap();
        assert_eq!(status(&dir).unwrap(), ServiceStatus::Stopped);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_lease_is_refused() {
        let dir = temp_dir("second");
        let _lease = ServiceLease::acquire(&dir).unwrap();
        let err = ServiceLease::acquire(&dir).expect_err("second lease must fail");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

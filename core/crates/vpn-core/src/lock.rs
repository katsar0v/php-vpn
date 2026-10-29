//! Cross-process lock per WireGuard key.
//!
//! The server keeps one session and one endpoint per peer key, so two
//! processes using the same key at the same time would keep replacing each
//! other's session. Every request therefore holds an exclusive `flock()` on a
//! file named after the key pair. The kernel drops the lock when the process
//! dies, so a killed worker cannot wedge it.
//!
//! The file also records which tunnel instance performed the last handshake:
//! if it is not ours, another process has replaced our session and we must
//! handshake again.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::WgConfig;
use crate::error::{Error, Result};

const MAGIC: &[u8; 4] = b"PVL2";
const RECORD_LEN: usize = 20;

/// What the lock file says about the key's current session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Record {
    /// Tunnel instance that performed the last handshake.
    pub instance: u64,
    /// When that handshake completed.
    pub handshake_at: SystemTime,
}

pub(crate) struct KeyLock {
    file: File,
}

impl KeyLock {
    pub fn path(dir: &Path, name: &str) -> PathBuf {
        dir.join(format!("php-vpn-{name}.lock"))
    }

    /// Takes the lock if it is free; `Ok(None)` if another process holds it.
    pub fn try_acquire(dir: &Path, name: &str) -> Result<Option<Self>> {
        let path = Self::path(dir, name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o660)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| {
                Error::config(format!(
                    "cannot open lock file `{}` (php_vpn.lock_dir must be writable by every process using this profile): {e}",
                    path.display()
                ))
            })?;
        // Group-writable whatever the creator's umask, so processes of the same
        // group (e.g. root and www-data in a setgid directory) can share it.
        // Only the owner may change the mode; for others it is already set.
        // SAFETY: fchmod on a valid, owned file descriptor.
        unsafe { libc::fchmod(file.as_raw_fd(), 0o660) };
        // SAFETY: flock on a valid, owned file descriptor.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(Self { file }));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            Err(Error::internal(format!(
                "cannot lock `{}`: {err}",
                path.display()
            )))
        }
    }

    pub fn record(&self) -> Option<Record> {
        let mut buf = [0u8; RECORD_LEN];
        self.file.read_exact_at(&mut buf, 0).ok()?;
        if &buf[..4] != MAGIC {
            return None;
        }
        let instance = u64::from_le_bytes(buf[4..12].try_into().ok()?);
        let nanos = u64::from_le_bytes(buf[12..20].try_into().ok()?);
        Some(Record {
            instance,
            handshake_at: UNIX_EPOCH + Duration::from_nanos(nanos),
        })
    }

    /// Records that `instance` has just completed a handshake.
    pub fn record_handshake(&self, instance: u64) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut buf = [0u8; RECORD_LEN];
        buf[..4].copy_from_slice(MAGIC);
        buf[4..12].copy_from_slice(&instance.to_le_bytes());
        buf[12..20].copy_from_slice(&nanos.to_le_bytes());
        // Losing the record only costs an extra handshake next time.
        let _ = self.file.write_all_at(&buf, 0);
    }
}

impl Drop for KeyLock {
    fn drop(&mut self) {
        // SAFETY: unlocking our own descriptor; closing would release it anyway.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Locks one profile of `members`, starting at `start` and rotating, waiting
/// until `deadline` if all are busy.
pub(crate) fn acquire(
    members: &[Arc<WgConfig>],
    dir: &Path,
    start: usize,
    deadline: Instant,
) -> Result<(usize, KeyLock)> {
    let n = members.len();
    let mut backoff = Duration::from_millis(2);
    loop {
        for i in 0..n {
            let idx = (start + i) % n;
            if let Some(lock) = KeyLock::try_acquire(dir, &members[idx].lock_name())? {
                return Ok((idx, lock));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::lock_timeout(if n == 1 {
                "the WireGuard profile is in use by another PHP process and did not become free within the connect timeout".to_string()
            } else {
                format!(
                    "all {n} WireGuard profiles of the pool are in use by other PHP processes and none became free within the connect timeout"
                )
            }));
        }
        std::thread::sleep(backoff.min(deadline - now));
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_and_records() {
        let dir = tempfile::tempdir().unwrap();
        let a = KeyLock::try_acquire(dir.path(), "k").unwrap().unwrap();
        // flock is per open file description, so a second open conflicts even
        // inside the same process (as it would in another process).
        assert!(KeyLock::try_acquire(dir.path(), "k").unwrap().is_none());
        assert!(KeyLock::try_acquire(dir.path(), "other").unwrap().is_some());
        assert_eq!(a.record(), None);
        a.record_handshake(42);
        drop(a);
        let b = KeyLock::try_acquire(dir.path(), "k").unwrap().unwrap();
        let r = b.record().unwrap();
        assert_eq!(r.instance, 42);
        assert!(r.handshake_at.elapsed().unwrap() < Duration::from_secs(5));
    }

    #[test]
    fn lock_files_are_group_writable_despite_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: setting the process umask for this test only.
        let old = unsafe { libc::umask(0o077) };
        let lock = KeyLock::try_acquire(dir.path(), "u").unwrap().unwrap();
        unsafe { libc::umask(old) };
        let mode = std::fs::metadata(KeyLock::path(dir.path(), "u"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o660);
        drop(lock);
    }

    #[test]
    fn refuses_symlinked_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, KeyLock::path(dir.path(), "s")).unwrap();
        assert!(KeyLock::try_acquire(dir.path(), "s").is_err());
    }
}

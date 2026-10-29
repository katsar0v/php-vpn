//! Public entry points: profiles, the per-process tunnel registry and
//! `request()`.
//!
//! State is per process and created lazily, so nothing exists in a PHP-FPM or
//! Apache master before it forks. A process that finds state created by a
//! different PID (it was forked after using a tunnel) abandons it without
//! touching the parent's sockets.

use std::cell::{Cell, RefCell};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

use crate::config::{WgConfig, MAX_CONFIG_BYTES};
use crate::error::{Error, ErrorKind, Result};
use crate::http::{self, RequestSpec, Response};
use crate::lock;
use crate::secret::encode_key;
use crate::tunnel::Tunnel;

pub const MAX_POOL_SIZE: usize = 64;

/// WireGuard servers drop a handshake initiation that arrives within 20 ms of
/// the previous one for the same key (flood protection), so a process taking
/// over a key waits this long after the last handshake.
const HANDSHAKE_GAP: Duration = Duration::from_millis(30);

/// Process-wide settings (php.ini).
#[derive(Debug, Clone)]
pub struct Settings {
    /// Directory for the per-key lock files; the system temp dir when `None`.
    pub lock_dir: Option<PathBuf>,
    /// Sessions older than this are replaced by a fresh handshake.
    pub session_ttl: Duration,
    /// Tunnels kept open per process (least recently used are closed first).
    pub max_tunnels: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lock_dir: None,
            session_ttl: Duration::from_secs(120),
            max_tunnels: 4,
        }
    }
}

/// One WireGuard profile, or a pool of them used in rotation.
#[derive(Clone, Debug)]
pub struct Profile {
    members: Arc<[Arc<WgConfig>]>,
}

/// Non-secret description of a profile.
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub endpoint: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub mtu: u16,
    pub public_key: String,
    pub peer_public_key: String,
    /// Age of the session in this process, if one is established.
    pub session_age: Option<Duration>,
}

impl Profile {
    pub fn from_text(text: &str) -> Result<Self> {
        let cfg = WgConfig::parse(text)?;
        Ok(Self {
            members: Arc::from(vec![Arc::new(cfg)]),
        })
    }

    /// Reads a profile file. With `enforce_permissions`, files readable or
    /// writable by "other" users are refused because they hold a private key.
    pub fn from_file(path: &Path, enforce_permissions: bool) -> Result<Self> {
        let shown = path.display();
        let mut file = OpenOptions::new()
            .read(true)
            // Non-blocking so that a FIFO cannot hang the caller; regular
            // files are refused below anyway.
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| Error::config(format!("cannot open WireGuard profile `{shown}`: {e}")))?;
        let meta = file
            .metadata()
            .map_err(|e| Error::config(format!("cannot stat WireGuard profile `{shown}`: {e}")))?;
        if !meta.is_file() {
            return Err(Error::config(format!(
                "WireGuard profile `{shown}` is not a regular file"
            )));
        }
        if meta.len() > MAX_CONFIG_BYTES as u64 {
            return Err(Error::config(format!(
                "WireGuard profile `{shown}` is larger than {MAX_CONFIG_BYTES} bytes"
            )));
        }
        if enforce_permissions && meta.mode() & 0o007 != 0 {
            return Err(Error::config(format!(
                "WireGuard profile `{shown}` is accessible by all users (mode {:04o}); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)",
                meta.mode() & 0o7777
            )));
        }
        let mut text = Zeroizing::new(String::new());
        file.read_to_string(&mut text)
            .map_err(|e| Error::config(format!("cannot read WireGuard profile `{shown}`: {e}")))?;
        Self::from_text(&text)
    }

    pub fn pool(parts: &[Profile]) -> Result<Self> {
        let members: Vec<Arc<WgConfig>> = parts
            .iter()
            .flat_map(|p| p.members.iter().cloned())
            .collect();
        if members.is_empty() {
            return Err(Error::config("a pool needs at least one profile"));
        }
        if members.len() > MAX_POOL_SIZE {
            return Err(Error::config(format!(
                "a pool can hold at most {MAX_POOL_SIZE} profiles"
            )));
        }
        let mut names: Vec<String> = members.iter().map(|m| m.lock_name()).collect();
        names.sort();
        names.dedup();
        if names.len() != members.len() {
            return Err(Error::config(
                "a pool contains the same WireGuard key twice; each member needs its own key pair",
            ));
        }
        Ok(Self {
            members: Arc::from(members),
        })
    }

    pub fn members(&self) -> &[Arc<WgConfig>] {
        &self.members
    }

    pub fn info(&self) -> Vec<ProfileInfo> {
        self.members
            .iter()
            .map(|m| ProfileInfo {
                endpoint: m.peer.endpoint.to_string(),
                addresses: m.addresses.iter().map(|a| a.to_string()).collect(),
                dns: m.dns.iter().map(|d| d.to_string()).collect(),
                allowed_ips: m.peer.allowed_ips.iter().map(|a| a.to_string()).collect(),
                mtu: m.mtu,
                public_key: encode_key(&m.public_key),
                peer_public_key: encode_key(&m.peer.public_key),
                session_age: session_age(m),
            })
            .collect()
    }
}

struct Entry {
    tunnel: Tunnel,
    last_used: Instant,
}

struct Process {
    pid: u32,
    rt: tokio::runtime::Runtime,
    tunnels: Vec<Entry>,
}

thread_local! {
    static PROCESS: RefCell<Option<Process>> = const { RefCell::new(None) };
    static ROTATION: Cell<usize> = const { Cell::new(0) };
}

fn with_process<R>(f: impl FnOnce(&mut Process) -> Result<R>) -> Result<R> {
    PROCESS.with(|cell| {
        let mut slot = cell
            .try_borrow_mut()
            .map_err(|_| Error::internal("php-vpn was re-entered during a request"))?;
        let pid = std::process::id();
        if slot.as_ref().is_some_and(|p| p.pid != pid) {
            // Forked after using a tunnel: the runtime's epoll instance and the
            // sockets are shared with the parent. Leak them instead of tearing
            // down state the parent still uses.
            std::mem::forget(slot.take());
        }
        if slot.is_none() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| Error::internal(format!("cannot create the I/O runtime: {e}")))?;
            *slot = Some(Process {
                pid,
                rt,
                tunnels: Vec::new(),
            });
        }
        f(slot.as_mut().expect("process state initialised"))
    })
}

impl Process {
    fn tunnel_index(&mut self, config: &Arc<WgConfig>, max: usize) -> Result<usize> {
        if let Some(i) = self
            .tunnels
            .iter()
            .position(|e| e.tunnel.config().fingerprint() == config.fingerprint())
        {
            self.tunnels[i].last_used = Instant::now();
            return Ok(i);
        }
        if self.tunnels.len() >= max.max(1) {
            let lru = self
                .tunnels
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
                .expect("non-empty");
            self.tunnels.remove(lru);
        }
        let _guard = self.rt.enter();
        let tunnel = Tunnel::new(Arc::clone(config))?;
        self.tunnels.push(Entry {
            tunnel,
            last_used: Instant::now(),
        });
        Ok(self.tunnels.len() - 1)
    }
}

fn session_age(config: &WgConfig) -> Option<Duration> {
    PROCESS.with(|cell| {
        let slot = cell.try_borrow().ok()?;
        let p = slot.as_ref().filter(|p| p.pid == std::process::id())?;
        p.tunnels
            .iter()
            .find(|e| e.tunnel.config().fingerprint() == config.fingerprint())
            .and_then(|e| e.tunnel.session_age())
    })
}

/// Sends one HTTP(S) request (following redirects) through the profile.
/// Fails closed: every error is returned, nothing is retried outside the tunnel.
pub fn request(profile: &Profile, spec: &RequestSpec, settings: &Settings) -> Result<Response> {
    let prepared = http::prepare(spec)?;
    if spec.timeout.is_zero() || spec.connect_timeout.is_zero() {
        return Err(Error::config("timeouts must be greater than zero"));
    }
    let started = Instant::now();
    let connect_deadline = started + spec.connect_timeout.min(spec.timeout);
    let total_deadline = started + spec.timeout;

    let members = profile.members();
    let start = ROTATION.with(|r| {
        let v = r.get();
        r.set(v.wrapping_add(1));
        v
    }) % members.len();
    let lock_dir = settings.lock_dir.clone().unwrap_or_else(std::env::temp_dir);
    let (idx, key_lock) = lock::acquire(members, &lock_dir, start, connect_deadline)?;
    let config = &members[idx];

    with_process(|p| {
        let i = p.tunnel_index(config, settings.max_tunnels)?;
        {
            let tunnel = &mut p.tunnels[i].tunnel;
            let record = key_lock.record();
            let fresh = tunnel
                .session_age()
                .is_some_and(|age| age < settings.session_ttl);
            if !fresh || record.map(|r| r.instance) != Some(tunnel.instance()) {
                tunnel.reset_session();
                let since =
                    record.and_then(|r| SystemTime::now().duration_since(r.handshake_at).ok());
                if let Some(since) = since.filter(|s| *s < HANDSHAKE_GAP) {
                    std::thread::sleep(HANDSHAKE_GAP - since);
                }
            }
        }
        let tunnel = &p.tunnels[i].tunnel;
        let _guard = p.rt.enter();
        let connect_at = tokio::time::Instant::from_std(connect_deadline);
        let total_at = tokio::time::Instant::from_std(total_deadline);
        let result = p.rt.block_on(tunnel.run(async {
            let work = async {
                tunnel.ensure_session(connect_at).await?;
                key_lock.record_handshake(tunnel.instance());
                http::execute(tunnel, spec, prepared, connect_at).await
            };
            match tokio::time::timeout_at(total_at, work).await {
                Ok(r) => r,
                Err(_) => Err(http::timeout_error(spec)),
            }
        }));
        tunnel.cleanup();
        if matches!(&result, Err(e) if e.kind() == ErrorKind::Tunnel) {
            // Start from scratch next time (re-resolve the endpoint, new socket).
            p.tunnels.remove(i);
        }
        result
    })
}

/// Closes this process's tunnels for the profile.
pub fn close(profile: &Profile) {
    let _ = with_process(|p| {
        p.tunnels.retain(|e| {
            !profile
                .members()
                .iter()
                .any(|m| m.fingerprint() == e.tunnel.config().fingerprint())
        });
        Ok(())
    });
}

/// Number of tunnels open in this process (for tests and diagnostics).
pub fn open_tunnels() -> usize {
    PROCESS.with(|cell| {
        cell.try_borrow()
            .ok()
            .and_then(|s| s.as_ref().map(|p| p.tunnels.len()))
            .unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PRIV2: &str = "WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=";
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn conf(private: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {private}\nAddress = 10.13.13.2/32\nDNS = 10.13.13.1\n[Peer]\nPublicKey = {PUB}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n"
        )
    }

    #[test]
    fn file_permissions_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.conf");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(conf(PRIV).as_bytes())
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = Profile::from_file(&path, true).unwrap_err();
        assert!(e.message().contains("0644"), "{}", e.message());
        assert!(Profile::from_file(&path, false).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Profile::from_file(&path, true).is_ok());
        assert!(Profile::from_file(dir.path(), true).is_err());
    }

    #[test]
    fn pools() {
        let a = Profile::from_text(&conf(PRIV)).unwrap();
        let b = Profile::from_text(&conf(PRIV2)).unwrap();
        assert_eq!(Profile::pool(&[a.clone(), b]).unwrap().members().len(), 2);
        assert!(Profile::pool(&[a.clone(), a]).is_err());
        assert!(Profile::pool(&[]).is_err());
    }

    #[test]
    fn info_has_no_private_key() {
        let p = Profile::from_text(&conf(PRIV)).unwrap();
        let info = format!("{:?}", p.info());
        assert!(!info.contains(PRIV));
        assert!(info.contains("127.0.0.1:9"));
    }

    #[test]
    fn handshake_failure_is_a_tunnel_error() {
        // Nothing answers on 127.0.0.1:9 (discard): the handshake must fail
        // closed with a tunnel error, never fall back.
        let dir = tempfile::tempdir().unwrap();
        let p = Profile::from_text(&conf(PRIV)).unwrap();
        let spec = RequestSpec {
            url: "http://198.51.100.30/ip".into(),
            connect_timeout: Duration::from_millis(600),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let settings = Settings {
            lock_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let started = Instant::now();
        let e = request(&p, &spec, &settings).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tunnel, "{e}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(open_tunnels(), 0);
    }
}

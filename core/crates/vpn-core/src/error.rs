use std::fmt;

/// Error categories. The numeric values are part of the PHP API
/// (`VPN\Exception::getCode()`) and must stay stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorKind {
    /// Anything that does not fit another category (including caught panics).
    Internal = 1,
    /// Invalid or unreadable profile, invalid request options.
    Config = 2,
    /// The WireGuard tunnel could not be established or was lost.
    Tunnel = 3,
    /// A host name could not be resolved through the tunnel.
    Dns = 4,
    /// The TCP connection through the tunnel failed.
    Connect = 5,
    /// TLS handshake or certificate verification failed.
    Tls = 6,
    /// The request did not finish within its time limit.
    Timeout = 7,
    /// The server sent something that is not valid HTTP.
    Protocol = 8,
    /// The destination is not allowed (scheme, private address, downgrade).
    Policy = 9,
    /// A size or count limit was exceeded.
    Limit = 10,
    /// Another process held the profile's lock for longer than the connect timeout.
    LockTimeout = 11,
}

#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

macro_rules! ctor {
    ($($name:ident => $kind:ident),* $(,)?) => {
        impl Error {
            $(
                pub fn $name(message: impl Into<String>) -> Self {
                    Self::new(ErrorKind::$kind, message)
                }
            )*
        }
    };
}

ctor! {
    internal => Internal,
    config => Config,
    tunnel => Tunnel,
    dns => Dns,
    connect => Connect,
    tls => Tls,
    timeout => Timeout,
    protocol => Protocol,
    policy => Policy,
    limit => Limit,
    lock_timeout => LockTimeout,
}

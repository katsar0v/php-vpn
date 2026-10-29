//! Userspace WireGuard egress for selected HTTP(S) requests.
//!
//! A request runs entirely inside this process: boringtun encrypts IP packets
//! produced by a smoltcp TCP/IP stack and sends them over one UDP socket to the
//! WireGuard endpoint. Host names are resolved by the profile's DNS servers
//! through the tunnel. Nothing changes the host's routes, and every failure is
//! reported instead of retried over the normal network (fail closed).

mod client;
mod config;
mod error;
mod http;
mod lock;
mod policy;
mod secret;
mod tls;
mod tunnel;

pub use client::{close, open_tunnels, request, Profile, ProfileInfo, Settings, MAX_POOL_SIZE};
pub use config::{Cidr, WgConfig, MAX_CONFIG_BYTES};
pub use error::{Error, ErrorKind, Result};
pub use http::{RequestSpec, Response, USER_AGENT};
pub use policy::is_restricted;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

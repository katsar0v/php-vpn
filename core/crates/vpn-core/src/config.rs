//! Parser for wg-quick style WireGuard profiles (`.conf`), as handed out by
//! providers such as Surfshark. Only the keys needed for a userspace client are
//! used; wg-quick hooks (`PostUp`, ...) are accepted but never executed.
//! Error messages name the line and key but never echo values, so key material
//! cannot end up in logs or exceptions.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use boringtun::x25519;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::secret::{decode_key, SecretKey};

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
const DEFAULT_MTU: u16 = 1420;

/// An address with a prefix length, e.g. `10.14.0.2/16` or `::/0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl FromStr for Cidr {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, ()> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| ())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| ())?,
            None => max,
        };
        if prefix > max {
            return Err(());
        }
        Ok(Cidr { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointHost {
    Ip(IpAddr),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: EndpointHost,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            EndpointHost::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            EndpointHost::Ip(ip) => write!(f, "{ip}:{}", self.port),
            EndpointHost::Name(n) => write!(f, "{n}:{}", self.port),
        }
    }
}

fn parse_endpoint(value: &str) -> Option<Endpoint> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (EndpointHost::Ip(IpAddr::V6(h.parse::<Ipv6Addr>().ok()?)), p)
    } else {
        let (h, p) = value.rsplit_once(':')?;
        if h.contains(':') {
            return None; // bare IPv6 must be bracketed
        }
        let host = match h.parse::<Ipv4Addr>() {
            Ok(ip) => EndpointHost::Ip(IpAddr::V4(ip)),
            Err(_) => {
                if !is_valid_hostname(h) {
                    return None;
                }
                EndpointHost::Name(h.to_ascii_lowercase())
            }
        };
        (host, p)
    };
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(Endpoint { host, port })
}

fn is_valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<SecretKey>,
    pub endpoint: Endpoint,
    pub allowed_ips: Vec<Cidr>,
    pub persistent_keepalive: Option<u16>,
}

/// A parsed profile. `Debug` output never contains key material.
#[derive(Clone)]
pub struct WgConfig {
    pub private_key: SecretKey,
    pub public_key: [u8; 32],
    pub addresses: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub peer: PeerConfig,
    fingerprint: [u8; 32],
}

impl fmt::Debug for WgConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgConfig")
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("endpoint", &self.peer.endpoint.to_string())
            .finish_non_exhaustive()
    }
}

impl WgConfig {
    /// Identifies the profile (all settings, including the private key) inside
    /// this process. Never exposed outside the core.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Name for the cross-process lock: one WireGuard key can only hold one
    /// session at the server, so every process using this key shares it.
    pub fn lock_name(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"php-vpn-lock\0");
        h.update(self.public_key);
        h.update(self.peer.public_key);
        hex(&h.finalize()[..16])
    }

    pub fn has_ipv4(&self) -> bool {
        self.addresses.iter().any(|c| c.addr.is_ipv4())
    }

    pub fn has_ipv6(&self) -> bool {
        self.addresses.iter().any(|c| c.addr.is_ipv6())
    }

    /// Whether the peer's AllowedIPs route `ip` into the tunnel.
    pub fn routes(&self, ip: IpAddr) -> bool {
        self.peer.allowed_ips.iter().any(|c| c.contains(ip))
    }

    pub fn parse(text: &str) -> Result<Self> {
        Parser::default().parse(text)
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct Parser {
    private_key: Option<SecretKey>,
    addresses: Vec<Cidr>,
    dns: Vec<IpAddr>,
    mtu: Option<u16>,
    peers: usize,
    public_key: Option<[u8; 32]>,
    preshared_key: Option<SecretKey>,
    endpoint: Option<Endpoint>,
    allowed_ips: Vec<Cidr>,
    keepalive: Option<u16>,
}

fn err(line: usize, msg: impl fmt::Display) -> Error {
    Error::config(format!("WireGuard profile, line {line}: {msg}"))
}

impl Parser {
    fn parse(mut self, text: &str) -> Result<WgConfig> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(Error::config(format!(
                "WireGuard profile is larger than {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut section = Section::None;
        let mut interfaces = 0;

        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = match raw.find('#') {
                Some(pos) => &raw[..pos],
                None => raw,
            }
            .trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                match line.to_ascii_lowercase().as_str() {
                    "[interface]" => {
                        interfaces += 1;
                        if interfaces > 1 {
                            return Err(err(line_no, "more than one [Interface] section"));
                        }
                        section = Section::Interface;
                    }
                    "[peer]" => {
                        self.peers += 1;
                        if self.peers > 1 {
                            return Err(err(
                                line_no,
                                "more than one [Peer] section (only single-peer profiles are supported)",
                            ));
                        }
                        section = Section::Peer;
                    }
                    _ => return Err(err(line_no, "unknown section")),
                }
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(err(line_no, "expected `Key = Value`"));
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match section {
                Section::None => return Err(err(line_no, "setting outside of a section")),
                Section::Interface => self.interface_key(line_no, &key, value)?,
                Section::Peer => self.peer_key(line_no, &key, value)?,
            }
        }
        self.finish()
    }

    fn interface_key(&mut self, line: usize, key: &str, value: &str) -> Result<()> {
        match key {
            "privatekey" => {
                let k = SecretKey::from_base64(value)
                    .ok_or_else(|| err(line, "PrivateKey is not a valid base64 WireGuard key"))?;
                self.private_key = Some(k);
            }
            "address" => {
                for item in split_list(value) {
                    let cidr: Cidr = item.parse().map_err(|_| {
                        err(
                            line,
                            "invalid Address (expected a.b.c.d/nn or an IPv6 CIDR)",
                        )
                    })?;
                    self.addresses.push(cidr);
                }
            }
            "dns" => {
                // wg-quick allows search domains next to servers; only servers matter here.
                for item in split_list(value) {
                    if let Ok(ip) = item.parse::<IpAddr>() {
                        self.dns.push(ip);
                    }
                }
            }
            "mtu" => {
                let mtu: u16 = value
                    .parse()
                    .map_err(|_| err(line, "MTU must be a number"))?;
                if !(576..=9000).contains(&mtu) {
                    return Err(err(line, "MTU must be between 576 and 9000"));
                }
                self.mtu = Some(mtu);
            }
            // wg-quick / kernel settings that do not apply to a userspace
            // client. Hooks are never executed.
            "listenport" | "fwmark" | "table" | "preup" | "postup" | "predown" | "postdown"
            | "saveconfig" => {}
            _ => return Err(err(line, format!("unsupported [Interface] key `{key}`"))),
        }
        Ok(())
    }

    fn peer_key(&mut self, line: usize, key: &str, value: &str) -> Result<()> {
        match key {
            "publickey" => {
                let k = decode_key(value)
                    .ok_or_else(|| err(line, "PublicKey is not a valid base64 WireGuard key"))?;
                self.public_key = Some(*k);
            }
            "presharedkey" => {
                let k = SecretKey::from_base64(value)
                    .ok_or_else(|| err(line, "PresharedKey is not a valid base64 WireGuard key"))?;
                self.preshared_key = Some(k);
            }
            "endpoint" => {
                let ep = parse_endpoint(value).ok_or_else(|| {
                    err(
                        line,
                        "Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`",
                    )
                })?;
                self.endpoint = Some(ep);
            }
            "allowedips" => {
                for item in split_list(value) {
                    let cidr: Cidr = item.parse().map_err(|_| {
                        err(
                            line,
                            "invalid AllowedIPs entry (expected CIDRs such as 0.0.0.0/0)",
                        )
                    })?;
                    self.allowed_ips.push(cidr);
                }
            }
            "persistentkeepalive" => {
                if value.eq_ignore_ascii_case("off") {
                    self.keepalive = None;
                } else {
                    let v: u16 = value
                        .parse()
                        .map_err(|_| err(line, "PersistentKeepalive must be a number or `off`"))?;
                    self.keepalive = (v > 0).then_some(v);
                }
            }
            _ => return Err(err(line, format!("unsupported [Peer] key `{key}`"))),
        }
        Ok(())
    }

    fn finish(self) -> Result<WgConfig> {
        let missing = |what: &str| Error::config(format!("WireGuard profile: missing {what}"));
        let private_key = self
            .private_key
            .ok_or_else(|| missing("[Interface] PrivateKey"))?;
        if self.addresses.is_empty() {
            return Err(missing("[Interface] Address"));
        }
        if self.peers == 0 {
            return Err(missing("[Peer] section"));
        }
        let peer_public = self.public_key.ok_or_else(|| missing("[Peer] PublicKey"))?;
        let endpoint = self.endpoint.ok_or_else(|| missing("[Peer] Endpoint"))?;
        if self.allowed_ips.is_empty() {
            return Err(missing("[Peer] AllowedIPs"));
        }

        let secret = x25519::StaticSecret::from(*private_key.expose());
        let public_key = x25519::PublicKey::from(&secret).to_bytes();

        let mut cfg = WgConfig {
            private_key,
            public_key,
            addresses: self.addresses,
            dns: self.dns,
            mtu: self.mtu.unwrap_or(DEFAULT_MTU),
            peer: PeerConfig {
                public_key: peer_public,
                preshared_key: self.preshared_key,
                endpoint,
                allowed_ips: self.allowed_ips,
                persistent_keepalive: self.keepalive,
            },
            fingerprint: [0; 32],
        };
        cfg.fingerprint = fingerprint(&cfg);
        Ok(cfg)
    }
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn fingerprint(cfg: &WgConfig) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"php-vpn-profile\0");
    h.update(cfg.private_key.expose());
    h.update(cfg.peer.public_key);
    if let Some(psk) = &cfg.peer.preshared_key {
        h.update(psk.expose());
    }
    h.update(cfg.peer.endpoint.to_string());
    for a in &cfg.addresses {
        h.update(a.to_string());
    }
    for d in &cfg.dns {
        h.update(d.to_string());
    }
    for a in &cfg.peer.allowed_ips {
        h.update(a.to_string());
    }
    h.update(cfg.mtu.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn sample() -> String {
        format!(
            "# Surfshark-style profile\n[Interface]\nPrivateKey = {PRIV}\nAddress = 10.14.0.2/16\nDNS = 162.252.172.57, 149.154.159.92\n\n[Peer]\nPublicKey = {PUB}\nAllowedIPs = 0.0.0.0/0\nEndpoint = de-fra.prod.surfshark.com:51820\nPersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn parses_surfshark_profile() {
        let cfg = WgConfig::parse(&sample()).unwrap();
        assert_eq!(cfg.addresses, vec!["10.14.0.2/16".parse().unwrap()]);
        assert_eq!(cfg.dns.len(), 2);
        assert_eq!(cfg.mtu, 1420);
        assert_eq!(
            cfg.peer.endpoint,
            Endpoint {
                host: EndpointHost::Name("de-fra.prod.surfshark.com".into()),
                port: 51820
            }
        );
        assert_eq!(cfg.peer.persistent_keepalive, Some(25));
        assert!(cfg.routes("1.1.1.1".parse().unwrap()));
        assert!(!cfg.routes("::1".parse().unwrap()));
        assert!(cfg.has_ipv4() && !cfg.has_ipv6());
    }

    #[test]
    fn derives_public_key() {
        let cfg = WgConfig::parse(&sample()).unwrap();
        // Public key of the RFC-style test private key above.
        assert_eq!(
            crate::secret::encode_key(&cfg.public_key),
            "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
        );
    }

    #[test]
    fn errors_never_contain_key_material() {
        let bad = sample().replace(PRIV, "AAAAsecretAAAAsecretAAAAsecretAAAAsecret=");
        let e = WgConfig::parse(&bad).unwrap_err();
        assert!(!e.message().contains("secret"), "{}", e.message());
        assert!(e.message().contains("line 3"));

        let pasted = sample().replace("Address = 10.14.0.2/16", &format!("Address = {PRIV}"));
        let e = WgConfig::parse(&pasted).unwrap_err();
        assert!(!e.message().contains("yAnz"), "{}", e.message());
        let pasted = sample().replace("AllowedIPs = 0.0.0.0/0", &format!("AllowedIPs = {PRIV}"));
        assert!(!WgConfig::parse(&pasted)
            .unwrap_err()
            .message()
            .contains("yAnz"));

        let dbg = format!("{:?}", WgConfig::parse(&sample()).unwrap());
        assert!(!dbg.contains(PRIV) && !dbg.contains("yAnz"));
    }

    #[test]
    fn hooks_are_ignored_unknown_keys_rejected() {
        let with_hooks = sample().replace("[Peer]", "PostUp = rm -rf /\nTable = off\n[Peer]");
        assert!(WgConfig::parse(&with_hooks).is_ok());
        let unknown = sample().replace("[Peer]", "Jc = 4\n[Peer]");
        assert!(WgConfig::parse(&unknown).is_err());
    }

    #[test]
    fn rejects_incomplete_or_ambiguous_profiles() {
        assert!(WgConfig::parse("").is_err());
        assert!(WgConfig::parse(&sample().replace("[Peer]", "[Peer]\n[Peer]")).is_err());
        assert!(WgConfig::parse(&sample().replace("Endpoint", "#Endpoint")).is_err());
        assert!(WgConfig::parse(&sample().replace("AllowedIPs", "#AllowedIPs")).is_err());
        assert!(WgConfig::parse(&sample().replace("Address", "#Address")).is_err());
        assert!(WgConfig::parse(&"x".repeat(MAX_CONFIG_BYTES + 1)).is_err());
    }

    #[test]
    fn endpoints() {
        assert!(parse_endpoint("1.2.3.4:51820").is_some());
        assert!(parse_endpoint("[2001:db8::1]:51820").is_some());
        assert!(parse_endpoint("wg.lab.test:51820").is_some());
        assert!(parse_endpoint("2001:db8::1:51820").is_none());
        assert!(parse_endpoint("host:0").is_none());
        assert!(parse_endpoint("host").is_none());
        assert!(parse_endpoint("bad_host!:1").is_none());
    }

    #[test]
    fn cidr_contains() {
        let c: Cidr = "10.14.0.0/16".parse().unwrap();
        assert!(c.contains("10.14.255.1".parse().unwrap()));
        assert!(!c.contains("10.15.0.1".parse().unwrap()));
        let all6: Cidr = "::/0".parse().unwrap();
        assert!(all6.contains("2001:db8::1".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
    }

    #[test]
    fn fingerprint_and_lock_name_are_stable() {
        let a = WgConfig::parse(&sample()).unwrap();
        let b = WgConfig::parse(&sample().replace("# Surfshark-style profile\n", "")).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.lock_name(), b.lock_name());
        assert_eq!(a.lock_name().len(), 32);
        let c = WgConfig::parse(&sample().replace("10.14.0.2/16", "10.14.0.3/16")).unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());
        assert_eq!(a.lock_name(), c.lock_name());
    }
}

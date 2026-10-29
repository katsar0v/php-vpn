//! Destination policy (SSRF guard rails). Through a VPN, "private" addresses
//! belong to the provider's network, so they are refused unless allowed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// Whether `ip` is loopback, private, link-local, CGNAT, multicast or otherwise
/// not a normal public destination. Documentation ranges are not included: they
/// are never routed on the internet and the test lab uses them.
pub fn is_restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_restricted_v4(v4),
        IpAddr::V6(v6) => is_restricted_v6(v6),
    }
}

fn is_restricted_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0 // "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 shared address space (CGNAT)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240 // reserved
}

fn is_restricted_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return is_restricted_v4(v4);
    }
    let seg = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
}

/// IPv4 addresses hidden in IPv4-mapped (::ffff:a.b.c.d) and NAT64
/// (64:ff9b::/96) addresses are judged as IPv4.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = ip.segments();
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let o = ip.octets();
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

pub fn check_scheme(scheme: &str) -> Result<()> {
    match scheme {
        "http" | "https" => Ok(()),
        other => Err(Error::policy(format!(
            "URL scheme `{other}` is not supported (only http and https)"
        ))),
    }
}

/// Keeps only the addresses the request may connect to.
pub fn filter_addresses(
    host: &str,
    addrs: Vec<IpAddr>,
    allow_private: bool,
    routed: impl Fn(IpAddr) -> bool,
) -> Result<Vec<IpAddr>> {
    let total = addrs.len();
    let mut not_routed = 0;
    let mut restricted = 0;
    let ok: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|ip| {
            if !routed(*ip) {
                not_routed += 1;
                false
            } else if !allow_private && is_restricted(*ip) {
                restricted += 1;
                false
            } else {
                true
            }
        })
        .collect();
    if !ok.is_empty() {
        return Ok(ok);
    }
    if total > 0 && restricted > 0 {
        Err(Error::policy(format!(
            "`{host}` resolves to a private or reserved address; set allow_private to permit it"
        )))
    } else if not_routed > 0 {
        Err(Error::policy(format!(
            "`{host}` is not covered by the profile's AllowedIPs, refusing to send it outside the tunnel"
        )))
    } else {
        Err(Error::dns(format!("`{host}` has no usable address")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> bool {
        is_restricted(s.parse().unwrap())
    }

    #[test]
    fn restricted_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "198.18.0.1",
            "192.0.0.8",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(r(ip), "{ip} should be restricted");
        }
    }

    #[test]
    fn public_ranges() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "198.51.100.30",
            "203.0.113.20",
            "2001:4860:4860::8888",
            "::ffff:1.1.1.1",
            "64:ff9b::101:101",
        ] {
            assert!(!r(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn filter() {
        let all = |_| true;
        let ips = vec!["10.0.0.1".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        assert_eq!(
            filter_addresses("h", ips.clone(), false, all)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(filter_addresses("h", ips, true, all).unwrap().len(), 2);
        let e = filter_addresses("h", vec!["10.0.0.1".parse().unwrap()], false, all).unwrap_err();
        assert_eq!(e.kind(), crate::error::ErrorKind::Policy);
        let e =
            filter_addresses("h", vec!["1.1.1.1".parse().unwrap()], false, |_| false).unwrap_err();
        assert!(e.message().contains("AllowedIPs"));
        assert!(check_scheme("file").is_err());
        assert!(check_scheme("https").is_ok());
    }
}

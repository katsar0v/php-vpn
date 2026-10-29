//! HTTP/1.1 over tunnel connections: one connection per hop, redirects,
//! size limits and content decoding.

use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::error::{Error, ErrorKind, Result};
use crate::policy;
use crate::tls;
use crate::tunnel::{TcpStream, Tunnel};

pub const USER_AGENT: &str = concat!("php-vpn/", env!("CARGO_PKG_VERSION"));
const MAX_HEADERS: usize = 128;
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Headers whose framing hyper owns; letting callers set them would allow
/// request smuggling or broken messages.
const MANAGED_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-connection",
];

/// Credentials that must not follow a redirect to another origin.
const ORIGIN_BOUND_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_redirects: u32,
    pub verify_tls: bool,
    pub ca_file: Option<PathBuf>,
    pub max_response_size: u64,
    pub allow_private: bool,
    pub allow_https_downgrade: bool,
    pub decode_content: bool,
}

impl Default for RequestSpec {
    fn default() -> Self {
        Self {
            method: "GET".into(),
            url: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            max_redirects: 5,
            verify_tls: true,
            ca_file: None,
            max_response_size: 16 * 1024 * 1024,
            allow_private: false,
            allow_https_downgrade: false,
            decode_content: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    pub effective_url: String,
    pub redirects: u32,
    pub remote_ip: IpAddr,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// Checked, typed version of the caller's request.
#[derive(Debug)]
pub(crate) struct Prepared {
    method: Method,
    url: Url,
    headers: Vec<(HeaderName, HeaderValue)>,
}

pub(crate) fn prepare(spec: &RequestSpec) -> Result<Prepared> {
    let method = Method::from_bytes(spec.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| Error::config(format!("invalid HTTP method `{}`", spec.method)))?;
    if method == Method::CONNECT || method == Method::TRACE {
        return Err(Error::config(format!(
            "HTTP method {method} is not supported"
        )));
    }
    let url = Url::parse(&spec.url).map_err(|e| Error::config(format!("invalid URL: {e}")))?;
    policy::check_scheme(url.scheme())?;
    if url.host_str().is_none() {
        return Err(Error::config("URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::config(
            "credentials in the URL are not supported; send an Authorization header",
        ));
    }
    // IP literals can be judged before any handshake (names after resolving).
    let literal = match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        _ => None,
    };
    if let Some(ip) = literal {
        policy::filter_addresses(&ip.to_string(), vec![ip], spec.allow_private, |_| true)?;
    }
    let mut headers = Vec::with_capacity(spec.headers.len());
    for (name, value) in &spec.headers {
        let hn = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| Error::config(format!("invalid header name `{name}`")))?;
        if MANAGED_HEADERS.contains(&hn.as_str()) {
            return Err(Error::config(format!(
                "header `{name}` is managed by php-vpn and cannot be set"
            )));
        }
        let hv = HeaderValue::from_bytes(value)
            .map_err(|_| Error::config(format!("invalid value for header `{name}`")))?;
        headers.push((hn, hv));
    }
    Ok(Prepared {
        method,
        url,
        headers,
    })
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn host_header(url: &Url) -> String {
    let host = match url.host() {
        Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
        Some(h) => h.to_string(),
        None => String::new(),
    };
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn hyper_error(e: hyper::Error) -> Error {
    if e.is_incomplete_message() || e.is_canceled() {
        return Error::protocol(format!(
            "connection closed before the response completed: {e}"
        ));
    }
    if e.is_parse() || e.is_parse_status() {
        return Error::protocol(format!("invalid HTTP response: {e}"));
    }
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return Error::connect(format!("connection error: {io}"));
        }
        src = s.source();
    }
    Error::protocol(e.to_string())
}

struct Hop {
    status: StatusCode,
    headers: http::HeaderMap,
    raw: Vec<u8>,
    remote_ip: IpAddr,
}

/// Executes the request (with redirects) through `tunnel`. The caller drives
/// the tunnel and enforces the total deadline.
pub(crate) async fn execute(
    tunnel: &Tunnel,
    spec: &RequestSpec,
    prepared: Prepared,
    connect_deadline: Instant,
) -> Result<Response> {
    let Prepared {
        mut method,
        mut url,
        mut headers,
    } = prepared;
    let mut body = Bytes::from(spec.body.clone());
    let mut redirects = 0u32;
    let mut hop_deadline = connect_deadline;

    loop {
        let hop = hop(
            tunnel,
            spec,
            &method,
            &url,
            &headers,
            body.clone(),
            hop_deadline,
        )
        .await;
        // No connection state survives a hop.
        tunnel.cleanup();
        let Hop {
            status,
            headers: response_headers,
            raw,
            remote_ip,
        } = hop?;

        if is_redirect(status) && spec.max_redirects > 0 {
            if let Some(location) = response_headers.get(http::header::LOCATION) {
                if redirects >= spec.max_redirects {
                    return Err(Error::limit(format!(
                        "too many redirects (more than {})",
                        spec.max_redirects
                    )));
                }
                let location = location
                    .to_str()
                    .map_err(|_| Error::protocol("redirect Location header is not valid text"))?;
                let next = url
                    .join(location)
                    .map_err(|e| Error::protocol(format!("invalid redirect Location: {e}")))?;
                policy::check_scheme(next.scheme())?;
                if url.scheme() == "https" && next.scheme() == "http" && !spec.allow_https_downgrade
                {
                    return Err(Error::policy(format!(
                        "refusing to follow a redirect from HTTPS to HTTP ({next}); set allow_https_downgrade to permit it"
                    )));
                }
                if !same_origin(&url, &next) {
                    headers.retain(|(n, _)| {
                        !ORIGIN_BOUND_HEADERS.contains(&n.as_str()) && n.as_str() != "host"
                    });
                }
                let to_get = status == StatusCode::SEE_OTHER
                    || ((status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND)
                        && method == Method::POST);
                if to_get && method != Method::HEAD {
                    method = Method::GET;
                    body = Bytes::new();
                    headers.retain(|(n, _)| !n.as_str().starts_with("content-"));
                }
                url = next;
                redirects += 1;
                // Later hops get a fresh connect budget, bounded by the total deadline.
                hop_deadline = Instant::now() + spec.connect_timeout;
                continue;
            }
        }

        let header_list = response_headers
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
            .collect();
        let body = if spec.decode_content && method != Method::HEAD {
            decode(&response_headers, raw, spec.max_response_size)?
        } else {
            raw
        };
        return Ok(Response {
            status: status.as_u16(),
            headers: header_list,
            body,
            effective_url: url.to_string(),
            redirects,
            remote_ip,
        });
    }
}

async fn hop(
    tunnel: &Tunnel,
    spec: &RequestSpec,
    method: &Method,
    url: &Url,
    headers: &[(HeaderName, HeaderValue)],
    body: Bytes,
    deadline: Instant,
) -> Result<Hop> {
    let host = url.host_str().unwrap_or_default().to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::config("URL has no port"))?;

    let candidates = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![IpAddr::V4(ip)],
        Some(url::Host::Ipv6(ip)) => vec![IpAddr::V6(ip)],
        Some(url::Host::Domain(d)) => tokio::time::timeout_at(deadline, tunnel.resolve(d))
            .await
            .map_err(|_| Error::dns(format!("resolving `{d}` through the tunnel timed out")))??,
        None => return Err(Error::config("URL has no host")),
    };
    let candidates = policy::filter_addresses(&host, candidates, spec.allow_private, |ip| {
        tunnel.config().routes(ip)
    })?;

    let mut last_err = None;
    let mut connected = None;
    for ip in &candidates {
        match tokio::time::timeout_at(deadline, tunnel.connect(*ip, port)).await {
            Ok(Ok(s)) => {
                connected = Some((s, *ip));
                break;
            }
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(Error::connect(format!(
                    "connecting to {host} ({ip}:{port}) through the tunnel timed out"
                )));
                break;
            }
        }
    }
    let Some((tcp, remote_ip)) = connected else {
        return Err(last_err.unwrap_or_else(|| Error::connect("no address to connect to")));
    };

    let conn = if url.scheme() == "https" {
        let cfg = tls::client_config(spec.verify_tls, spec.ca_file.as_deref())?;
        let tls_host = match url.host() {
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            _ => host.clone(),
        };
        let name = tls::server_name(&tls_host)?;
        let tls = tokio::time::timeout_at(deadline, TlsConnector::from(cfg).connect(name, tcp))
            .await
            .map_err(|_| Error::tls(format!("TLS handshake with `{host}` timed out")))?
            .map_err(|e| tls::handshake_error(&host, e))?;
        Conn::Tls(Box::new(tls))
    } else {
        Conn::Plain(tcp)
    };

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(&url[url::Position::BeforePath..url::Position::AfterQuery]);
    let has = |name: &str| headers.iter().any(|(n, _)| n.as_str() == name);
    if !has("host") {
        builder = builder.header(http::header::HOST, host_header(url));
    }
    if !has("user-agent") {
        builder = builder.header(http::header::USER_AGENT, USER_AGENT);
    }
    if !has("accept") {
        builder = builder.header(http::header::ACCEPT, "*/*");
    }
    if spec.decode_content && !has("accept-encoding") {
        builder = builder.header(http::header::ACCEPT_ENCODING, "gzip, deflate");
    }
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    let request = builder
        .body(Full::new(body))
        .map_err(|e| Error::config(format!("cannot build request: {e}")))?;

    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_HEADER_BYTES)
        .handshake::<_, Full<Bytes>>(TokioIo::new(conn))
        .await
        .map_err(hyper_error)?;
    let mut connection = Box::pin(connection);
    let mut conn_done = false;

    let response = tokio::select! {
        r = sender.send_request(request) => r.map_err(hyper_error)?,
        c = &mut connection => {
            c.map_err(hyper_error)?;
            return Err(Error::protocol("connection closed before a response was received"));
        }
    };
    let (parts, mut incoming) = response.into_parts();

    let limit = spec.max_response_size;
    let mut raw = Vec::new();
    loop {
        tokio::select! {
            frame = incoming.frame() => match frame {
                None => break,
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if raw.len() as u64 + data.len() as u64 > limit {
                            return Err(Error::limit(format!(
                                "response body is larger than max_response_size ({limit} bytes)"
                            )));
                        }
                        raw.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => return Err(hyper_error(e)),
            },
            c = &mut connection, if !conn_done => {
                conn_done = true;
                c.map_err(hyper_error)?;
            }
        }
    }
    drop(incoming);
    drop(sender);
    drop(connection);
    tunnel.linger(Duration::from_millis(100)).await;

    Ok(Hop {
        status: parts.status,
        headers: parts.headers,
        raw,
        remote_ip,
    })
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn decode(headers: &http::HeaderMap, raw: Vec<u8>, limit: u64) -> Result<Vec<u8>> {
    let encoding = headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty() && v != "identity")
        .collect::<Vec<_>>();
    if raw.is_empty() || encoding.is_empty() {
        return Ok(raw);
    }
    if encoding.len() > 1 {
        return Ok(raw); // stacked encodings are left to the caller
    }
    let read_limited = |mut r: Box<dyn Read + '_>| -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        (&mut r).take(limit + 1).read_to_end(&mut out)?;
        Ok(out)
    };
    let decoded = match encoding[0].as_str() {
        "gzip" | "x-gzip" => read_limited(Box::new(flate2::read::MultiGzDecoder::new(&raw[..]))),
        "deflate" => read_limited(Box::new(flate2::read::ZlibDecoder::new(&raw[..])))
            .or_else(|_| read_limited(Box::new(flate2::read::DeflateDecoder::new(&raw[..])))),
        _ => return Ok(raw),
    }
    .map_err(|e| Error::protocol(format!("cannot decode {} response body: {e}", encoding[0])))?;
    if decoded.len() as u64 > limit {
        return Err(Error::limit(format!(
            "decoded response body is larger than max_response_size ({limit} bytes)"
        )));
    }
    Ok(decoded)
}

/// Total-deadline wrapper used by the client.
pub(crate) fn timeout_error(spec: &RequestSpec) -> Error {
    Error::new(
        ErrorKind::Timeout,
        format!(
            "the request did not complete within {:.1} s",
            spec.timeout.as_secs_f64()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn spec(url: &str) -> RequestSpec {
        RequestSpec {
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn prepare_validates() {
        assert!(prepare(&spec("https://example.com/a?b=c")).is_ok());
        assert_eq!(
            prepare(&spec("ftp://x/")).unwrap_err().kind(),
            ErrorKind::Policy
        );
        assert_eq!(
            prepare(&spec("not a url")).unwrap_err().kind(),
            ErrorKind::Config
        );
        assert!(prepare(&spec("https://user:pw@example.com/")).is_err());
        assert_eq!(
            prepare(&spec("http://10.0.0.1/")).unwrap_err().kind(),
            ErrorKind::Policy
        );
        assert_eq!(
            prepare(&spec("http://[::1]/")).unwrap_err().kind(),
            ErrorKind::Policy
        );
        let mut private = spec("http://10.0.0.1/");
        private.allow_private = true;
        assert!(prepare(&private).is_ok());
        let mut s = spec("https://example.com/");
        s.headers = vec![("Content-Length".into(), b"5".to_vec())];
        assert!(prepare(&s).is_err());
        s.headers = vec![("X-Ok".into(), b"a\r\nInjected: 1".to_vec())];
        assert!(prepare(&s).is_err());
        s.headers = vec![("Bad Name".into(), b"x".to_vec())];
        assert!(prepare(&s).is_err());
        s.headers = vec![("X-Ok".into(), b"fine".to_vec())];
        assert!(prepare(&s).is_ok());
        s.method = "CONNECT".into();
        assert!(prepare(&s).is_err());
    }

    #[test]
    fn host_headers() {
        assert_eq!(
            host_header(&Url::parse("http://a.test/").unwrap()),
            "a.test"
        );
        assert_eq!(
            host_header(&Url::parse("http://a.test:8080/").unwrap()),
            "a.test:8080"
        );
        assert_eq!(
            host_header(&Url::parse("https://[::1]:8443/").unwrap()),
            "[::1]:8443"
        );
        assert_eq!(
            host_header(&Url::parse("https://a.test:443/").unwrap()),
            "a.test"
        );
    }

    #[test]
    fn decoding_and_bombs() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&vec![b'a'; 100_000]).unwrap();
        let gz = enc.finish().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        assert_eq!(decode(&h, gz.clone(), 200_000).unwrap().len(), 100_000);
        assert_eq!(decode(&h, gz, 1000).unwrap_err().kind(), ErrorKind::Limit);
        h.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("br"),
        );
        assert_eq!(decode(&h, b"xyz".to_vec(), 10).unwrap(), b"xyz");
    }
}

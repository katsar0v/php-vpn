//! One userspace WireGuard tunnel: a boringtun session, a single UDP socket to
//! the endpoint and a smoltcp TCP/IP stack whose packets only ever leave
//! through that session. Nothing here touches the host's routes or resolver
//! (except resolving the endpoint's own host name).
//!
//! Everything runs on the calling thread inside a current-thread tokio
//! runtime: `run()` drives the stack while the request future runs, and nothing
//! runs between requests.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp};
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::config::{EndpointHost, WgConfig};
use crate::error::{Error, Result};

const TCP_RX_BUFFER: usize = 256 * 1024;
const TCP_TX_BUFFER: usize = 64 * 1024;
/// WireGuard timers (handshake retries, keepalives) are checked at least this often.
const TIMER_TICK: Duration = Duration::from_millis(100);
/// Re-send the handshake initiation after this long without a response
/// (faster than WireGuard's 5 s REKEY_TIMEOUT: a request is waiting on it).
const HANDSHAKE_RETRY: Duration = Duration::from_secs(1);
/// Minimum spacing of handshakes forced because the server seems to use a
/// session we do not have (the key was used elsewhere in the meantime).
const REHANDSHAKE_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// A TCP connect still pending after this long on an established session
/// suggests the server dropped our session; force a new handshake.
const CONNECT_STALL: Duration = Duration::from_secs(1);
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_MAX: usize = 256;

pub(crate) fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    u64::from_ne_bytes(b)
}

/// Resolves the WireGuard endpoint. This is the only lookup that uses the
/// host resolver; it reveals the VPN server name, never a destination.
pub(crate) fn resolve_endpoint(config: &WgConfig) -> Result<SocketAddr> {
    let ep = &config.peer.endpoint;
    match &ep.host {
        EndpointHost::Ip(ip) => Ok(SocketAddr::new(*ip, ep.port)),
        EndpointHost::Name(name) => {
            let addrs: Vec<SocketAddr> = (name.as_str(), ep.port)
                .to_socket_addrs()
                .map_err(|e| {
                    Error::tunnel(format!("cannot resolve WireGuard endpoint `{name}`: {e}"))
                })?
                .collect();
            addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| addrs.first())
                .copied()
                .ok_or_else(|| Error::tunnel(format!("WireGuard endpoint `{name}` has no address")))
        }
    }
}

/// Packets between smoltcp and the WireGuard session.
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct QueueRx(Vec<u8>);
struct QueueTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for QueueRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(
        &mut self,
        _ts: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((QueueRx(pkt), QueueTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct Stack {
    epoch: Instant,
    config: Arc<WgConfig>,
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    dns: Option<SocketHandle>,
    tcp: HashMap<SocketHandle, u16>,
    tunn: Box<Tunn>,
    out: Vec<u8>,
    fatal: Option<Error>,
    last_initiation: Option<Instant>,
    /// Set when traffic suggests the server no longer has our session.
    rehandshake: bool,
}

fn new_tunn(config: &WgConfig) -> Box<Tunn> {
    let secret = x25519::StaticSecret::from(*config.private_key.expose());
    let peer = x25519::PublicKey::from(config.peer.public_key);
    let psk = config.peer.preshared_key.as_ref().map(|k| *k.expose());
    let index = (random_u64() as u32) & 0x00ff_ffff;
    Box::new(Tunn::new(
        secret,
        peer,
        psk,
        config.peer.persistent_keepalive,
        index,
        None,
    ))
}

/// Sends through the plain socket: tokio's `try_send` refuses to even try
/// before the reactor has reported writability, which silently dropped the
/// first handshake initiation of every new tunnel.
fn send_datagram(udp: &StdUdpSocket, packet: &[u8], fatal: &mut Option<Error>) {
    match udp.send(packet) {
        Ok(_) => {}
        // A full socket buffer drops the packet; TCP retransmits.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => {
            if fatal.is_none() {
                *fatal = Some(udp_error(e));
            }
        }
    }
}

fn udp_error(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::ConnectionRefused {
        Error::tunnel("the WireGuard endpoint is unreachable (ICMP port unreachable)")
    } else {
        Error::tunnel(format!("WireGuard UDP socket error: {e}"))
    }
}

impl Stack {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    fn on_datagram(&mut self, data: &[u8], udp: &StdUdpSocket, src: IpAddr) {
        let mut input = data;
        loop {
            match self.tunn.decapsulate(Some(src), input, &mut self.out) {
                TunnResult::WriteToNetwork(p) => {
                    send_datagram(udp, p, &mut self.fatal);
                    // Flush packets queued while the handshake was in flight.
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(p, from) => {
                    // Cryptokey routing: only accept sources the peer may use.
                    if self.config.routes(IpAddr::V4(from)) {
                        self.device.rx.push_back(p.to_vec());
                    }
                    break;
                }
                TunnResult::WriteToTunnelV6(p, from) => {
                    if self.config.routes(IpAddr::V6(from)) {
                        self.device.rx.push_back(p.to_vec());
                    }
                    break;
                }
                // Data for a session we do not know: another process or host
                // using the same key replaced ours at the server. Re-key.
                TunnResult::Err(WireGuardError::WrongIndex | WireGuardError::NoCurrentSession) => {
                    self.rehandshake = true;
                    break;
                }
                // Other invalid or stale packets are dropped.
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
    }

    fn poll(&mut self, udp: &StdUdpSocket) {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(pkt) = self.device.tx.pop_front() {
            if let TunnResult::WriteToNetwork(p) = self.tunn.encapsulate(&pkt, &mut self.out) {
                send_datagram(udp, p, &mut self.fatal);
            }
        }
        if self.rehandshake
            && self
                .last_initiation
                .is_none_or(|t| t.elapsed() >= REHANDSHAKE_MIN_INTERVAL)
        {
            self.rehandshake = false;
            self.last_initiation = Some(Instant::now());
            if let TunnResult::WriteToNetwork(p) =
                self.tunn.format_handshake_initiation(&mut self.out, true)
            {
                send_datagram(udp, p, &mut self.fatal);
            }
        }
        // ConnectionExpired only means boringtun dropped a stale session; the
        // next packet starts a new handshake and our deadlines catch failures.
        if let TunnResult::WriteToNetwork(p) = self.tunn.update_timers(&mut self.out) {
            send_datagram(udp, p, &mut self.fatal);
        }
    }

    fn next_delay(&mut self) -> Duration {
        let now = self.now();
        match self.iface.poll_delay(now, &self.sockets) {
            Some(d) => Duration::from_micros(d.total_micros()).min(TIMER_TICK),
            None => TIMER_TICK,
        }
    }

    fn alloc_port(&self) -> u16 {
        let used: HashSet<u16> = self.tcp.values().copied().collect();
        loop {
            let port = 49152 + (random_u64() % 16384) as u16;
            if !used.contains(&port) {
                return port;
            }
        }
    }
}

pub(crate) struct Tunnel {
    config: Arc<WgConfig>,
    endpoint: SocketAddr,
    instance: u64,
    /// Receives (with readiness from the runtime).
    udp: Rc<UdpSocket>,
    /// Same socket, used for sending.
    tx: Rc<StdUdpSocket>,
    stack: Rc<RefCell<Stack>>,
    notify: Rc<Notify>,
    dns_cache: RefCell<HashMap<String, (Instant, Vec<IpAddr>)>>,
}

impl Tunnel {
    /// Must be called inside the process runtime (it registers the UDP socket).
    pub fn new(config: Arc<WgConfig>) -> Result<Self> {
        let endpoint = resolve_endpoint(&config)?;
        let bind: SocketAddr = if endpoint.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = StdUdpSocket::bind(bind)
            .and_then(|s| {
                s.connect(endpoint)?;
                s.set_nonblocking(true)?;
                Ok(s)
            })
            .map_err(|e| Error::tunnel(format!("cannot open the WireGuard UDP socket: {e}")))?;
        let tx = sock
            .try_clone()
            .map_err(|e| Error::tunnel(format!("cannot open the WireGuard UDP socket: {e}")))?;
        let udp = UdpSocket::from_std(sock)
            .map_err(|e| Error::tunnel(format!("cannot register the WireGuard UDP socket: {e}")))?;

        let mut device = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: usize::from(config.mtu),
        };
        let epoch = Instant::now();
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = random_u64();
        let mut iface = Interface::new(iface_cfg, &mut device, smoltcp::time::Instant::ZERO);
        iface.update_ip_addrs(|addrs| {
            for a in &config.addresses {
                let _ = addrs.push(IpCidr::new(IpAddress::from(a.addr), a.prefix));
            }
        });
        // Medium::Ip has no neighbours; any gateway sends everything to the device.
        for a in &config.addresses {
            match a.addr {
                IpAddr::V4(v4) => {
                    let _ = iface.routes_mut().add_default_ipv4_route(v4);
                }
                IpAddr::V6(v6) => {
                    let _ = iface.routes_mut().add_default_ipv6_route(v6);
                }
            }
        }

        let mut sockets = SocketSet::new(Vec::new());
        let servers: Vec<IpAddress> = config
            .dns
            .iter()
            .filter(|ip| (ip.is_ipv4() && config.has_ipv4()) || (ip.is_ipv6() && config.has_ipv6()))
            .take(4)
            .map(|ip| IpAddress::from(*ip))
            .collect();
        let dns =
            (!servers.is_empty()).then(|| sockets.add(dns::Socket::new(&servers, Vec::new())));

        let stack = Stack {
            epoch,
            tunn: new_tunn(&config),
            config: Arc::clone(&config),
            iface,
            device,
            sockets,
            dns,
            tcp: HashMap::new(),
            out: vec![0u8; 65536 + 256],
            fatal: None,
            last_initiation: None,
            rehandshake: false,
        };
        Ok(Self {
            config,
            endpoint,
            instance: random_u64(),
            udp: Rc::new(udp),
            tx: Rc::new(tx),
            stack: Rc::new(RefCell::new(stack)),
            notify: Rc::new(Notify::new()),
            dns_cache: RefCell::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &Arc<WgConfig> {
        &self.config
    }

    /// Random id of the current session, recorded in the cross-process lock so
    /// the next holder knows whether the server still has our session.
    pub fn instance(&self) -> u64 {
        self.instance
    }

    /// Age of the current WireGuard session, if one is established.
    pub fn session_age(&self) -> Option<Duration> {
        self.stack.borrow().tunn.time_since_last_handshake()
    }

    /// Drops the session so the next request performs a fresh handshake.
    pub fn reset_session(&mut self) {
        let mut s = self.stack.borrow_mut();
        s.tunn = new_tunn(&self.config);
        s.last_initiation = None;
        s.rehandshake = false;
        s.fatal = None;
        s.device.rx.clear();
        s.device.tx.clear();
        drop(s);
        self.instance = random_u64();
    }

    /// Runs `fut` while driving the tunnel. A fatal tunnel error ends the
    /// request; there is no fallback path.
    pub async fn run<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            r = fut => r,
            e = self.drive() => Err(e),
        }
    }

    async fn drive(&self) -> Error {
        let mut buf = vec![0u8; 65536];
        let src = self.endpoint.ip();
        loop {
            loop {
                match self.udp.try_recv(&mut buf) {
                    Ok(n) => self
                        .stack
                        .borrow_mut()
                        .on_datagram(&buf[..n], &self.tx, src),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return udp_error(e),
                }
            }
            let delay = {
                let mut s = self.stack.borrow_mut();
                s.poll(&self.tx);
                if let Some(e) = s.fatal.take() {
                    return e;
                }
                s.next_delay()
            };
            tokio::select! {
                r = self.udp.readable() => {
                    if let Err(e) = r {
                        return udp_error(e);
                    }
                }
                _ = tokio::time::sleep(delay) => {}
                _ = self.notify.notified() => {}
            }
        }
    }

    /// Waits until the WireGuard handshake has completed.
    pub async fn ensure_session(&self, deadline: tokio::time::Instant) -> Result<()> {
        loop {
            {
                let mut s = self.stack.borrow_mut();
                if s.tunn.time_since_last_handshake().is_some() {
                    return Ok(());
                }
                let due = s
                    .last_initiation
                    .is_none_or(|t| t.elapsed() >= HANDSHAKE_RETRY);
                if due {
                    let s = &mut *s;
                    let force = s.last_initiation.is_some();
                    if let TunnResult::WriteToNetwork(p) =
                        s.tunn.format_handshake_initiation(&mut s.out, force)
                    {
                        send_datagram(&self.tx, p, &mut s.fatal);
                    }
                    s.last_initiation = Some(Instant::now());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::tunnel(format!(
                    "WireGuard handshake with {} did not complete in time (wrong keys, endpoint down or UDP blocked)",
                    self.endpoint
                )));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Resolves `host` with the profile's DNS servers, through the tunnel.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let key = host.to_ascii_lowercase();
        if let Some((at, addrs)) = self.dns_cache.borrow().get(&key) {
            if at.elapsed() < DNS_CACHE_TTL {
                return Ok(addrs.clone());
            }
        }
        let Some(handle) = self.stack.borrow().dns else {
            return Err(Error::dns(format!(
                "cannot resolve `{host}`: the profile has no DNS servers for its address family (add `DNS = ...` or use an IP address)"
            )));
        };
        let mut types = Vec::new();
        if self.config.has_ipv4() {
            types.push(DnsQueryType::A);
        }
        if self.config.has_ipv6() {
            types.push(DnsQueryType::Aaaa);
        }
        let mut found = Vec::new();
        for qtype in types {
            let query = {
                let mut s = self.stack.borrow_mut();
                let s = &mut *s;
                s.sockets
                    .get_mut::<dns::Socket>(handle)
                    .start_query(s.iface.context(), host, qtype)
                    .map_err(|e| Error::dns(format!("cannot resolve `{host}`: {e}")))?
            };
            self.notify.notify_one();
            let guard = QueryGuard {
                stack: &self.stack,
                handle,
                query: Some(query),
            };
            let res = poll_fn(|cx| {
                let mut s = self.stack.borrow_mut();
                let sock = s.sockets.get_mut::<dns::Socket>(handle);
                match sock.get_query_result(query) {
                    Ok(addrs) => Poll::Ready(Some(addrs)),
                    Err(dns::GetQueryResultError::Failed) => Poll::Ready(None),
                    Err(dns::GetQueryResultError::Pending) => {
                        sock.register_query_waker(query, cx.waker());
                        Poll::Pending
                    }
                }
            })
            .await;
            guard.done();
            if let Some(addrs) = res {
                found.extend(addrs.iter().map(|a| IpAddr::from(*a)));
            }
        }
        if found.is_empty() {
            return Err(Error::dns(format!(
                "`{host}` could not be resolved through the tunnel"
            )));
        }
        let mut cache = self.dns_cache.borrow_mut();
        if cache.len() >= DNS_CACHE_MAX {
            cache.clear();
        }
        cache.insert(key, (Instant::now(), found.clone()));
        Ok(found)
    }

    /// Opens a TCP connection through the tunnel.
    pub async fn connect(&self, ip: IpAddr, port: u16) -> Result<TcpStream> {
        let handle = {
            let mut s = self.stack.borrow_mut();
            let s = &mut *s;
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]),
                tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]),
            );
            sock.set_nagle_enabled(false);
            let local_port = s.alloc_port();
            let handle = s.sockets.add(sock);
            s.tcp.insert(handle, local_port);
            s.sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(s.iface.context(), (IpAddress::from(ip), port), local_port)
                .map_err(|e| Error::connect(format!("cannot connect to {ip}:{port}: {e}")))?;
            handle
        };
        let stream = TcpStream {
            stack: Rc::clone(&self.stack),
            notify: Rc::clone(&self.notify),
            handle,
        };
        self.notify.notify_one();
        let established = poll_fn(|cx| {
            let mut s = self.stack.borrow_mut();
            let sock = s.sockets.get_mut::<tcp::Socket>(handle);
            match sock.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                tcp::State::SynSent | tcp::State::SynReceived => {
                    sock.register_recv_waker(cx.waker());
                    sock.register_send_waker(cx.waker());
                    Poll::Pending
                }
                _ => Poll::Ready(Err(Error::connect(format!(
                    "connection to {ip}:{port} was refused through the tunnel"
                )))),
            }
        });
        let mut established = std::pin::pin!(established);
        tokio::select! {
            r = &mut established => r?,
            _ = tokio::time::sleep(CONNECT_STALL) => {
                // Our session may be gone at the server; re-key and keep
                // waiting (smoltcp retransmits the SYN). Still inside the tunnel.
                self.stack.borrow_mut().rehandshake = true;
                self.notify.notify_one();
                established.await?;
            }
        }
        Ok(stream)
    }

    /// Gives closed connections a moment to exchange FINs.
    pub async fn linger(&self, max: Duration) {
        let until = Instant::now() + max;
        while Instant::now() < until {
            let open = {
                let s = self.stack.borrow();
                s.tcp.keys().any(|h| {
                    !matches!(
                        s.sockets.get::<tcp::Socket>(*h).state(),
                        tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen
                    )
                })
            };
            if !open {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// Aborts and removes every TCP socket. Called after each request so no
    /// connection state outlives it.
    pub fn cleanup(&self) {
        let mut s = self.stack.borrow_mut();
        let handles: Vec<SocketHandle> = s.tcp.keys().copied().collect();
        for h in &handles {
            s.sockets.get_mut::<tcp::Socket>(*h).abort();
        }
        // Emit the resets if a session exists; the result does not matter.
        s.poll(&self.tx);
        s.fatal = None;
        for h in handles {
            s.sockets.remove(h);
            s.tcp.remove(&h);
        }
        s.device.rx.clear();
        s.device.tx.clear();
    }
}

/// Cancels a pending DNS query if the request is dropped (e.g. on timeout).
struct QueryGuard<'a> {
    stack: &'a RefCell<Stack>,
    handle: SocketHandle,
    query: Option<dns::QueryHandle>,
}

impl QueryGuard<'_> {
    fn done(mut self) {
        self.query = None;
    }
}

impl Drop for QueryGuard<'_> {
    fn drop(&mut self) {
        if let Some(q) = self.query.take() {
            if let Ok(mut s) = self.stack.try_borrow_mut() {
                s.sockets
                    .get_mut::<dns::Socket>(self.handle)
                    .cancel_query(q);
            }
        }
    }
}

/// A TCP connection inside the tunnel.
pub(crate) struct TcpStream {
    stack: Rc<RefCell<Stack>>,
    notify: Rc<Notify>,
    handle: SocketHandle,
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut s = self.stack.borrow_mut();
        let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
        if sock.can_recv() {
            let n = sock
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::other(e.to_string()))?;
            buf.advance(n);
            drop(s);
            // Let the driver advertise the freed window.
            self.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !sock.may_recv() {
            return if sock.state() == tcp::State::Closed {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection reset or timed out inside the tunnel",
                )))
            } else {
                Poll::Ready(Ok(())) // EOF
            };
        }
        sock.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut s = self.stack.borrow_mut();
        let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
        if sock.can_send() {
            let n = sock
                .send_slice(data)
                .map_err(|e| io::Error::other(e.to_string()))?;
            drop(s);
            self.notify.notify_one();
            return Poll::Ready(Ok(n));
        }
        if !sock.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed inside the tunnel",
            )));
        }
        sock.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut s) = self.stack.try_borrow_mut() {
            s.sockets.get_mut::<tcp::Socket>(self.handle).close();
        }
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if let Ok(mut s) = self.stack.try_borrow_mut() {
            if s.tcp.contains_key(&self.handle) {
                s.sockets.get_mut::<tcp::Socket>(self.handle).close();
            }
        }
        self.notify.notify_one();
    }
}

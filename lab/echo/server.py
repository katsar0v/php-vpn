#!/usr/bin/env python3
"""Fake "internet" for the php-vpn lab (python stdlib only).

One process serves several listeners (plain HTTP and TLS) with the same
routes.  Run twice: as `echo` (198.51.100.30) and as `secret` (203.0.113.20).

Every request is logged as one line (stdout + --log file):

    2026-10-29T15:50:12.345Z 198.51.100.10 GET echo.lab.test /ip?x=1

    time(UTC, ms)  remote-ip  method  Host-header  request-target

Routes (any method: GET POST PUT PATCH DELETE HEAD OPTIONS):
    /                 identifies the server (name)
    /ip               client IP, text/plain, no trailing newline
    /echo             JSON: method, path, query, query_params, headers([[name,value],..]),
                      body, remote, ...
    /redirect         ?code=302&to=<url>
    /redirect-chain   ?n=N[&code=302][&rel=1]   N redirects, then /ip
    /status/<code>    that status (optional ?to=<url> adds Location)
    /slow             ?ms=N   delay before the response headers
    /drip             ?bytes=N&ms=M[&chunk=K]  Content-Length N, K bytes (default 1) every M ms
    /stall            reads the request, never answers until the client disconnects
    /bytes            ?n=N    deterministic bytes (i % 251), X-Content-SHA256 header
    /chunked          ?chunks=N&size=M  Transfer-Encoding: chunked, chunk i = letter(i)*M
    /gzip             gzip-encoded JSON (Content-Encoding: gzip)
    /gzip-bomb        ?mb=N   small gzip body that inflates to N MiB of zeros
    /headers-multi    two Set-Cookie headers (+ a repeated X-Multi header)
    /healthz          200 ok
"""
import argparse
import hashlib
import json
import os
import select
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
import zlib
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

MAX_BODY = 64 * 1024 * 1024
BLOCK = bytes(range(251)) * 261  # 65511 bytes, multiple of the 251-byte pattern
METHODS = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LineLog:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.fh = None
        if path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.fh = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, line):
        with self.lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            if self.fh:
                self.fh.write(line + "\n")
                self.fh.flush()


@lru_cache(maxsize=64)
def bytes_sha256(n):
    h = hashlib.sha256()
    full, rem = divmod(n, len(BLOCK))
    for _ in range(full):
        h.update(BLOCK)
    h.update(BLOCK[:rem])
    return h.hexdigest()


@lru_cache(maxsize=16)
def gzip_bomb(mb):
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\0" * (1 << 20)
    out = []
    for _ in range(mb):
        out.append(co.compress(chunk))
    out.append(co.flush())
    return b"".join(out)


class BadRequest(Exception):
    pass


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lab-echo/1.0"
    sys_version = ""
    timeout = 120
    disable_nagle_algorithm = True

    lab_name = "echo"
    lab_scheme = "http"
    lab_port = 80
    lab_log = None

    # ------------------------------------------------------------ plumbing
    def log_request(self, *args, **kwargs):  # we write our own request log
        pass

    def log_message(self, fmt, *args):  # protocol errors etc. -> stderr only
        sys.stderr.write("%s %s %s\n" % (now_iso(), self.client_address[0], fmt % args))

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, socket.timeout, TimeoutError):
            self.close_connection = True

    def _start(self, code, ctype="text/plain; charset=utf-8", length=None, extra=()):
        self.send_response(code)
        if ctype:
            self.send_header("Content-Type", ctype)
        if length is not None:
            self.send_header("Content-Length", str(length))
        if self.command == "OPTIONS":
            self.send_header("Allow", METHODS)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()

    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=()):
        if isinstance(body, str):
            body = body.encode()
        nobody = code in (204, 304) or 100 <= code < 200
        self._start(code, ctype, None if nobody else len(body), extra)
        if self.command != "HEAD" and not nobody and body:
            self.wfile.write(body)

    def _json(self, obj, code=200, extra=()):
        self._send(code, json.dumps(obj, indent=None, separators=(",", ":")) + "\n", "application/json", extra)

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            data = bytearray()
            while True:
                line = self.rfile.readline(65537)
                if not line:
                    raise BadRequest("truncated chunked body")
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while True:  # trailers
                        t = self.rfile.readline(65537)
                        if t in (b"\r\n", b"\n", b""):
                            break
                    break
                data += self._read_exact(size)
                self.rfile.readline(3)  # CRLF
                if len(data) > MAX_BODY:
                    raise BadRequest("body too large")
            return bytes(data)
        cl = self.headers.get("Content-Length")
        if cl is None:
            return b""
        n = int(cl)
        if n > MAX_BODY:
            raise BadRequest("body too large")
        return self._read_exact(n)

    def _read_exact(self, n):
        data = self.rfile.read(n)
        if len(data) != n:
            raise BadRequest("truncated body")
        return data

    def _abs(self, target):
        host = self.headers.get("Host") or "%s:%d" % (self.connection.getsockname()[0], self.lab_port)
        return "%s://%s%s" % (self.lab_scheme, host, target)

    # ------------------------------------------------------------ dispatch
    def _handle(self):
        parts = urlsplit(self.path)
        path, query = parts.path, parts.query
        host = self.headers.get("Host", "-") or "-"
        if not (path == "/healthz" and self.client_address[0] == "127.0.0.1"):  # docker healthchecks: no log noise
            self.lab_log.write("%s %s %s %s %s" % (now_iso(), self.client_address[0], self.command, host, self.path))
        try:
            body = self._read_body()
        except (BadRequest, ValueError) as e:
            self.close_connection = True
            return self._send(400 if "large" not in str(e) else 413, "bad request: %s\n" % e)

        params = dict(parse_qsl(query, keep_blank_values=True))

        def num(key, default, lo=0, hi=None):
            raw = params.get(key)
            if raw is None:
                return default
            try:
                v = int(raw)
            except ValueError:
                raise BadRequest("%s must be an integer" % key)
            if v < lo or (hi is not None and v > hi):
                raise BadRequest("%s out of range" % key)
            return v

        try:
            if path == "/":
                return self._send(200, "lab server %s (%s)\n" % (self.lab_name, self.lab_scheme))
            if path == "/healthz":
                return self._send(200, "ok\n")
            if path == "/ip":
                return self._send(200, self.client_address[0])
            if path == "/echo":
                return self._echo(parts, body)
            if path == "/redirect":
                code = num("code", 302)
                if code not in (301, 302, 303, 307, 308):
                    raise BadRequest("code must be 301/302/303/307/308")
                to = params.get("to", "/ip")
                return self._send(code, "redirect %d -> %s\n" % (code, to), extra=[("Location", to)])
            if path == "/redirect-chain":
                n = num("n", 1, 0, 1000)
                code = num("code", 302)
                if code not in (301, 302, 303, 307, 308):
                    raise BadRequest("code must be 301/302/303/307/308")
                if n == 0:
                    return self._send(200, self.client_address[0])
                nxt = "/redirect-chain?n=%d&code=%d" % (n - 1, code) if n > 1 else "/ip"
                loc = nxt if params.get("rel") == "1" else self._abs(nxt)
                return self._send(code, "hop %d -> %s\n" % (n, loc), extra=[("Location", loc)])
            if path.startswith("/status/"):
                try:
                    code = int(path[len("/status/"):])
                except ValueError:
                    raise BadRequest("bad status")
                if not 200 <= code <= 599:
                    raise BadRequest("status must be 200..599")
                extra = [("Location", params["to"])] if "to" in params else []
                return self._send(code, "status %d\n" % code, extra=extra)
            if path == "/slow":
                time.sleep(num("ms", 1000, 0, 600000) / 1000.0)
                return self._send(200, "slow ok\n")
            if path == "/drip":
                return self._drip(num("bytes", 10, 0, 1 << 30), num("ms", 100, 0, 600000), num("chunk", 1, 1, 1 << 20))
            if path == "/stall":
                return self._stall()
            if path == "/bytes":
                return self._bytes(num("n", 1024, 0, 2 << 30))
            if path == "/chunked":
                return self._chunked(num("chunks", 3, 0, 100000), num("size", 16, 0, 1 << 24))
            if path == "/gzip":
                payload = json.dumps({"gzip": True, "message": "hello from %s" % self.lab_name, "pad": "x" * 200},
                                     separators=(",", ":")).encode()
                return self._send(200, self._gzip(payload), "application/json", [("Content-Encoding", "gzip")])
            if path == "/gzip-bomb":
                mb = num("mb", 10, 1, 4096)
                return self._send(200, gzip_bomb(mb), "application/octet-stream",
                                  [("Content-Encoding", "gzip"), ("X-Inflated-Bytes", str(mb << 20))])
            if path == "/headers-multi":
                extra = [("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/"),
                         ("X-Multi", "one"), ("X-Multi", "two")]
                return self._json({"set-cookie": ["a=1; Path=/", "b=2; Path=/"], "x-multi": ["one", "two"]}, extra=extra)
            return self._send(404, "not found: %s\n" % path)
        except BadRequest as e:
            return self._send(400, "bad request: %s\n" % e)

    @staticmethod
    def _gzip(data):
        co = zlib.compressobj(6, zlib.DEFLATED, 31)
        return co.compress(data) + co.flush()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

    # ------------------------------------------------------------ routes
    def _echo(self, parts, body):
        self._json({
            "method": self.command,
            "path": parts.path,
            "query": parts.query,
            "query_params": {k: [v for kk, v in parse_qsl(parts.query, keep_blank_values=True) if kk == k]
                             for k, _ in parse_qsl(parts.query, keep_blank_values=True)},
            "raw_target": self.path,
            "headers": [[k, v] for k, v in self.headers.items()],
            "body": body.decode("utf-8", "replace"),
            "body_length": len(body),
            "remote": self.client_address[0],
            "remote_port": self.client_address[1],
            "scheme": self.lab_scheme,
            "server_port": self.lab_port,
            "server": self.lab_name,
            "http_version": self.request_version,
        })

    def _drip(self, total, ms, chunk):
        self._start(200, "application/octet-stream", total)
        if self.command == "HEAD":
            return
        sent = 0
        while sent < total:
            n = min(chunk, total - sent)
            self.wfile.write(b"d" * n)
            self.wfile.flush()
            sent += n
            if sent < total:
                time.sleep(ms / 1000.0)

    def _stall(self):
        self.close_connection = True
        deadline = time.time() + 600
        conn = self.connection
        while time.time() < deadline:
            try:
                r, _, _ = select.select([conn], [], [], 1.0)
                if r and not conn.recv(4096):
                    return
            except (OSError, ValueError):
                return

    def _bytes(self, n):
        extra = [("X-Content-SHA256", bytes_sha256(n))] if n <= (256 << 20) else []
        self._start(200, "application/octet-stream", n, extra)
        if self.command == "HEAD":
            return
        full, rem = divmod(n, len(BLOCK))
        for _ in range(full):
            self.wfile.write(BLOCK)
        if rem:
            self.wfile.write(BLOCK[:rem])

    def _chunked(self, chunks, size):
        if self.request_version == "HTTP/1.0":  # no chunked in 1.0: fall back to close-delimited
            self.close_connection = True
            self._start(200, "text/plain; charset=utf-8", None)
            if self.command != "HEAD":
                for i in range(chunks):
                    self.wfile.write((chr(ord("a") + i % 26) * size).encode())
            return
        self._start(200, "text/plain; charset=utf-8", None, [("Transfer-Encoding", "chunked")])
        if self.command == "HEAD":
            return
        for i in range(chunks):
            data = (chr(ord("a") + i % 26) * size).encode()
            if data:  # a zero-size chunk would terminate the body
                self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
                self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256
    ssl_context = None

    def server_bind(self):  # HTTPServer.server_bind() does a reverse DNS lookup: skip it
        socketserver.TCPServer.server_bind(self)
        self.server_name = "lab"
        self.server_port = self.server_address[1]

    def finish_request(self, request, client_address):
        if self.ssl_context is None:
            self.RequestHandlerClass(request, client_address, self)
            return
        try:
            request.settimeout(15)
            tls = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            sys.stdout.write("%s TLS-ERROR port=%d client=%s %s\n" % (
                now_iso(), self.server_address[1], client_address[0], e))
            sys.stdout.flush()
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass


def serve(name, log, port, scheme, ca_dir, cert_base):
    cls = type("Handler%d" % port, (LabHandler,), dict(lab_name=name, lab_scheme=scheme, lab_port=port, lab_log=log))
    srv = LabServer(("0.0.0.0", port), cls)
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.path.join(ca_dir, cert_base + ".pem"), os.path.join(ca_dir, cert_base + ".key"))
        ctx.set_alpn_protocols(["http/1.1"])
        srv.ssl_context = ctx
    threading.Thread(target=srv.serve_forever, name="listen-%d" % port, daemon=True).start()
    print("%s listening %s on :%d%s" % (now_iso(), scheme, port, " cert=" + cert_base if scheme == "https" else ""), flush=True)
    return srv


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="server name (echo|secret)")
    ap.add_argument("--log", help="request log file (also written to stdout)")
    ap.add_argument("--http", type=int, action="append", default=[], metavar="PORT")
    ap.add_argument("--https", action="append", default=[], metavar="PORT:CERTBASE",
                    help="TLS listener; cert/key are CA_DIR/CERTBASE.pem/.key")
    ap.add_argument("--ca-dir", default="/state/ca")
    a = ap.parse_args()

    log = LineLog(a.log)
    servers = [serve(a.name, log, p, "http", a.ca_dir, None) for p in a.http]
    for spec in a.https:
        port, base = spec.split(":", 1)
        servers.append(serve(a.name, log, int(port), "https", a.ca_dir, base))

    def stop(*_):
        os._exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    threading.Event().wait()


if __name__ == "__main__":
    main()

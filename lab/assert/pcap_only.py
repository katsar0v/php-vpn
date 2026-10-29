#!/usr/bin/env python3
"""Assert that a packet capture contains ONLY traffic covered by allow rules.

    pcap_only.py --pcap lab/state/pcap/vpn.pcap \\
        --allow udp:198.51.100.10:51820 [--allow udp:198.51.100.53:53 ...]

Used by the php-vpn lab: during VPN-only requests the PHP container must emit
nothing but UDP to/from the WireGuard endpoint.  Pure python 3 stdlib; parses
classic libpcap files (tcpdump -w) itself - Ethernet, Linux cooked (SLL/SLL2),
raw IP and BSD loopback link types, IPv4 and IPv6 (extension headers skipped),
TCP / UDP / ICMP / ICMPv6.  pcapng is not supported.

Allow rules:   PROTO:HOST[:PORT]
    PROTO  udp | tcp | icmp | icmp6 | any
    HOST   IPv4/IPv6 address or CIDR, '*' for anything; IPv6 as [2001:db8::1]
    PORT   number or '*' (default '*'; ignored for icmp)
A packet is covered when some rule matches either its destination (traffic TO
the allowed endpoint) or its source (traffic FROM it, i.e. the replies).

ARP is always ignored (link-local housekeeping).  IPv6 neighbour discovery /
MLD (ICMPv6 types 130-137, 143) is ignored unless --strict-icmp6 is given.

Exit status: 0 = every packet covered (and every --require rule matched),
             1 = violations / unmet --require, 2 = bad input.
"""
import argparse
import collections
import ipaddress
import json
import struct
import sys

ETH_IPV4, ETH_ARP, ETH_VLAN, ETH_IPV6 = 0x0800, 0x0806, 0x8100, 0x86DD
LINKTYPES = {0: "NULL", 1: "ETHERNET", 12: "RAW", 14: "RAW", 101: "RAW", 108: "LOOP", 113: "LINUX_SLL", 276: "LINUX_SLL2"}
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}
ICMP6_HOUSEKEEPING = {130, 131, 132, 133, 134, 135, 136, 143}


class PcapError(Exception):
    pass


class Packet:
    __slots__ = ("index", "ts", "proto", "src", "dst", "sport", "dport", "length", "info", "kind")

    def __init__(self, index, ts, length):
        self.index, self.ts, self.length = index, ts, length
        self.proto = self.src = self.dst = None
        self.sport = self.dport = None
        self.info = ""
        self.kind = "ip"  # ip | arp | other

    def flow(self):
        s = fmt_ep(self.src, self.sport)
        d = fmt_ep(self.dst, self.dport)
        return "%s %s -> %s" % (self.proto, s, d)


def fmt_ep(ip, port):
    if ip is None:
        return "?"
    s = "[%s]" % ip if ":" in str(ip) else str(ip)
    return s if port is None else "%s:%d" % (s, port)


# --------------------------------------------------------------------------- pcap reader
def read_pcap(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise PcapError("file too short for a pcap header (%d bytes)" % len(hdr))
        magic = hdr[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            end, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            end, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            end, nano = ">", True
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise PcapError("pcapng is not supported; capture with `tcpdump -w` (classic pcap)")
        else:
            raise PcapError("not a pcap file (magic %s)" % magic.hex())
        _vmaj, _vmin, _tz, _sig, snaplen, linktype = struct.unpack(end + "HHiIII", hdr[4:])
        linktype &= 0x0FFFFFFF
        records = []
        truncated = False
        while True:
            rh = f.read(16)
            if not rh:
                break
            if len(rh) < 16:
                truncated = True
                break
            sec, frac, incl, orig = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                truncated = True
                break
            ts = sec + frac / (1e9 if nano else 1e6)
            records.append((ts, orig, data))
    return linktype, records, truncated


# --------------------------------------------------------------------------- decoding
def decode(index, ts, orig, data, linktype):
    p = Packet(index, ts, orig)
    ethertype = None
    payload = b""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            p.kind, p.info = "other", "short ethernet frame"
            return p
        ethertype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while ethertype in (ETH_VLAN, 0x88A8) and len(data) >= off + 4:
            ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        payload = data[off:]
    elif linktype == 113:  # Linux cooked v1
        if len(data) < 16:
            p.kind, p.info = "other", "short SLL frame"
            return p
        ethertype = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
    elif linktype == 276:  # Linux cooked v2
        if len(data) < 20:
            p.kind, p.info = "other", "short SLL2 frame"
            return p
        ethertype = struct.unpack("!H", data[0:2])[0]
        payload = data[20:]
    elif linktype in (12, 14, 101):  # raw IP
        v = data[0] >> 4 if data else 0
        ethertype = ETH_IPV4 if v == 4 else ETH_IPV6 if v == 6 else None
        payload = data
    elif linktype in (0, 108):  # BSD loopback
        if len(data) < 4:
            p.kind, p.info = "other", "short loopback frame"
            return p
        fam = struct.unpack("<I" if linktype == 0 else ">I", data[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I" if linktype == 0 else "<I", data[:4])[0]
        ethertype = ETH_IPV4 if fam == 2 else ETH_IPV6 if fam in (10, 24, 28, 30) else None
        payload = data[4:]
    else:
        raise PcapError("unsupported link type %d" % linktype)

    if ethertype == ETH_ARP:
        p.kind, p.info = "arp", "ARP"
        return p
    if ethertype == ETH_IPV4:
        decode_ipv4(p, payload)
    elif ethertype == ETH_IPV6:
        decode_ipv6(p, payload)
    else:
        p.kind, p.info = "other", "ethertype %s" % (("0x%04x" % ethertype) if ethertype is not None else "unknown")
    return p


def decode_l4(p, proto, payload):
    p.proto = PROTO_NAMES.get(proto, "ip-proto-%d" % proto)
    if proto == 17 and len(payload) >= 8:
        p.sport, p.dport = struct.unpack("!HH", payload[:4])
    elif proto == 6 and len(payload) >= 14:
        p.sport, p.dport = struct.unpack("!HH", payload[:4])
        flags = payload[13]
        names = [n for bit, n in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")) if flags & bit]
        p.info = "+".join(names)
    elif proto in (1, 58) and len(payload) >= 2:
        p.info = "type %d code %d" % (payload[0], payload[1])
        if proto == 58 and payload[0] in ICMP6_HOUSEKEEPING:
            p.kind = "icmp6-nd"


def decode_ipv4(p, b):
    if len(b) < 20 or b[0] >> 4 != 4:
        p.kind, p.info = "other", "bad IPv4 header"
        return
    ihl = (b[0] & 0x0F) * 4
    proto = b[9]
    frag = struct.unpack("!H", b[6:8])[0] & 0x1FFF
    p.src = ipaddress.IPv4Address(b[12:16])
    p.dst = ipaddress.IPv4Address(b[16:20])
    if frag:
        p.proto, p.info = PROTO_NAMES.get(proto, "ip-proto-%d" % proto), "non-first fragment"
        return
    decode_l4(p, proto, b[ihl:])


def decode_ipv6(p, b):
    if len(b) < 40 or b[0] >> 4 != 6:
        p.kind, p.info = "other", "bad IPv6 header"
        return
    nxt = b[6]
    p.src = ipaddress.IPv6Address(b[8:24])
    p.dst = ipaddress.IPv6Address(b[24:40])
    off = 40
    while nxt in (0, 43, 60, 44, 51) and len(b) >= off + 8:  # hop-by-hop, routing, dest opts, fragment, AH
        if nxt == 44:
            ext_len = 8
        elif nxt == 51:
            ext_len = (b[off + 1] + 2) * 4
        else:
            ext_len = (b[off + 1] + 1) * 8
        nxt = b[off]
        off += ext_len
    decode_l4(p, nxt, b[off:])


# --------------------------------------------------------------------------- rules
class Rule:
    def __init__(self, text):
        self.text = text
        parts = text.strip()
        if ":" not in parts:
            raise ValueError("rule %r must look like proto:host[:port]" % text)
        proto, rest = parts.split(":", 1)
        proto = proto.lower()
        if proto not in ("udp", "tcp", "icmp", "icmp6", "any"):
            raise ValueError("rule %r: unknown protocol %r" % (text, proto))
        self.proto = proto
        if rest.startswith("["):
            host, _, tail = rest[1:].partition("]")
            port = tail[1:] if tail.startswith(":") else "*"
        elif rest.count(":") >= 2:
            host, port = rest, "*"  # bare IPv6, no port
        else:
            host, _, port = rest.partition(":")
            port = port or "*"
        if host in ("*", ""):
            self.net = None
        else:
            try:
                self.net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                raise ValueError("rule %r: bad host %r" % (text, host))
        if port == "*":
            self.port = None
        else:
            try:
                self.port = int(port)
            except ValueError:
                raise ValueError("rule %r: bad port %r" % (text, port))
        self.hits = 0

    def _ep(self, ip, port):
        if self.net is not None and (ip is None or ip.version != self.net.version or ip not in self.net):
            return False
        if self.port is not None and port != self.port:
            return False
        return True

    def matches(self, p):
        if self.proto != "any" and p.proto != self.proto:
            return False
        return self._ep(p.dst, p.dport) or self._ep(p.src, p.sport)


# --------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True, help="classic libpcap file")
    ap.add_argument("--allow", action="append", default=[], metavar="RULE", help="allowed traffic, e.g. udp:198.51.100.10:51820 (repeatable)")
    ap.add_argument("--require", action="append", default=[], metavar="RULE", help="like --allow, and at least one packet must match")
    ap.add_argument("--ip", help="only judge packets whose source or destination is this address (default: all packets)")
    ap.add_argument("--strict-icmp6", action="store_true", help="do not ignore IPv6 neighbour discovery / MLD")
    ap.add_argument("--max-violations", type=int, default=20, help="distinct violating flows to list (default 20)")
    ap.add_argument("--json", action="store_true", help="machine readable result on stdout")
    a = ap.parse_args(argv)

    try:
        rules = [Rule(r) for r in a.allow]
        req = [Rule(r) for r in a.require]
    except ValueError as e:
        print("pcap_only: %s" % e, file=sys.stderr)
        return 2
    rules += req
    only_ip = ipaddress.ip_address(a.ip) if a.ip else None

    try:
        linktype, records, truncated = read_pcap(a.pcap)
    except (OSError, PcapError) as e:
        print("pcap_only: %s: %s" % (a.pcap, e), file=sys.stderr)
        return 2
    if linktype not in LINKTYPES:
        print("pcap_only: unsupported link type %d" % linktype, file=sys.stderr)
        return 2

    flows = collections.OrderedDict()        # allowed flows summary
    violations = collections.OrderedDict()   # distinct violating flows
    counts = collections.Counter()
    t0 = records[0][0] if records else 0.0
    nbytes = 0
    for i, (ts, orig, data) in enumerate(records, 1):
        p = decode(i, ts, orig, data, linktype)
        nbytes += orig
        if p.kind == "arp":
            counts["arp-ignored"] += 1
            continue
        if p.kind == "icmp6-nd" and not a.strict_icmp6:
            counts["icmp6-nd-ignored"] += 1
            continue
        if only_ip is not None and only_ip not in (p.src, p.dst):
            counts["other-host-ignored"] += 1
            continue
        hit = None
        if p.kind == "ip":
            for r in rules:
                if r.matches(p):
                    r.hits += 1
                    hit = hit or r
        if hit is not None:
            counts["allowed"] += 1
            key = hit.text
            f = flows.setdefault(key, [0, 0])
            f[0] += 1
            f[1] += orig
        else:
            counts["violations"] += 1
            key = p.flow() if p.kind == "ip" else "non-ip frame (%s)" % p.info
            # collapse client ephemeral ports so one connection attempt is one line
            v = violations.get(key)
            if v is None:
                violations[key] = {"count": 1, "first_index": i, "first_t": ts - t0, "info": p.info, "bytes": orig}
            else:
                v["count"] += 1
                v["bytes"] += orig

    unmet = [r.text for r in req if r.hits == 0]
    ok = not violations and not unmet

    if a.json:
        print(json.dumps({
            "ok": ok, "pcap": a.pcap, "linktype": LINKTYPES[linktype], "packets": len(records), "bytes": nbytes,
            "truncated": truncated, "counts": dict(counts),
            "allowed": {k: {"packets": v[0], "bytes": v[1]} for k, v in flows.items()},
            "violations": [dict(flow=k, **v) for k, v in violations.items()],
            "unmet_require": unmet,
        }, indent=2))
        return 0 if ok else 1

    span = (records[-1][0] - t0) if records else 0.0
    print("pcap_only: %s" % a.pcap)
    print("  linktype=%s packets=%d bytes=%d span=%.3fs%s" % (
        LINKTYPES[linktype], len(records), nbytes, span, "  (TRUNCATED last record)" if truncated else ""))
    print("  allowed=%d violations=%d ignored(arp/nd/other-host)=%d" % (
        counts["allowed"], counts["violations"],
        counts["arp-ignored"] + counts["icmp6-nd-ignored"] + counts["other-host-ignored"]))
    for k, (n, b) in flows.items():
        print("  ALLOWED  %-40s %6d pkts %9d bytes" % (k, n, b))
    for k in unmet:
        print("  UNMET    --require %s matched no packet" % k)
    shown = 0
    for k, v in violations.items():
        if shown >= a.max_violations:
            print("  ... %d more violating flow(s)" % (len(violations) - shown))
            break
        shown += 1
        print("  VIOLATION %s  x%d (first: packet #%d at +%.3fs%s)" % (
            k, v["count"], v["first_index"], v["first_t"], ", " + v["info"] if v["info"] else ""))
    if not records:
        print("  WARNING  capture holds 0 packets: the check is vacuous (use --require to demand traffic)")
    print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

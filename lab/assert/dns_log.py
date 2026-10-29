#!/usr/bin/env python3
"""Assert on the dnsmasq query logs of the php-vpn lab.

    dns_log.py --log lab/state/logs/hostdns.log --since 1793282228.5 \\
               --forbid secret.vpn.test [--forbid echo.lab.test] [--client 198.51.100.40]
    dns_log.py --log lab/state/logs/hostdns.log --since "$T0" --expect echo.lab.test

Fails (exit 1) if a --forbid name was queried at/after --since (and before --until,
and from one of the --client addresses when given), or if an --expect name was NOT
queried in that window.  Exit 2 on unreadable log / bad arguments.  Pure stdlib.

Log format (written by lab/tools/dnsmasq-run.sh, `log-queries=extra`):
    2026-10-29T15:50:12.345Z dnsmasq[7]: 12 198.51.100.40/41234 query[A] echo.lab.test from 198.51.100.40
Plain dnsmasq lines ("Oct 29 15:50:12 dnsmasq[7]: query[A] name from ip", UTC) are
understood too.

--since / --until: unix timestamp (float) or ISO-8601 (naive = UTC).  Queries are
matched to the millisecond.  By default the script waits --settle seconds (0.3)
before reading, because dnsmasq's log reaches the file asynchronously - this keeps
"nothing was queried" checks that run right after a request from racing.

NAME matching is case-insensitive and exact; a leading '.' or '*.' matches the
domain and everything below it (e.g. '*.vpn.test').
"""
import argparse
import re
import sys
import time
from datetime import datetime, timezone

ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+Z)\s+dnsmasq\[\d+\]:\s+(?:\d+\s+\S+\s+)?"
    r"query\[(?P<qtype>[A-Za-z0-9]+)\]\s+(?P<name>\S+)\s+from\s+(?P<client>\S+)")
NATIVE_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+dnsmasq\[\d+\]:\s+(?:\d+\s+\S+\s+)?"
    r"query\[(?P<qtype>[A-Za-z0-9]+)\]\s+(?P<name>\S+)\s+from\s+(?P<client>\S+)")


def parse_when(text):
    text = text.strip()
    try:
        return float(text)
    except ValueError:
        pass
    t = text.replace("Z", "+00:00").replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        raise argparse.ArgumentTypeError("not a unix timestamp or ISO-8601 time: %r" % text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def line_time(m, native):
    s = m.group("ts")
    if not native:
        return datetime.strptime(s.rstrip("Z") + "+0000", "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() if "." in s \
            else datetime.strptime(s.rstrip("Z") + "+0000", "%Y-%m-%dT%H:%M:%S%z").timestamp()
    now = datetime.now(timezone.utc)
    dt = datetime.strptime("%d %s" % (now.year, re.sub(r"\s+", " ", s)), "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    if dt > now.replace(microsecond=0) and (dt - now).days > 1:
        dt = dt.replace(year=now.year - 1)
    return dt.timestamp()


def norm(name):
    return name.strip().lower().rstrip(".")


def name_matches(pattern, name):
    pattern = norm(pattern)
    if pattern.startswith("*."):
        pattern = pattern[1:]
    if pattern.startswith("."):
        return name == pattern[1:] or name.endswith(pattern)
    return name == pattern


def read_queries(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ISO_LINE.match(line)
            native = False
            if not m:
                m = NATIVE_LINE.match(line)
                native = True
            if not m:
                continue
            out.append((line_time(m, native), m.group("qtype"), norm(m.group("name")), m.group("client"), line.rstrip("\n")))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", required=True, help="dnsmasq query log (hostdns.log or tunneldns.log)")
    ap.add_argument("--since", required=True, type=parse_when, help="window start (unix ts or ISO-8601)")
    ap.add_argument("--until", type=parse_when, help="window end (default: now / end of log)")
    ap.add_argument("--forbid", action="append", default=[], metavar="NAME", help="fail if this name was queried (repeatable)")
    ap.add_argument("--expect", action="append", default=[], metavar="NAME", help="fail if this name was NOT queried (repeatable)")
    ap.add_argument("--client", action="append", default=[], metavar="IP", help="only consider queries from this source address (repeatable)")
    ap.add_argument("--qtype", action="append", default=[], metavar="TYPE", help="only consider these query types, e.g. A (repeatable)")
    ap.add_argument("--settle", type=float, default=0.3, help="seconds to wait before reading the log (default 0.3)")
    ap.add_argument("--show", action="store_true", help="print every query in the window")
    a = ap.parse_args(argv)
    if not a.forbid and not a.expect and not a.show:
        ap.error("give at least one of --forbid / --expect / --show")

    if a.settle > 0:
        time.sleep(a.settle)
    try:
        queries = read_queries(a.log)
    except OSError as e:
        print("dns_log: cannot read %s: %s" % (a.log, e), file=sys.stderr)
        return 2

    qtypes = {t.upper() for t in a.qtype}
    window = [q for q in queries
              if q[0] >= a.since and (a.until is None or q[0] <= a.until)
              and (not a.client or q[3] in a.client) and (not qtypes or q[1].upper() in qtypes)]

    print("dns_log: %s: %d queries in window (since %s%s%s)" % (
        a.log, len(window), datetime.fromtimestamp(a.since, timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z",
        ", until %s" % datetime.fromtimestamp(a.until, timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z" if a.until else "",
        ", clients %s" % ",".join(a.client) if a.client else ""))
    if a.show:
        for q in window:
            print("  %s query[%s] %s from %s" % (datetime.fromtimestamp(q[0], timezone.utc).strftime("%H:%M:%S.%f")[:-3], q[1], q[2], q[3]))

    failed = False
    for pat in a.forbid:
        hits = [q for q in window if name_matches(pat, q[2])]
        if hits:
            failed = True
            print("FAIL  forbidden name %s was queried %d time(s):" % (pat, len(hits)))
            for q in hits[:10]:
                print("      %s" % q[4])
        else:
            print("ok    %s was not queried" % pat)
    for pat in a.expect:
        hits = [q for q in window if name_matches(pat, q[2])]
        if hits:
            print("ok    %s was queried %d time(s) (e.g. from %s)" % (pat, len(hits), hits[0][3]))
        else:
            failed = True
            print("FAIL  expected name %s was never queried" % pat)
    print("RESULT: %s" % ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

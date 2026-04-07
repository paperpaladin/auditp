#!/usr/bin/env python3
"""Put a packed sockaddr to ausearch and to auditp and compare the two.

The corpus holds five SOCKADDR records, which is five of the shapes
libaudit renders and none of the boundaries.  This builds a log of every
address family, the lengths either side of the point where each
structure becomes long enough to read, and a set of IPv6 addresses
chosen for the places two inet_ntop implementations drift apart.

Nothing here is a value worked out by hand.  The expected string is
whatever ausearch printed for the same bytes in the same run, so this is
one source and not two, which the README says; libaudit's source is not
installed here and the uapi headers describe the structures and not the
rendering.  It is still external: ausearch decides and this only asks.

Three outcomes, kept apart, the same three the field comparison uses:

  SAME      auditp printed what ausearch printed
  REFUSED   auditp declined and printed the hex it was given.  ax25,
            atmpvc and x25 are refused deliberately; see saddr.go.
  DIFFER    auditp claimed the field and printed something else.  The
            only failure.

Exit 1 on any DIFFER, or if ausearch answered fewer cases than it was
asked, which would make the comparison quietly smaller than it looks.
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

AUSEARCH = "/usr/sbin/ausearch"


def cases():
    """(label, sockaddr bytes), in a fixed order."""
    out = []

    # Every family at one length.  This is what separates the families
    # with a renderer of their own from the ones that come out as
    # "(unsupported)" and the numbers ausearch has no name for at all.
    for fam in range(0, 46):
        out.append(("family-%d" % fam,
                    struct.pack("<H", fam) + bytes([0x41] * 30)))

    # AF_UNIX.  The two-byte sockaddr is an unnamed socket, three bytes
    # is too short, and from four on it is a path.  An abstract socket's
    # name starts after a leading NUL.
    out.append(("local-bare", struct.pack("<H", 1)))
    out.append(("local-1", struct.pack("<H", 1) + b"A"))
    out.append(("local-2", struct.pack("<H", 1) + b"AB"))
    out.append(("local-path",
                struct.pack("<H", 1) + b"/run/widget.sock" + bytes(10)))
    out.append(("local-abstract",
                struct.pack("<H", 1) + b"\0abstract-name" + bytes(5)))
    out.append(("local-allzero", struct.pack("<H", 1) + bytes(20)))
    out.append(("local-full", struct.pack("<H", 1) + b"B" * 106))

    # AF_INET, around the 16 bytes of a sockaddr_in.
    for n in (0, 12, 13, 14, 15):
        out.append(("inet-len%d" % (n + 2), struct.pack("<H", 2) + bytes(n)))
    for addr, port in ((b"\x0a\x00\x00\x01", 443), (b"\x00\x00\x00\x00", 0),
                       (b"\xff\xff\xff\xff", 65535), (b"\x7f\x00\x00\x01", 1),
                       (b"\xc0\xa8\x01\x7f", 32768)):
        out.append(("inet-%d" % port,
                    struct.pack("<H", 2) + struct.pack(">H", port)
                    + addr + bytes(8)))

    # AF_INET6, around the 28 bytes of a sockaddr_in6, then the
    # addresses where a hand-written formatter and inet_ntop part
    # company: the all-zero one, a single run, two runs of equal length,
    # a run at each end, and the v4-mapped form that Go's own
    # net.IP.String would print as a dotted quad.
    for n in (24, 25, 26):
        out.append(("inet6-len%d" % (n + 2), struct.pack("<H", 10) + bytes(n)))
    v6 = [
        ("unspecified", "00000000000000000000000000000000"),
        ("loopback", "00000000000000000000000000000001"),
        ("v4mapped", "00000000000000000000ffff01020304"),
        ("v4compat", "00000000000000000000000001020304"),
        ("doc", "20010db8000000000000000000000001"),
        ("tworuns", "20010db80000000000010000000000ff"),
        ("tworuns-equal", "20010000000100000002000000030004"),
        ("leading", "00010002000300040005000600070008"),
        ("full", "fe800000000000000202b3fffe1e8329"),
        ("trailing", "20010db8000000000000000000000000"),
        ("onegroup", "20010db80001000200030004000500ff"),
        ("singlezero", "2001000000020003000400050006000 7"),
    ]
    for label, hexa in v6:
        a = bytes.fromhex(hexa.replace(" ", ""))
        out.append(("inet6-" + label,
                    struct.pack("<H", 10) + struct.pack(">H", 80) + bytes(4)
                    + a + bytes(4)))
    out.append(("inet6-scope",
                struct.pack("<H", 10) + struct.pack(">H", 80) + bytes(4)
                + bytes.fromhex("fe800000000000000202b3fffe1e8329")
                + struct.pack("<I", 3)))

    # AF_NETLINK, around the 12 bytes of a sockaddr_nl.
    for n in (8, 9, 10):
        out.append(("netlink-len%d" % (n + 2),
                    struct.pack("<H", 16) + bytes(n)))
    for pid in (0, 1, 1234, 4294967295):
        out.append(("netlink-%d" % pid,
                    struct.pack("<H", 16) + bytes(2) + struct.pack("<I", pid)
                    + struct.pack("<I", 0)))

    # Not a sockaddr at all.
    out.append(("empty", b""))
    out.append(("one-byte", b"\x02"))
    out.append(("high-family", struct.pack("<H", 4095) + bytes(30)))
    return out


SADDR = re.compile(r"(?:^| )saddr=(.*?)\s*$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditp", default="./auditp")
    args = ap.parse_args()

    cs = cases()
    d = tempfile.mkdtemp(prefix="auditp-saddr-")
    path = os.path.join(d, "s.log")
    try:
        with open(path, "w") as f:
            for i, (_, blob) in enumerate(cs):
                f.write("type=SOCKADDR msg=audit(1700000000.%03d:%d): "
                        "saddr=%s\n"
                        % (i % 1000, 800000 + i, blob.hex().upper()))
        env = dict(os.environ)
        env["TZ"] = "UTC"
        env["LC_ALL"] = "C"
        p = subprocess.run([AUSEARCH, "-i", "-if", path],
                           capture_output=True, env=env)
        want = {}
        pat = re.compile(r"^type=\S+ msg=audit\([^)]*:(\d+)\) : (.*)")
        for line in p.stdout.decode("utf-8", "replace").splitlines():
            m = pat.match(line)
            if not m:
                continue
            v = SADDR.search(m.group(2))
            if v:
                want[int(m.group(1)) - 800000] = v.group(1)

        q = subprocess.run([args.auditp, "-o", "flat", "-i", path],
                           capture_output=True, env=env)
        got = {}
        for line in q.stdout.decode("utf-8", "surrogateescape").splitlines():
            f = line.split("\t")
            if len(f) >= 5 and f[2] == "saddr":
                got[int(f[0].split(":")[1]) - 800000] = (f[3], f[4])

        same = refused = differ = 0
        missing = 0
        bad = []
        for i, (label, _) in enumerate(cs):
            if i not in want:
                missing += 1
                continue
            if i not in got:
                differ += 1
                bad.append("%s: auditp emitted no saddr field" % label)
                continue
            flag, val = got[i]
            if val == want[i]:
                same += 1
            elif flag != "i":
                refused += 1
            else:
                differ += 1
                bad.append("%s:\n    ours   %r\n    oracle %r"
                           % (label, val, want[i]))

        print("cases    %d" % len(cs))
        print("answered %d" % len(want))
        print("same     %d" % same)
        print("refused  %d" % refused)
        print("differ   %d" % differ)
        print("missing  %d" % missing)
        for line in bad[:12]:
            print("  DIFFER %s" % line)
        if missing:
            print("  ausearch did not answer %d cases, so they were not "
                  "tested" % missing)
        return 1 if differ or missing else 0
    finally:
        os.unlink(path)
        os.rmdir(d)


if __name__ == "__main__":
    sys.exit(main())

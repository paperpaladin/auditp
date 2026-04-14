#!/usr/bin/env python3
"""Put TTY keystroke data to ausearch and to auditp and compare.

A TTY record's data= field is the bytes somebody typed, and ausearch
renders it as quoted text with the control keys named.  The corpus has
one such record, which reaches one of the three rules.  This builds
several hundred: every single byte, every escape sequence the table was
probed for and a few it was not, the boundaries between a text run and a
named key, and the bytes that have to be escaped inside a quoted run.

The expected string is whatever ausearch printed for the same bytes in
the same run; see t/tables.py for why this one table has no second
source.

Exit 1 on any difference, or if ausearch left a case unanswered.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

AUSEARCH = "/usr/sbin/ausearch"
DATA = re.compile(r"(?:^| )data=(.*?)\s*$")


def cases():
    out = []
    for b in range(0, 256):
        out.append(("byte-%02x" % b, bytes([b])))
    # A named key between two text runs, two keys in a row, a key at
    # each end: the places a renderer that forgets to close or open a
    # quoted run goes wrong.
    for mid in (b"\r", b"\x1b[A", b"\x00", b"\x1c", b"\x7f"):
        out.append(("mid-%s" % mid.hex(), b"ab" + mid + b"cd"))
        out.append(("lead-%s" % mid.hex(), mid + b"cd"))
        out.append(("trail-%s" % mid.hex(), b"ab" + mid))
        out.append(("double-%s" % mid.hex(), mid + mid))
    # Escape sequences, including the ones that consume fewer bytes than
    # they look like and the ones that are not in the table at all.
    for seq in (b"[A", b"[B", b"[C", b"[D", b"[H", b"[F", b"[Z", b"[M",
                b"[1~", b"[2~", b"[3~", b"[4~", b"[5~", b"[6~", b"[7~",
                b"[8~", b"[9~", b"[10~", b"[11~", b"[15~", b"[17~",
                b"[23~", b"[24~", b"[29~", b"[30~", b"[99~", b"[123~",
                b"OP", b"OQ", b"OR", b"OS", b"OA", b"OM", b"X", b"[",
                b"O", b"[3", b"[~", b"", b"\x1b"):
        out.append(("esc-%s" % seq.hex(), b"\x1b" + seq))
        out.append(("escmid-%s" % seq.hex(), b"x" + b"\x1b" + seq + b"y"))
    # Quoting.
    out.append(("quote", b'say "x"'))
    out.append(("backslash", b"a\\b"))
    out.append(("both", b'a"b\\c'))
    out.append(("highbytes", "\u00e9\u20ac".encode()))
    out.append(("nul-inside", b"hi\x00there"))
    out.append(("long", b"A" * 200))
    out.append(("mixed", b"ls -l\r\x1b[Acd\x7f\x7f\x1bOPz"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditp", default="./auditp")
    args = ap.parse_args()

    cs = cases()
    d = tempfile.mkdtemp(prefix="auditp-tty-")
    path = os.path.join(d, "t.log")
    try:
        with open(path, "w") as f:
            for i, (_, blob) in enumerate(cs):
                f.write("type=TTY msg=audit(1700000000.%03d:%d): data=%s\n"
                        % (i % 1000, 700000 + i,
                           blob.hex().upper() if blob else "(null)"))
        env = dict(os.environ)
        env["TZ"] = "UTC"
        env["LC_ALL"] = "C"
        p = subprocess.run([AUSEARCH, "-i", "-if", path],
                           capture_output=True, env=env)
        pat = re.compile(r"^type=\S+ msg=audit\([^)]*:(\d+)\) : (.*)")
        want = {}
        for line in p.stdout.decode("utf-8", "surrogateescape").splitlines():
            m = pat.match(line)
            if not m:
                continue
            v = DATA.search(m.group(2))
            if v:
                want[int(m.group(1)) - 700000] = v.group(1)

        q = subprocess.run([args.auditp, "-o", "flat", "-i", path],
                           capture_output=True, env=env)
        got = {}
        for line in q.stdout.decode("utf-8", "surrogateescape").splitlines():
            f = line.split("\t")
            if len(f) >= 5 and f[2] == "data":
                got[int(f[0].split(":")[1]) - 700000] = (f[3], f[4])

        same = differ = missing = refused = 0
        bad = []
        for i, (label, _) in enumerate(cs):
            if i not in want:
                missing += 1
                continue
            if i not in got:
                differ += 1
                bad.append("%s: auditp emitted no data field" % label)
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
        return 1 if differ or missing else 0
    finally:
        os.unlink(path)
        os.rmdir(d)


if __name__ == "__main__":
    sys.exit(main())

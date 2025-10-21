#!/usr/bin/env python3
"""Ask ausearch which field names it hex-decodes.

The kernel hex-encodes a value only when it holds a byte outside
0x21..0x7e or a double quote, and which FIELDS that can happen to is a
table inside libaudit.  Guessing it is how a reader ends up decoding
op=4558454355544544 into bytes, or leaving every cmd= unreadable.

So it is measured.  One record is written for each (record type, field
name) pair that occurs in the corpus, with that field set to 5A71, which
is the hex for Zq.  ausearch is asked to interpret the file, and the pairs
where Zq came back are the ones it decodes.  The pair and not just the
name, because a0 in an EXECVE record is an argument string and decodes
while a0 in a SYSCALL record is a register value and does not.  TTY data comes back as "Zq",
quotes included, because ausearch renders that field in a format of its
own; it still decoded, so it counts.

This is derived from the oracle rather than from an independent source,
and the README says so.  What it buys is that the table cannot go stale
without the suite noticing: t/run.sh runs this probe on every run and
diffs it against the table auditp compiled in.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

AUSEARCH = "/usr/sbin/ausearch"
PROBE = "5A71"
PLAIN = "Zq"
HDR = re.compile(r"^(?:node=\S+ )?type=(\S+) msg=audit\([^)]*\): ?(.*)")
# The character before a field name is the start of the body, a space, or
# the opening quote of a nested msg='...' list.  Leaving the quote out of
# this class hid exactly one pair, USER_CMD cwd, which is the first field
# inside the quote and therefore never had a space before it.
FIELD = re.compile(r"(?:^|[ ('])([A-Za-z][A-Za-z0-9_-]*)=")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    args = ap.parse_args()

    # A real record of that type with the one field's value replaced, not
    # a synthetic record holding only that field.  The first version wrote
    # "type=SYSCALL msg=audit(...): comm=5A71" and ausearch answered
    # nothing for 35 of the 497 pairs, so six fields auditp decodes looked
    # unconfirmed when they had simply not been asked about.
    sample = {}
    with open(args.corpus, "r", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            m = HDR.match(line)
            if not m:
                continue
            for fm in FIELD.finditer(m.group(2)):
                key = (m.group(1), fm.group(1))
                if key not in sample:
                    sample[key] = (line, m.start(2) + fm.end())
    pairs = sorted(sample)

    lines = []
    index = {}
    for i, key in enumerate(pairs):
        serial = 7000000 + i
        index[serial] = key
        line, at = sample[key]
        # Replace the value that starts at `at` with the probe.
        rest = line[at:]
        if rest[:1] == '"':
            end = rest.find('"', 1) + 1
        elif rest[:1] == "'":
            end = rest.find("'", 1) + 1
        elif rest[:1] in (" ", ""):
            end = 0
        else:
            end = rest.find(" ")
            if end < 0:
                end = len(rest)
        line = line[:at] + PROBE + rest[end:]
        line = re.sub(r"msg=audit\([^)]*\)",
                      "msg=audit(1700000000.%03d:%d)" % (i % 1000, serial),
                      line, count=1)
        lines.append(line)
    fd, path = tempfile.mkstemp(prefix="auditp-escaped-")
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode())
        os.close(fd)
        env = dict(os.environ)
        env["TZ"] = "UTC"
        p = subprocess.run([AUSEARCH, "-i", "-if", path],
                           capture_output=True, env=env)
    finally:
        os.unlink(path)

    out = p.stdout.decode("utf-8", "surrogateescape")
    decoded = set()
    answered = 0
    pat = re.compile(r"^(?:node=\S+ )?type=\S+ msg=audit\([^)]*:(\d+)\) : (.*)")
    for line in out.splitlines():
        m = pat.match(line)
        if not m:
            continue
        serial = int(m.group(1))
        if serial not in index:
            continue
        answered += 1
        body = m.group(2).rstrip()
        if PLAIN in body and PROBE not in body:
            decoded.add(index[serial])

    if not answered:
        sys.stderr.write("escaped probe: ausearch answered nothing\n")
        return 2
    sys.stderr.write("escaped probe: %d pairs, %d answered, %d decode\n"
                     % (len(pairs), answered, len(decoded)))
    for t, n in sorted(decoded):
        print("%s %s" % (t, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())

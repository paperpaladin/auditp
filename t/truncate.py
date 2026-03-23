#!/usr/bin/env python3
"""Feed auditp truncated and corrupted logs and compare it with ausearch.

An audit log is attacker-influenced in anything that ships one off a
machine.  Two failures are worth separating here and neither is folded
into the other: a crash, and refusing a record the authority reads.

Three sweeps:

  BYTE PREFIX   every prefix of the corpus at a stride, so the last line
                of the file stops in the middle of a value.  Crash check
                only.  See below for why the record counts are not
                compared here.
  LINE PREFIX   every prefix at a line boundary.  Both sides see only
                whole records, so the counts are comparable, and auditp
                must also read exactly one record per line.
  FLIP          single bytes overwritten with one of a set chosen to
                break the parse in different places: 0xFF and 0x00 for
                the decoder, '=' and '"' and ' ' and ':' for the
                splitter, since a byte that invents structure is worse
                than one that destroys it.  Crash check, plus a count of
                each direction of disagreement, which the caller puts a
                ceiling on.  Not a pass/fail comparison: a flip inside
                "type=SYSCALL msg=" leaves a line ausearch still reads,
                because it hunts for "msg=audit(" rather than requiring
                it where the format puts it, and auditp requiring it
                there is the stricter and better-defined behaviour
                rather than a gap.
  LONG          a line longer than the reader's buffer, with a valid
                record on each side of it.

Why the byte prefixes are not compared.  auditp is a lexer: a line whose
header parses is a record to it.  ausearch parses a SYSCALL record into a
struct and wants the fields that struct needs, so it reads nothing from
the first 190 bytes of the corpus's first record and reads it at byte
200.  It is also looser than auditp about the header itself and takes
"msg=audit(1700000000.137:1001" with no closing parenthesis at all.
Comparing counts there measures the difference between a lexer and an
event reconstructor, which is real and is in the README, and it would
drown the one thing this sweep is for.

A crash is any exit status other than 0 or 1.  auditp's contract says 2
is a usage error, so a 2 out of a parse is a bug, and a negative status
is a signal.

Exit 1 if anything crashed, if auditp refused a LINE-ALIGNED case
ausearch read, if a line-aligned prefix did not give one record per
line, or if the long line cost auditp the records around it.
"""

import argparse
import os
import subprocess
import sys
import tempfile

AUSEARCH = "/usr/sbin/ausearch"


def ours(auditp, path, strict=False):
    """(exit status, records read).  Negative status means a signal."""
    cmd = [auditp, "-o", "flat", path]
    if strict:
        cmd.insert(1, "-strict")
    p = subprocess.run(cmd, capture_output=True)
    keys = set()
    for line in p.stdout.split(b"\n"):
        f = line.split(b"\t")
        if len(f) >= 3:
            keys.add((f[0], f[1]))
    return p.returncode, len(keys)


def theirs(path):
    p = subprocess.run([AUSEARCH, "-if", path], capture_output=True)
    return sum(1 for line in p.stdout.split(b"\n")
               if line.startswith(b"type=") or line.startswith(b"node="))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditp", default="./auditp")
    ap.add_argument("--log", default="t/corpus/gen.log")
    ap.add_argument("--stride", type=int, default=13,
                    help="byte-prefix stride")
    ap.add_argument("--bytes", type=int, default=4000,
                    help="byte-sweep only the first N bytes; 0 for all")
    ap.add_argument("--lines", type=int, default=11,
                    help="line-prefix stride")
    ap.add_argument("--flips", type=int, default=120,
                    help="how many leading byte offsets to overwrite")
    args = ap.parse_args()

    data = open(args.log, "rb").read()
    lines = data.splitlines(keepends=True)
    limit = min(args.bytes, len(data)) if args.bytes else len(data)

    crashes = []
    overref = []
    misread = []
    looser = 0
    fliplax = 0
    flipstrict = 0
    ncase = 0

    d = tempfile.mkdtemp(prefix="auditp-trunc-")
    path = os.path.join(d, "t.log")

    def run(label, blob, compare, want=None):
        nonlocal ncase, looser, fliplax, flipstrict
        ncase += 1
        with open(path, "wb") as f:
            f.write(blob)
        rc, mine = ours(args.auditp, path)
        if rc not in (0, 1):
            crashes.append("%s: exit %d" % (label, rc))
            return
        rcs, _ = ours(args.auditp, path, strict=True)
        if rcs not in (0, 1):
            crashes.append("%s -strict: exit %d" % (label, rcs))
            return
        if compare == "none":
            return
        if want is not None and mine != want:
            misread.append("%s: auditp read %d records of %d lines"
                           % (label, mine, want))
        yours = theirs(path)
        if compare == "count":
            if mine < yours:
                flipstrict += 1
            elif mine > yours:
                fliplax += 1
            return
        if mine < yours:
            overref.append("%s: auditp %d records, ausearch %d"
                           % (label, mine, yours))
        elif mine > yours:
            looser += 1

    try:
        nbyte = 0
        for i in range(0, limit + 1, args.stride):
            run("prefix-%d" % i, data[:i], "none")
            nbyte += 1

        nline = 0
        for i in range(0, len(lines) + 1, args.lines):
            run("lines-%d" % i, b"".join(lines[:i]), "strict", want=i)
            nline += 1

        # Flips stay line-aligned so that the counts remain comparable:
        # the slice ends at a newline and only one byte inside it moves.
        tail = 0
        for ln in lines:
            if tail + len(ln) > 1200:
                break
            tail += len(ln)
        nflip = 0
        for off in range(0, min(args.flips, tail)):
            for b in (0xFF, 0x00, ord("="), ord('"'), ord(" "), ord(":")):
                if data[off] == b:
                    continue
                run("flip-%d-%02x" % (off, b),
                    data[:off] + bytes([b]) + data[off + 1:tail], "count")
                nflip += 1

        # A line the reader cannot hold, with a good record on each side.
        # The record AFTER it is the point: a reader that abandons the
        # file loses every record past the long line, and ausearch does
        # not lose them.
        good = b"type=BPF msg=audit(1700000000.000:1): prog-id=1 op=LOAD\n"
        long_line = (b"type=USER_CMD msg=audit(1700000000.000:2): cmd="
                     + b"41" * 1200000 + b"\n")
        with open(path, "wb") as f:
            f.write(good + long_line + good.replace(b":1)", b":3)"))
        rc, longmine = ours(args.auditp, path)
        longtheirs = theirs(path)
        ncase += 1
        if rc not in (0, 1):
            crashes.append("long-line: exit %d" % rc)
        if longmine < 2:
            overref.append("long-line: auditp kept %d of the 2 records "
                           "either side, ausearch read %d"
                           % (longmine, longtheirs))
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
        os.rmdir(d)

    print("cases        %d" % ncase)
    print("byte-prefix  %d" % nbyte)
    print("line-prefix  %d" % nline)
    print("flips        %d" % nflip)
    print("crashes      %d" % len(crashes))
    print("overrefused  %d" % len(overref))
    print("misread      %d" % len(misread))
    print("looser       %d" % looser)
    print("flip-stricter %d" % flipstrict)
    print("flip-looser  %d" % fliplax)
    print("long-line    auditp %d records, ausearch %d"
          % (longmine, longtheirs))
    for line in crashes[:10]:
        print("  CRASH %s" % line)
    for line in overref[:10]:
        print("  OVERREFUSED %s" % line)
    for line in misread[:10]:
        print("  MISREAD %s" % line)
    return 1 if crashes or overref or misread else 0


if __name__ == "__main__":
    sys.exit(main())

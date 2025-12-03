#!/usr/bin/env python3
"""Turn ausearch output into the same flat per-field rows auditp emits.

    EVENTKEY <TAB> RECORD-INDEX <TAB> FIELD <TAB> VALUE

ausearch and auditp agree about nothing in their output formats and diffing
the two texts would measure rendering, so both are reduced to facts first.
What is compared is the VALUE column, which is ausearch's; the splitting
that produces the FIELD column is structural and is done the same way on
both sides.  That is a real shared-code risk and the README says so: a
splitter wrong in the same way on both sides would agree with itself.  It is
bounded by the round-trip check, which reads only auditp's side and would
notice a field that went missing, and by the field-name floor, which would
notice a splitter that found nothing.

Two facts about ausearch this relies on, both measured rather than assumed
and both asserted by the suite:

  Records within an event are printed in the REVERSE of the order the log
  holds them.  830 of the corpus's 1110 events hold one record, where the
  question does not arise; all 280 of the rest are reversed, with no
  exceptions.  The index emitted here is therefore counted from the end.

  The timestamp is printed in local time.  The zone comes from the
  environment and is not forced here: t/run.sh sets TZ once for both
  sides and runs the comparison a second time in a zone with a
  half-hour offset.  Forcing it here was a real defect, because auditp
  was left in the shell's zone and every @time field disagreed.
"""

import argparse
import io
import re
import subprocess
import sys
import time

AUSEARCH = "/usr/sbin/ausearch"

# type=X msg=audit(09/02/2026 19:12:06.243:4) : BODY     (-i)
# type=X msg=audit(1788376326.243:4): BODY               (no -i)
NODE = re.compile(r"^node=(\S+) ")
HDR_I = re.compile(r"^type=(\S+) msg=audit\((\d\d)/(\d\d)/(\d{4}) "
                   r"(\d\d):(\d\d):(\d\d)\.(\d{3}):(\d+)\) : ?")
HDR_R = re.compile(r"^type=(\S+) msg=audit\((\d+)\.(\d{3}):(\d+)\): ?")
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")


def field_at(body, i):
    """Length of a field name starting at body[i], or 0.  Same rule as the
    Go side: start of body or after a space, starts with a letter, followed
    by '='."""
    if i > 0 and body[i - 1] != " ":
        return 0
    m = NAME.match(body, i)
    if not m or m.end() >= len(body) or body[m.end()] != "=":
        return 0
    return m.end() - i


def scan_value(body, i):
    if i >= len(body) or body[i] == " ":
        return ""
    if body[i] == "{":
        # ausearch renders a decoded sockaddr as a brace-delimited group of
        # its own invented sub-fields: saddr={ saddr_fam=inet laddr=... }.
        # Without this the group's contents are read as record fields and
        # turn up as three fields auditp never emitted, which read as a
        # parser defect and are a rendering convention.
        j = body.find("}", i)
        return body[i:j + 1] if j >= 0 else body[i:]
    if body[i] == '"':
        j = body.find('"', i + 1)
        return body[i:j + 1] if j >= 0 else body[i:]
    if body[i] == "'":
        j = body.find("'", i + 1)
        return body[i:j + 1] if j >= 0 else body[i:]
    # A bare value runs to the next " NAME=" boundary, NOT to the next
    # space.  ausearch prints a decoded proctitle as
    # proctitle=/opt/widget/bin/widgetd -c /etc/widget.conf
    # with no quoting at all, so stopping at the first space loses every
    # argument after the first: 62 proctitle fields, 16 names and 10
    # commands read as truncated before this was fixed.
    #
    # The rule cannot be made exact, and that is a property of ausearch's
    # output rather than of this parser.  A decoded value holding " x=y"
    # is indistinguishable from the end of one field and the start of
    # another.  The corpus avoids that case deliberately and the README
    # says so.
    j = i
    while True:
        j = body.find(" ", j)
        if j < 0:
            return body[i:]
        if field_at(body, j + 1):
            return body[i:j]
        j += 1


def split_fields(body):
    i = 0
    start = -1
    while i < len(body):
        if field_at(body, i):
            start = i
            break
        i += 1
    if start < 0:
        return body, []
    prefix = body[:start]
    out = []
    i = start
    while i < len(body):
        n = field_at(body, i)
        if not n:
            i += 1
            continue
        name = body[i:i + n]
        raw = scan_value(body, i + n + 1)
        out.append((name, raw))
        i = i + n + 1 + len(raw)
    return prefix, out


def unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def rows_for_record(typ, key, body, idx, stamp):
    yield (key, idx, "@type", typ)
    yield (key, idx, "@time", stamp)
    prefix, fields = split_fields(body)
    prefix = prefix.strip()
    if prefix:
        yield (key, idx, "@prefix", prefix)
    for name, raw in fields:
        yield (key, idx, name, unquote(raw))
        if raw[:1] == "'":
            _, sub = split_fields(raw[1:-1])
            for sname, sraw in sub:
                yield (key, idx, name + "." + sname, unquote(sraw))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--interpret", action="store_true")
    args = ap.parse_args()

    cmd = [AUSEARCH, "-if", args.log]
    if args.interpret:
        cmd.insert(1, "-i")
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode not in (0, 1):
        sys.stderr.write("ausearch exited %d: %s\n"
                         % (p.returncode, p.stderr.decode(errors="replace")))
        return 2
    text = p.stdout.decode("utf-8", "surrogateescape")

    events = []
    cur = None
    for line in text.split("\n"):
        if line.startswith("----"):
            cur = []
            events.append(cur)
            continue
        if cur is None or not (line.startswith("type=")
                               or line.startswith("node=")):
            continue
        cur.append(line)

    # Binary stdout with surrogateescape: a decoded value can hold any
    # byte, and writing through the default UTF-8 encoder raised on the
    # first one that was not valid UTF-8 and silently truncated the run at
    # 120 fields short.  The exception went to a stderr nobody was reading.
    out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                           errors="surrogateescape", newline="")
    nrec = 0
    for recs in events:
        n = len(recs)
        for pos, line in enumerate(recs):
            node = ""
            mn = NODE.match(line)
            if mn:
                node = mn.group(1)
                line = line[mn.end():]
            m = HDR_I.match(line)
            if m:
                typ = m.group(1)
                mo, dy, yr, hh, mm, ss, ms, serial = (
                    int(m.group(2)), int(m.group(3)), int(m.group(4)),
                    int(m.group(5)), int(m.group(6)), int(m.group(7)),
                    m.group(8), m.group(9))
                # Local time back to epoch, in whatever zone ausearch
                # just printed in.  time.mktime and not calendar.timegm,
                # which is only right when the zone is UTC and silently
                # moved every event key by 5h30m when the suite started
                # running this a second time in Asia/Kolkata.  isdst=-1
                # asks libc; both zones the suite uses are DST-free, so
                # there is no ambiguous hour to guess at.
                secs = int(time.mktime((yr, mo, dy, hh, mm, ss, 0, 0, -1)))
                stamp = "%02d/%02d/%04d %02d:%02d:%02d.%s" % (
                    mo, dy, yr, hh, mm, ss, ms)
            else:
                m = HDR_R.match(line)
                if not m:
                    continue
                typ, secs, ms, serial = (m.group(1), int(m.group(2)),
                                         m.group(3), m.group(4))
                stamp = "%d.%s" % (secs, ms)
            key = "%d.%s:%s" % (secs, ms, serial)
            if node:
                key = node + ":" + key
            body = line[m.end():]
            # ausearch -i appends a space after every field.
            body = body.rstrip(" ")
            idx = n - 1 - pos   # printed in reverse of log order
            nrec += 1
            for k, i, name, val in rows_for_record(typ, key, body, idx, stamp):
                out.write("%s\t%d\t%s\t%s\n" % (k, i, name, val))
    out.flush()
    sys.stderr.write("oracle: %d events, %d records\n" % (len(events), nrec))
    return 0 if nrec else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Read auditp's JSON output back with Python and compare it with the
flat output of the same run.

Nothing else in the suite reads -o json at all.  It is the form a
pipeline would consume, and a comma in the wrong place or a field
silently dropped from the map would not have turned anything red.

Two questions, and the second is the one worth asking:

  Is it JSON?  Python's json module is the parser, not ours.

  Does it say the same thing as -o flat?  Every record and every field
  is compared, so a field that exists in one form and not the other is
  a failure.  A map cannot hold a repeated field name, which the flat
  form can, so auditp suffixes the second one, and this checks that
  the suffixed name is there rather than letting the field vanish.

Also checked, because each has been wrong at some point: the event key
agrees with secs, millis and serial; the record type number is
resolved rather than -1; and the order list names exactly the keys of
the field map.
"""

import argparse
import json
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditp", default="./auditp")
    ap.add_argument("--log", default="t/corpus/gen.log")
    ap.add_argument("--interpret", action="store_true")
    args = ap.parse_args()

    cmd = [args.auditp, "-o", "json", args.log]
    if args.interpret:
        cmd.insert(1, "-i")
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        print("auditp -o json exited %d" % p.returncode)
        return 1

    events = []
    bad = []
    for n, line in enumerate(p.stdout.decode("utf-8", "surrogateescape")
                             .splitlines(), 1):
        try:
            events.append(json.loads(line))
        except ValueError as e:
            bad.append("line %d is not JSON: %s" % (n, e))
            if len(bad) > 5:
                break

    cmd = [args.auditp, "-o", "flat", args.log]
    if args.interpret:
        cmd.insert(1, "-i")
    q = subprocess.run(cmd, capture_output=True)

    # Keyed by the event's POSITION in the stream, not by its key string.
    # An audit key is a timestamp and a serial, and it is not unique: a
    # user-space message carries the serial of whatever was happening at the
    # time, so two standalone records can share one. The corpus has such a
    # pair, a USER_AUTH and a CRED_ACQ both at 1700000065.897:1481, and
    # ausearch emits them as two events as well, so auditp is right about it.
    #
    # Keying on the string collapsed them: the second event's record 0 landed
    # on top of the first's, the duplicate-name loop renamed its fields to
    # comm#2 and pid#2, and the comparison then reported 17 field
    # disagreements that were entirely this script's doing.
    #
    # Each record begins with an @type row, so an event begins at an @type
    # row whose record index is 0.
    flat = {}
    ev_idx = -1
    for line in q.stdout.decode("utf-8", "surrogateescape").splitlines():
        f = line.split("\t")
        if len(f) < 5:
            continue
        if f[2] == "@type" and f[1] == "0":
            ev_idx += 1
        if f[2].startswith("@"):
            continue
        k = (ev_idx, f[1], f[2])
        n = 2
        while k in flat:
            k = (ev_idx, f[1], "%s#%d" % (f[2], n))
            n += 1
        flat[k] = f[4]

    seen = set()
    nonum = set()
    nhex = 0
    nrec = nfield = 0
    for evpos, ev in enumerate(events):
        # The key has to agree with the parts it was built from.
        want = "%d.%03d:%d" % (ev["secs"], ev["millis"], ev["serial"])
        if ev.get("node"):
            want = ev["node"] + ":" + want
        if ev["key"] != want:
            bad.append("key %s does not match %s" % (ev["key"], want))
        for idx, rec in enumerate(ev["records"]):
            nrec += 1
            # A missing type_num is a fact about this libaudit, not a
            # defect: a record names its own type in the text, and
            # LANDLOCK_ACCESS and LANDLOCK_DOMAIN are named by records this
            # libaudit has no number for. What must never happen is a
            # number that is present and wrong in shape, so that is what is
            # asserted, and the nameless-but-numberless count is reported
            # instead of failed.
            if "type_num" in rec and rec["type_num"] <= 0:
                bad.append("%s record %d: type_num is %r, which is not a "
                           "type number" % (ev["key"], idx, rec["type_num"]))
            if "type_num" not in rec and not rec["type"].startswith("UNKNOWN["):
                nonum.add(rec["type"])
            # Reported, not raised. The first run of this crashed here with
            # a TypeError because one record carried "order": null, a Go nil
            # slice where every other record had a list. A checker that dies
            # on the defect it was written to find reports nothing at all,
            # and the traceback looked like a bug in this file rather than a
            # finding about the output.
            if not isinstance(rec.get("order"), list):
                bad.append("%s record %d: order is %r, not a list"
                           % (ev["key"], idx, rec.get("order")))
            elif sorted(rec["order"]) != sorted(rec["fields"]):
                bad.append("%s record %d: order and fields disagree"
                           % (ev["key"], idx))
            for name, val in rec["fields"].items():
                nfield += 1
                k = (evpos, str(idx), name)
                seen.add(k)
                if k not in flat:
                    bad.append("%s record %d: %s is in the JSON and not "
                               "in the flat output" % (ev["key"], idx, name))
                elif name in (rec.get("fields_hex") or {}):
                    # The JSON's plain value is lossy for this one, because
                    # encoding/json substitutes U+FFFD for an invalid byte.
                    # fields_hex carries the bytes, so compare those against
                    # the flat output's bytes rather than comparing two
                    # different lossy renderings and calling it a
                    # disagreement.
                    want = flat[k].encode("utf-8", "surrogateescape")
                    got = bytes.fromhex(rec["fields_hex"][name])
                    nhex += 1
                    if want != got:
                        bad.append("%s record %d: %s hex %s does not match "
                                   "the flat bytes %s"
                                   % (ev["key"], idx, name,
                                      got.hex(), want.hex()))
                elif flat[k] != val:
                    bad.append("%s record %d: %s is %r in the JSON and "
                               "%r in the flat output"
                               % (ev["key"], idx, name, val, flat[k]))
    missing = set(flat) - seen
    for k in sorted(missing)[:5]:
        bad.append("%s record %s: %s is in the flat output and not in "
                   "the JSON" % k)

    print("events   %d" % len(events))
    print("records  %d" % nrec)
    print("fields   %d" % nfield)
    print("missing  %d" % len(missing))
    print("named types with no number %d%s" % (len(nonum),
          (": " + " ".join(sorted(nonum))) if nonum else ""))
    print("values carried as hex because they are not UTF-8 %d" % nhex)
    print("problems %d" % len(bad))
    for line in bad[:10]:
        print("  BAD %s" % line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

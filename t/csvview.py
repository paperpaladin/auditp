#!/usr/bin/env python3
"""Compare auditp's events against `ausearch --format csv`.

The csv form is a second view of the same events, derived inside
ausearch by a higher layer than `-i`: one row per event, with the
subject, the object, the action and the result worked out from whichever
records the event happens to hold.  Because it is a different
derivation, it can disagree with `-i` about an event the per-field
comparison agrees on, and that disagreement is the reason to run it.

Six of the sixteen columns are a restatement of something auditp
already has, and those are compared:

    NODE SERIAL_NUM DATE TIME   the event key and the timestamp,
                               formatted a second way
    EVENT                      the record type
    SESSION                    ses=
    SUBJ_PRIME                 auid, or the nested acct=
    SUBJ_SEC                   uid
    RESULT                     success=

The other ten are libaudit's classification of the event
(EVENT_KIND, SUBJ_KIND, ACTION, OBJ_KIND), or are assembled from
several fields by a rule that is not a restatement of any one of them
(OBJ_PRIME, OBJ_SEC, HOW).  This file is t/csvview.py and not t/csv.py
because t/ is on sys.path when the suite runs a script from it, so the
obvious name shadows the standard library module this needs.  auditp does not classify events and says
so in its non-goals, so comparing those columns would be comparing
against a feature that is deliberately absent.  What this script does
with them instead is count how they are derived, which is the measured
form of that statement.

The rules for the three subject and result columns were worked out by
comparing, not read out of documentation: libaudit's source is the only
authority for them and these are what this version does.  They are
written here as exact rules, so a version that derives them differently
turns this red rather than passing quietly.
"""

import argparse
import collections
import csv
import os
import subprocess
import sys

AUSEARCH = "/usr/sbin/ausearch"


def auditp_events(auditp, log):
    """[(key, [record]), ...] in auditp's order, each record a dict.

    Read out of -o flat -i, which is the form the per-field comparison
    reads, so this script cannot see a different program's answer from
    the one that comparison checks.
    """
    out = subprocess.run([auditp, "-i", "-o", "flat", log],
                         capture_output=True)
    if out.returncode != 0:
        sys.stderr.write("auditp -o flat exited %d\n" % out.returncode)
        return None
    events = []
    for line in out.stdout.decode("utf-8", "surrogateescape").splitlines():
        f = line.split("\t")
        if len(f) < 5:
            continue
        key, idx, name, val = f[0], f[1], f[2], f[4]
        if name == "@type" and idx == "0":
            events.append((key, []))
        if not events:
            continue
        recs = events[-1][1]
        while len(recs) <= int(idx):
            recs.append({})
        recs[int(idx)][name] = val
    return events


def first(recs, name):
    """The value of a field, from the first record that has one.

    ausearch works the same way round: the subject of an event is taken
    from whichever record carries it, not from a fixed record index.
    """
    for r in recs:
        if name in r:
            return r[name]
    return None


def ausearch_csv(log):
    out = subprocess.run([AUSEARCH, "--format", "csv", "-if", log],
                         capture_output=True)
    if out.returncode != 0:
        sys.stderr.write("ausearch --format csv exited %d\n" % out.returncode)
        return None
    text = out.stdout.decode("utf-8", "surrogateescape").splitlines()
    return list(csv.DictReader(text))


def pair(rows, events):
    """Pair csv rows with auditp events, by key and then by record type.

    An audit key is not unique: the corpus holds a USER_AUTH and a BPF
    event at the same timestamp and serial, and ausearch emits them in
    the other order from auditp.  Pairing by position would report both
    as a disagreement about the record type, which is how an ordering
    difference between two events that both tools agree exist comes out
    looking like a parse defect.
    """
    bykey = collections.defaultdict(list)
    for r in rows:
        bykey[csv_key(r)].append(r)
    pairs = []
    unmatched_events = []
    for key, recs in events:
        cand = bykey.get(key)
        if not cand:
            unmatched_events.append(key)
            continue
        want = [r["@type"] for r in recs if "@type" in r]
        hit = None
        for r in cand:
            if r["EVENT"] in want:
                hit = r
                break
        if hit is None:
            hit = cand[0]
        cand.remove(hit)
        pairs.append((hit, key, recs))
    leftover = [r for v in bykey.values() for r in v]
    return pairs, unmatched_events, leftover


def csv_key(r):
    """The csv row's event key, in auditp's spelling.

    DATE and TIME are compared separately against the timestamp; this
    only has to put the row in the right bucket, and the serial plus the
    node does that.
    """
    k = r["SERIAL_NUM"]
    if r["NODE"]:
        return r["NODE"] + ":@" + k
    return "@" + k


def auditp_key(key):
    """The same spelling, from auditp's own event key."""
    k = key.rsplit(":", 1)[1]
    if key.count(":") > 1:
        return key.split(":", 1)[0] + ":@" + k
    return "@" + k


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditp", default="./auditp")
    ap.add_argument("--log", default="t/corpus/gen.log")
    args = ap.parse_args()

    if not os.access(AUSEARCH, os.X_OK):
        sys.stderr.write("%s is not executable\n" % AUSEARCH)
        return 2
    rows = ausearch_csv(args.log)
    events = auditp_events(args.auditp, args.log)
    if rows is None or events is None:
        return 1

    # Keyed the same way on both sides, so the pairing cannot depend on
    # either tool's event order.
    keyed = [(auditp_key(k), r) for k, r in events]
    pairs, missing, leftover = pair(rows, keyed)

    bad = []
    n = collections.Counter()
    for row, key, recs in pairs:
        n["events"] += 1

        def cmp(col, want, why):
            n[col + " compared"] += 1
            if row[col] == want:
                n[col + " agree"] += 1
            else:
                n[col + " differ"] += 1
                bad.append("%s: %s is %r in the csv and %r %s"
                           % (key, col, row[col], want, why))

        node = key.split(":@")[0] if ":@" in key else ""
        cmp("NODE", node, "in the event key")
        cmp("SERIAL_NUM", key.rsplit("@", 1)[1], "in the event key")

        stamp = first(recs, "@time") or ""
        date, _, time = stamp.partition(" ")
        cmp("DATE", date, "in @time")
        cmp("TIME", time.split(".")[0], "in @time")

        # EVENT is the record type ausearch considers the event's own.
        # Which record it picks is its business; that it picks one of the
        # records auditp assembled for that event is the claim here, and
        # it is a check on event assembly from a direction the per-field
        # comparison cannot see.
        types = [r["@type"] for r in recs if "@type" in r]
        n["EVENT compared"] += 1
        if row["EVENT"] in types:
            n["EVENT agree"] += 1
        elif row["EVENT"] == "":
            # The csv leaves EVENT empty for a type libaudit has no
            # number for, while ausearch -i prints the name out of the
            # record's own text.  Three in the corpus: LANDLOCK_ACCESS,
            # LANDLOCK_DOMAIN and UNKNOWN[9999].  A disagreement between
            # the two views of one tool, not a defect in either.
            n["EVENT empty in the csv"] += 1
            if not (types and (types[0].startswith("UNKNOWN[")
                               or types[0] in ("LANDLOCK_ACCESS",
                                               "LANDLOCK_DOMAIN"))):
                bad.append("%s: the csv names no type for %r, which "
                           "libaudit does have a number for" % (key, types))
        else:
            n["EVENT differ"] += 1
            bad.append("%s: the csv calls this a %s and auditp assembled %s"
                       % (key, row["EVENT"], types))

        ses = first(recs, "ses")
        if ses is not None:
            cmp("SESSION", ses, "in ses=")

        # SUBJ_PRIME: the nested acct= for a USER_LOGIN, "system" when
        # the login uid is unset, and the login uid's name otherwise.
        # All three branches are live in the corpus: 3 from acct=, 244
        # unset, 431 from auid.  The first version of this rule took
        # acct= for every record that had one and differed on 25 events,
        # because libaudit prefers acct= only for a login, where the
        # login uid is the account being logged into rather than the
        # subject doing it.
        acct = first(recs, "msg.acct")
        auid = first(recs, "auid")
        if acct is not None and "USER_LOGIN" in types:
            cmp("SUBJ_PRIME", acct, "in the nested acct=")
        elif auid == "unset":
            cmp("SUBJ_PRIME", "system", "for an unset auid")
        elif auid is not None:
            cmp("SUBJ_PRIME", auid, "in auid=")

        uid = first(recs, "uid")
        if uid is not None and row["SUBJ_SEC"] != "":
            cmp("SUBJ_SEC", uid, "in uid=")
        elif uid is not None:
            # 6 events, all USER_LOGIN or DAEMON_*, where the csv prints
            # no secondary subject and -i prints a uid.
            n["SUBJ_SEC empty in the csv"] += 1

        succ = first(recs, "success")
        if succ is not None:
            cmp("RESULT", {"yes": "success", "no": "failed"}.get(succ, succ),
                "in success=")
        elif row["RESULT"] != "":
            # 148 events: the csv decides the result from the record type
            # and its fields (an AVC denial, a SECCOMP action) where
            # there is no success= to restate.
            n["RESULT without a success= field"] += 1

        # The classification columns, counted rather than compared.
        for col in ("EVENT_KIND", "SUBJ_KIND", "ACTION", "OBJ_KIND"):
            if row[col]:
                n["classified " + col] += 1
        exe = first(recs, "exe")
        if row["HOW"] == "":
            n["HOW empty"] += 1
        elif row["HOW"] == exe:
            n["HOW is exe"] += 1
        elif row["HOW"] == first(recs, "syscall"):
            n["HOW is the syscall"] += 1
        else:
            n["HOW is neither exe nor the syscall"] += 1
        name = first(recs, "name")
        if row["OBJ_PRIME"] == "":
            n["OBJ_PRIME empty"] += 1
        elif row["OBJ_PRIME"] == name:
            n["OBJ_PRIME is name"] += 1
        else:
            n["OBJ_PRIME is not name"] += 1

    for k in missing[:5]:
        bad.append("%s: auditp has this event and the csv has no row for it"
                   % k)
    for r in leftover[:5]:
        bad.append("serial %s: the csv has a row and auditp has no event "
                   "for it" % r["SERIAL_NUM"])
    n["csv rows"] = len(rows)
    n["csv rows with no auditp event"] = len(leftover)
    n["auditp events with no csv row"] = len(missing)

    for k in sorted(n):
        print("%-42s %d" % (k, n[k]))
    print("problems %d" % len(bad))
    for line in bad[:10]:
        print("  BAD %s" % line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

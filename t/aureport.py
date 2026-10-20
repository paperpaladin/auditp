#!/usr/bin/env python3
"""Compare auditp's fields against `aureport --summary -i`.

aureport is the third view of the same log inside auditd: it walks the
events and counts, where `ausearch -i` prints fields and `--format csv`
prints one row per event.  A count is derived from everything auditp
got right and everything it dropped at once, so a record auditp loses
moves a total here whether or not any field comparison noticed.

What is compared is the syscall summary, interpreted.  `aureport -s
--summary -i` is one row per distinct syscall NAME with the number of
records that called it, and the name depends on the record's own arch,
so this puts both syscall tables and the choice between them under a
third derivation of the same fact.  91 names, every one of them
compared.

Two rules are needed to line the two sides up, and both are aureport
being different from `ausearch -i` rather than auditp being wrong:

  aureport leaves out syscall 0 entirely.  Four records in the corpus
  have syscall=0, two x86_64 (read) and two i386 (restart_syscall), and
  no row for either name accounts for them.  Both names are in
  aureport's output with the counts of the OTHER records that call
  them, so this is not a missing table entry.

  aureport does not fold i386's multiplexers into the syscall name.
  `ausearch -i` prints socketcall(bind) and ipc(msgsnd); aureport
  prints socketcall and ipc, 11 and 9 of them, and names no sub-call
  anywhere in the summary.

Two more summaries are counted and reported rather than compared,
because what they count is not a restatement of one field:

  `-u --summary -i` says 248 records have an unset login uid where 245
  records in the corpus carry auid=4294967295.  The other seven values
  agree exactly.  Where the three extra come from is not established;
  they are the same count as the three records whose type libaudit has
  no name for, which is a coincidence until someone reads the source.

  `-x --summary -i` prints `(null)` for a record with no exe= at all,
  which is aureport's own filler and not a value in the log, and its
  counts for two of the ten real executables are 1 and 2 below the
  number of records naming them.  Not understood, and so not asserted.
"""

import argparse
import collections
import os
import re
import subprocess
import sys

AUREPORT = "/usr/sbin/aureport"


def summary(flag, log):
    """{value: count} from one aureport --summary -i report.

    The report is a title, a rule, a `total  WHAT` header, a second
    rule, then "count value" lines.  Parsed by shape rather than by
    counting header lines, because the title differs per report.
    """
    out = subprocess.run([AUREPORT, flag, "--summary", "-i", "-if", log],
                         capture_output=True)
    if out.returncode != 0:
        sys.stderr.write("aureport %s exited %d\n" % (flag, out.returncode))
        return None
    d = {}
    for line in out.stdout.decode("utf-8", "surrogateescape").splitlines():
        p = line.split(None, 1)
        if len(p) != 2 or not p[0].isdigit():
            continue
        # The two rule lines and the `total  WHAT` header are excluded
        # by the count having to be a number, so nothing else needs
        # filtering by name here: a file called "file" is a real value.
        d[p[1].strip()] = int(p[0])
    return d


def auditp_rows(auditp, log, interpret):
    """[(record ordinal, field name, value)] from -o flat.

    Rows, not a dict per record: one record in the corpus repeats a
    field name, and a dict silently keeps one of the two.  That cost a
    wrong count of auid=unset while this was being written, 244 against
    the 245 the log holds.
    """
    cmd = [auditp, "-o", "flat", log]
    if interpret:
        cmd.insert(1, "-i")
    out = subprocess.run(cmd, capture_output=True)
    if out.returncode != 0:
        sys.stderr.write("auditp -o flat exited %d\n" % out.returncode)
        return None
    rows = []
    rec = -1
    last = None
    for line in out.stdout.decode("utf-8", "surrogateescape").splitlines():
        f = line.split("\t")
        if len(f) < 5:
            continue
        here = (f[0], f[1])
        if here != last:
            rec += 1
            last = here
        rows.append((rec, f[2], f[4]))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auditp", default="./auditp")
    ap.add_argument("--log", default="t/corpus/gen.log")
    args = ap.parse_args()

    if not os.access(AUREPORT, os.X_OK):
        sys.stderr.write("%s is not executable\n" % AUREPORT)
        return 2

    rows = auditp_rows(args.auditp, args.log, True)
    raw = auditp_rows(args.auditp, args.log, False)
    if rows is None or raw is None:
        return 1
    # The raw syscall number of each record, to find the syscall 0 rows
    # aureport leaves out.  Keyed by record ordinal, which is the same
    # ordinal in both runs because -i changes values and not structure.
    rawsys = {}
    for rec, name, val in raw:
        if name == "syscall":
            rawsys[rec] = val

    bad = []
    n = collections.Counter()

    want = summary("-s", args.log)
    if want is None:
        return 1
    got = collections.Counter()
    for rec, name, val in rows:
        if name != "syscall":
            continue
        if rawsys.get(rec) == "0":
            n["syscall 0 records aureport leaves out"] += 1
            continue
        # socketcall(bind) -> socketcall.  Only the multiplexers carry
        # a bracket, and the bare name has to survive unchanged.
        folded = re.sub(r"\([^()]*\)$", "", val)
        if folded != val:
            n["sub-calls folded into the syscall name"] += 1
        got[folded] += 1
    n["syscall names in the aureport summary"] = len(want)
    for name in sorted(set(want) | set(got)):
        n["syscall names compared"] += 1
        if want.get(name) == got.get(name):
            n["syscall names agree"] += 1
        else:
            n["syscall names differ"] += 1
            bad.append("syscall %s: aureport counts %s records and auditp "
                       "has %s" % (name, want.get(name), got.get(name)))
    n["syscall records counted"] = sum(got.values())

    # Counted, not compared.  See the top of this file for each.
    for flag, fields, label in (("-u", ("auid",), "login uid"),
                                ("-x", ("exe", "msg.exe"), "executable")):
        them = summary(flag, args.log)
        if them is None:
            return 1
        # exe lives in the record for a SYSCALL and inside the nested
        # msg='...' for a PAM record, and aureport counts both.
        us = collections.Counter(v for _, name, v in rows if name in fields)
        agree = sum(1 for k in set(them) | set(us) if them.get(k) == us.get(k))
        n["%s values in the aureport summary" % label] = len(them)
        n["%s values agreeing with the records" % label] = agree
        n["%s values derived differently" % label] = (
            len(set(them) | set(us)) - agree)

    for k in sorted(n):
        print("%-46s %d" % (k, n[k]))
    print("problems %d" % len(bad))
    for line in bad[:10]:
        print("  BAD %s" % line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

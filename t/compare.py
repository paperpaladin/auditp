#!/usr/bin/env python3
"""Compare auditp's per-field output against ausearch's, field by field.

Five outcomes, never added together:

  AGREE-i    an interpreter claimed the field and its answer is ausearch's
  AGREE-p    no interpreter claimed it and the decoded value is ausearch's
             anyway, which is the common case for pid= and friends
  REFUSED    no interpreter claimed it and ausearch translated it.  Not a
             failure: it is the gap, and it is meant to be visible and to
             shrink.  It is counted and the field names are listed.
  WRONG      an interpreter claimed it and gave a different answer.  This
             is the only outcome that fails the suite.
  MISSING    the field exists on one side and not the other, or the two
             sides disagree about how many records an event has.  Also a
             failure: a field nobody compares is not a field that agrees.

"N fields compared" is reported alongside, because a comparison over an
empty set agrees with everything.
"""

import argparse
import collections
import sys


def load(path, flagged):
    rows = {}
    order = []
    with open(path, "r", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            parts = line.split("\t")
            if flagged:
                if len(parts) < 5:
                    continue
                key, idx, name, flag = parts[0], parts[1], parts[2], parts[3]
                val = "\t".join(parts[4:])
            else:
                if len(parts) < 4:
                    continue
                key, idx, name, flag = parts[0], parts[1], parts[2], "-"
                val = "\t".join(parts[3:])
            k = (key, idx, name)
            if k in rows:
                # A repeated field name in one record: disambiguate by
                # occurrence so the two sides still line up.
                n = 2
                while (key, idx, "%s#%d" % (name, n)) in rows:
                    n += 1
                k = (key, idx, "%s#%d" % (name, n))
            rows[k] = (flag, val)
            order.append(k)
    return rows, order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--show", type=int, default=12)
    ap.add_argument("--no-refusals", action="store_true",
                    help="treat a refusal as a failure.  Used for the "
                         "uninterpreted comparison, where there is nothing "
                         "to refuse: every field must match.  Without this "
                         "the raw comparison is vacuous, which is how a "
                         "mutation that stopped recognising the quoted "
                         "encoding survived it.")
    args = ap.parse_args()

    ours, oorder = load(args.ours, True)
    orc, _ = load(args.oracle, False)

    agree_i = agree_p = refused = wrong = 0
    missing_ours = missing_orc = 0
    by_refused = collections.Counter()
    by_wrong = collections.Counter()
    examples = []
    names = set()

    for k in oorder:
        flag, val = ours[k]
        names.add(k[2])
        if k not in orc:
            missing_orc += 1
            if len(examples) < args.show:
                examples.append(("MISSING-ORACLE", k, val, "<absent>"))
            continue
        oval = orc[k][1]
        if val == oval:
            if flag == "i":
                agree_i += 1
            else:
                agree_p += 1
        elif flag == "i":
            wrong += 1
            by_wrong[k[2]] += 1
            if len(examples) < args.show:
                examples.append(("WRONG", k, val, oval))
        else:
            refused += 1
            by_refused[k[2]] += 1
            if args.no_refusals and len(examples) < args.show:
                examples.append(("REFUSED", k, val, oval))

    for k in orc:
        if k not in ours:
            missing_ours += 1
            if len(examples) < args.show:
                examples.append(("MISSING-OURS", k, "<absent>", orc[k][1]))

    total = agree_i + agree_p + refused + wrong
    print("compared        %d fields, %d distinct names" % (total, len(names)))
    print("AGREE-i         %d" % agree_i)
    print("AGREE-p         %d" % agree_p)
    print("REFUSED         %d" % refused)
    print("WRONG           %d" % wrong)
    print("MISSING-ours    %d" % missing_ours)
    print("MISSING-oracle  %d" % missing_orc)
    if by_refused:
        print("refused by field name:")
        for n, c in by_refused.most_common():
            print("  %6d %s" % (c, n))
    if by_wrong:
        print("wrong by field name:")
        for n, c in by_wrong.most_common():
            print("  %6d %s" % (c, n))
    # The example lines are prefixed so that nothing greps them by mistake
    # for a summary line: the first version shared a prefix with the
    # REFUSED count and a harness extractor picked up thirteen hundred
    # lines where it wanted one number.
    for kind, k, a, b in examples:
        print("eg %-12s %s %s %s" % (kind, k[0], k[1], k[2]))
        print("eg   ours   %r" % (a,))
        print("eg   oracle %r" % (b,))
    bad = wrong + missing_ours + missing_orc
    if args.no_refusals:
        bad += refused
    if total == 0:
        print("NOTHING COMPARED")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

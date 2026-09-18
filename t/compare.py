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
    cur = None
    typ = None
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
            # A record is identified by its event key, its position in
            # the event AND its type.  Two events can share a key,
            # because a record of certain types ends an event, and
            # ausearch sorts a whole file's events by time, so two
            # same-key events swap places in a file of nine hundred
            # records and keep their order in a file of two.  Keying on
            # position alone made the comparison depend on that sort: a
            # UNKNOWN[1100] and a BPF record at position 0 of two
            # same-key events were paired with each other and reported
            # as six differing fields.
            if (key, idx) != cur:
                cur = (key, idx)
                typ = None
            if name == "@type":
                typ = val
                n = 2
                while (key, idx, typ, "@type") in rows:
                    typ = "%s#%d" % (val, n)
                    n += 1
            k = (key, idx, typ, name)
            if k in rows:
                # A repeated field name in one record: disambiguate by
                # occurrence so the two sides still line up.
                n = 2
                while (key, idx, typ, "%s#%d" % (name, n)) in rows:
                    n += 1
                k = (key, idx, typ, "%s#%d" % (name, n))
            rows[k] = (flag, val)
            order.append(k)
    return rows, order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--show", type=int, default=12)
    ap.add_argument("--known", help="file of fields where ausearch's own "
                    "output is ambiguous; counted apart from WRONG and "
                    "required by the suite to be exactly this set")
    ap.add_argument("--known-may-be-unmet", action="store_true",
                    help="do not fail on an entry in the known file that "
                         "did not fire.  For the fuzzer, whose input "
                         "changes with the seed: a stale exemption is "
                         "still a failure for the fixed corpus, which is "
                         "where that check belongs.")
    ap.add_argument("--oracle-declines", action="store_true",
                    help="count a record the oracle read NOTHING of as "
                         "declined rather than as missing fields.  For "
                         "the fuzzer, where a type and field list drawn "
                         "at random is often something ausearch will not "
                         "parse at all: an AVC with no avc: prose in "
                         "front of it is refused outright.  A field "
                         "missing from a record ausearch DID read is "
                         "still a failure, which is the distinction "
                         "worth keeping.")
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

    known = set()
    if args.known:
        with open(args.known) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                p = line.split("\t")
                if len(p) == 3:
                    known.add(tuple(p))
    # Keyed by (field, our value, ausearch's value) and not by position.
    # The first version keyed on the event serial, and every regeneration
    # of the corpus moved the serials, so a recorded difference silently
    # became a failure and a new one silently became exempt.

    declined = set()
    if args.oracle_declines:
        orc_recs = {(k[0], k[1]) for k in orc}
        for k in oorder:
            if (k[0], k[1]) not in orc_recs:
                declined.add((k[0], k[1]))

    agree_i = agree_p = refused = wrong = ambiguous = 0
    seen_known = set()
    missing_ours = missing_orc = 0
    by_refused = collections.Counter()
    by_wrong = collections.Counter()
    examples = []
    names = set()

    for k in oorder:
        if (k[0], k[1]) in declined:
            continue
        flag, val = ours[k]
        names.add(k[3])
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
        elif (k[3].split("#")[0], val, oval) in known:
            # The name without its occurrence suffix.  A field that
            # appears twice in one record is disambiguated as sig#2,
            # and an exemption recorded for sig did not cover it, so
            # the same known ausearch defect counted as a new failure
            # the moment the fuzzer wrote two signals in one record.
            ambiguous += 1
            seen_known.add((k[3].split("#")[0], val, oval))
        elif flag == "i":
            wrong += 1
            by_wrong[k[3]] += 1
            if len(examples) < args.show:
                examples.append(("WRONG", k, val, oval))
        else:
            refused += 1
            by_refused[k[3]] += 1
            if args.no_refusals and len(examples) < args.show:
                examples.append(("REFUSED", k, val, oval))

    for k in orc:
        if k not in ours:
            missing_ours += 1
            if len(examples) < args.show:
                examples.append(("MISSING-OURS", k, "<absent>", orc[k][1]))

    total = agree_i + agree_p + refused + wrong + ambiguous
    print("compared        %d fields, %d distinct names" % (total, len(names)))
    print("AGREE-i         %d" % agree_i)
    print("AGREE-p         %d" % agree_p)
    print("REFUSED         %d" % refused)
    print("WRONG           %d" % wrong)
    print("AMBIGUOUS       %d" % ambiguous)
    print("AMBIGUOUS-unmet %d" % len(known - seen_known))
    print("MISSING-ours    %d" % missing_ours)
    print("MISSING-oracle  %d" % missing_orc)
    print("ORACLE-DECLINED %d" % len(declined))
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
        print("eg %-12s %s %s %s %s" % (kind, k[0], k[1], k[2], k[3]))
        print("eg   ours   %r" % (a,))
        print("eg   oracle %r" % (b,))
    bad = wrong + missing_ours + missing_orc
    if args.no_refusals:
        bad += refused
    # An entry in the known-ambiguous file that did not fire is a stale
    # exemption, and a stale exemption is how a real failure gets excused
    # later.  It fails too.
    if not args.known_may_be_unmet:
        bad += len(known - seen_known)
    if total == 0:
        print("NOTHING COMPARED")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

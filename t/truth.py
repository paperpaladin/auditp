#!/usr/bin/env python3
"""Compare auditp's decoded field bytes against the generator's record of
what it encoded.

This is the one comparison here that does not involve ausearch.  Agreeing
with a second decoder and recovering the bytes that were encoded are
different claims: the hex encoding exists for exactly the bytes two
decoders are most likely to mangle in the same way, so the second decoder
is the weaker instrument for them.

Rows present in auditp's output and absent from the truth file are not
failures: the truth file holds only the fields the generator encoded text
into, and most of a record is numbers.
"""

import argparse
import sys


def load(path):
    d = {}
    with open(path, "r", errors="surrogateescape") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 4:
                continue
            d[(p[0], p[1], p[2])] = "\t".join(p[3:])
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--decoded", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--show", type=int, default=10)
    args = ap.parse_args()

    got = load(args.decoded)
    want = load(args.truth)
    agree = differ = missing = 0
    shown = 0
    for k, v in sorted(want.items()):
        if k not in got:
            missing += 1
            if shown < args.show:
                shown += 1
                print("MISSING %s %s %s want %r" % (k[0], k[1], k[2], v))
            continue
        if got[k] == v:
            agree += 1
        else:
            differ += 1
            if shown < args.show:
                shown += 1
                print("DIFFER  %s %s %s\n  got  %r\n  want %r"
                      % (k[0], k[1], k[2], got[k], v))
    print("truth-rows %d" % len(want))
    print("agree %d" % agree)
    print("differ %d" % differ)
    print("missing %d" % missing)
    if not want:
        print("NOTHING COMPARED")
        return 1
    return 1 if (differ or missing) else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Apply one mutation to one file: replace OLD with NEW, exactly once.

Refuses when the pattern is absent or occurs more than once.  A mutation
harness that silently applies nothing reports every mutant as a survivor,
which reads as a weak suite and is a broken harness; one that applies a
pattern twice is testing something other than what it says.
"""
import sys

if len(sys.argv) != 4:
    sys.exit(2)
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
old = old.replace("\\n", "\n").replace("\\t", "\t")
new = new.replace("\\n", "\n").replace("\\t", "\t")
s = open(path).read()
if s.count(old) != 1:
    sys.stderr.write("patch: %d occurrences of %r in %s\n"
                     % (s.count(old), old[:60], path))
    sys.exit(1)
open(path, "w").write(s.replace(old, new))

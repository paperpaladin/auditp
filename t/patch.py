#!/usr/bin/env python3
"""Apply one mutation to one file: replace OLD with NEW, exactly once.

Refuses when the pattern is absent or occurs more than once.  A mutation
harness that silently applies nothing reports every mutant as a survivor,
which reads as a weak suite and is a broken harness; one that applies a
pattern twice is testing something other than what it says.
"""
import os
import sys

def unescape(s):
    """\\n and \\t for a newline and a tab, \\\\ for a backslash.

    The two-replace version this had could not express a Go source line
    containing a backslash escape, because it turned the backslash-n
    INSIDE 'x == \\n' into a real newline.  So no mutant could touch any
    line of the reader or the renderer that mentions a newline
    character, and the limitation was invisible: such a mutant is
    reported NOBUILD, which reads as a mistake in the mutant.
    """
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            c = s[i + 1]
            if c == "n":
                out.append("\n")
            elif c == "t":
                out.append("\t")
            elif c == "\\":
                out.append("\\")
            else:
                out.append(s[i:i + 2])
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def check(catalogue):
    """Report every entry in the catalogue whose pattern no longer applies.

    The sweep is minutes and so runs nowhere near a commit, which leaves
    nothing to ask between sweeps whether the table still describes the
    sources.  Four entries here had gone dead under refactoring and were
    neither killed nor surviving: a pattern that does not match is not a
    result about the suite, it is an entry that tests nothing.  This asks
    only that question, over the unescaped patterns rather than the
    literal fields, because the escaping is itself one of the ways an
    entry dies.
    """
    src = {}
    bad = 0
    n = 0
    for lineno, line in enumerate(open(catalogue), 1):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("@@@")
        if len(parts) != 4:
            print("line %d: %d fields, want 4" % (lineno, len(parts)))
            bad += 1
            continue
        n += 1
        name, path, pat = parts[0], parts[1], unescape(parts[2])
        d = os.path.join(os.path.dirname(catalogue) or ".", "..")
        full = os.path.join(d, path)
        if path not in src:
            try:
                src[path] = open(full).read()
            except OSError as e:
                print("line %d: %s: %s" % (lineno, name, e))
                src[path] = ""
        c = src[path].count(pat)
        if c != 1:
            print("line %d: %s: %d matches in %s for %r"
                  % (lineno, name, c, path, parts[2][:60]))
            bad += 1
    print("mutants --check: %d entries, %d that do not apply" % (n, bad))
    return 1 if bad else 0


if len(sys.argv) == 2 and sys.argv[1] == "--check":
    sys.exit(check(os.path.join(os.path.dirname(__file__), "mutants.txt")))
if len(sys.argv) != 4:
    sys.exit(2)
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
old = unescape(old)
new = unescape(new)
s = open(path).read()
if s.count(old) != 1:
    sys.stderr.write("patch: %d occurrences of %r in %s\n"
                     % (s.count(old), old[:60], path))
    sys.exit(1)
open(path, "w").write(s.replace(old, new))

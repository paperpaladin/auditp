#!/usr/bin/env python3
"""Apply one mutation to one file: replace OLD with NEW, exactly once.

Refuses when the pattern is absent or occurs more than once.  A mutation
harness that silently applies nothing reports every mutant as a survivor,
which reads as a weak suite and is a broken harness; one that applies a
pattern twice is testing something other than what it says.
"""
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

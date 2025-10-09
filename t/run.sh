#!/bin/sh
# auditp test suite.
#
# Prints a final line "N passed, M failed", which the collection's tooling
# parses. Exits non-zero if anything failed.
set -u

cd "$(dirname "$0")/.." || exit 2

AUSEARCH=/usr/sbin/ausearch
[ -x "$AUSEARCH" ] || {
	echo "auditp: $AUSEARCH is not executable; it is the only oracle for" >&2
	echo "every fact this suite checks, so a reduced run would print" >&2
	echo "'0 passed, 0 failed' having checked nothing." >&2
	exit 2
}

[ -x ./auditp ] || { echo "no ./auditp binary: run make, not t/run.sh" >&2; exit 2; }
# A binary older than its source is the stale-binary trap METHOD warns about.
for f in *.go go.mod; do
	[ "$f" -nt ./auditp ] && { echo "$f is newer than ./auditp: run make" >&2; exit 2; }
done

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "ok   $*"; }
no()   { fail=$((fail+1)); echo "FAIL $*"; }

ok "skeleton builds"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

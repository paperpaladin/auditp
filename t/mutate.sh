#!/bin/sh
# Build each deliberate defect in t/mutants.txt and run the whole suite
# against it.
#
# Nothing here edits the working tree: each mutant is built from a copy of
# the sources in a scratch directory and the suite is pointed at that
# binary with $AUDITP.  A mutation harness that patches in place and
# restores afterwards is one interrupted run away from a corrupted tree,
# and the thing it corrupts is the code the suite is about to approve.
#
# Three outcomes, kept apart:
#   KILLED    the suite went red, and the names of the assertions that
#             caught it are printed
#   SURVIVED  the suite stayed green.  A hole, written down as one.
#   NOPATCH   the pattern is absent from the file or occurs more than
#             once, so the entry describes source that is not there any
#             more.  Four entries sat in this state unnoticed because it
#             shared a bucket with the one below.  t/patch.py --check,
#             which t/run.sh runs, is what now catches it in a second.
#   NOBUILD   the patch applied and the result did not compile.  Neither
#             is a result about the suite, and counting either as a kill
#             would be the easiest way to fake this number.
set -u
cd "$(dirname "$0")/.." || exit 2

T=t/tmp.mut.$$
mkdir -p "$T/src" || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
cp ./*.go go.mod "$T/src/"

killed=0
survived=0
nobuild=0
nopatch=0
survivors=""

run_one() {
	name=$1
	file=$2
	old=$3
	new=$4
	rm -rf "$T/w"
	cp -r "$T/src" "$T/w"
	if ! python3 t/patch.py "$T/w/$file" "$old" "$new"; then
		nopatch=$((nopatch + 1))
		echo "NOPATCH  $name (pattern not found or ambiguous)"
		return
	fi
	if ! (cd "$T/w" && go build -mod=mod -o ../mut . ) 2>"$T/build.err"; then
		nobuild=$((nobuild + 1))
		echo "NOBUILD  $name ($(head -1 "$T/build.err"))"
		return
	fi
	if AUDITP="$PWD/$T/mut" sh t/run.sh > "$T/out" 2>&1; then
		survived=$((survived + 1))
		survivors="$survivors $name"
		echo "SURVIVED $name"
	else
		killed=$((killed + 1))
		echo "KILLED   $name: $(grep '^FAIL' "$T/out" | head -2 | \
			sed 's/^FAIL *//' | cut -c1-70 | tr '\n' ';')"
	fi
}

# The catalogue is split by a helper rather than by the shell: a field
# separator that can appear inside Go source cannot be read with IFS, and
# the first version of this lost three mutants to a pipe in an expression
# and called them NOBUILD.
python3 - "$T" <<'SPLIT' || exit 2
import os, sys
d = sys.argv[1]
n = 0
for line in open("t/mutants.txt"):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    parts = line.split("@@@")
    if len(parts) != 4:
        sys.stderr.write("mutants.txt line %r has %d fields\n"
                         % (line[:40], len(parts)))
        sys.exit(2)
    for i, p in enumerate(parts):
        open(os.path.join(d, "m%04d.%d" % (n, i)), "w").write(p)
    n += 1
open(os.path.join(d, "count"), "w").write(str(n))
SPLIT
n=$(cat "$T/count")
i=0
while [ "$i" -lt "$n" ]; do
	m=$(printf "m%04d" "$i")
	run_one "$(cat "$T/$m.0")" "$(cat "$T/$m.1")" \
	        "$(cat "$T/$m.2")" "$(cat "$T/$m.3")"
	i=$((i + 1))
done

echo
echo "mutants: $killed killed, $survived survived, $nopatch did not apply,"\
     "$nobuild did not build"
[ -n "$survivors" ] && echo "survivors:$survivors"
[ "$nobuild" -eq 0 ] && [ "$nopatch" -eq 0 ] || exit 1
exit 0

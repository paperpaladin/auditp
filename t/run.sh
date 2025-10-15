#!/bin/sh
# auditp test suite.
#
# Prints a final line "N passed, M failed", which the collection's tooling
# parses.  Exits non-zero if anything failed.
#
# The scratch directory is per-process with an EXIT trap: two concurrent
# runs must not feed each other their intermediate files.
set -u

cd "$(dirname "$0")/.." || exit 2

AUSEARCH=/usr/sbin/ausearch
[ -x "$AUSEARCH" ] || {
	echo "auditp: $AUSEARCH is not executable.  It is the only oracle for" >&2
	echo "every fact this suite checks, so a reduced run would print" >&2
	echo "'0 passed, 0 failed' having checked nothing." >&2
	exit 2
}

[ -x ./auditp ] || { echo "no ./auditp binary: run make, not t/run.sh" >&2; exit 2; }
# A binary older than its source is the stale-binary trap METHOD warns about:
# three terminfo mutants were recorded as surviving against one.
for f in *.go go.mod; do
	[ "$f" -nt ./auditp ] && { echo "$f is newer than ./auditp: run make" >&2; exit 2; }
done

T=t/tmp.$$
mkdir -p "$T" || exit 2
trap 'rm -rf "$T"' EXIT INT TERM

pass=0
fail=0
ok() { pass=$((pass+1)); echo "ok   $*"; }
no() { fail=$((fail+1)); echo "FAIL $*"; }

CORPUS=t/corpus/gen.log
HOSTILE=t/corpus/hostile.log
TRUTH=t/corpus/truth.tsv

# --- 1. the corpus is what is committed -------------------------------
# A generator whose output drifts takes every number in the README with it,
# so regenerating must reproduce the committed files byte for byte.
python3 t/gen.py --out "$T/gen.log" --truth "$T/truth.tsv" \
	--hostile "$T/hostile.log" --interleaved "$T/inter.log" \
	--counts "$T/counts.txt" >/dev/null 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	no "t/gen.py exited $rc"
else
	cmp -s "$T/gen.log" "$CORPUS"   && ok "corpus regenerates byte for byte" \
	                                || no "corpus regenerates differently"
	cmp -s "$T/truth.tsv" "$TRUTH"  && ok "ground truth regenerates byte for byte" \
	                                || no "ground truth regenerates differently"
	cmp -s "$T/hostile.log" "$HOSTILE" && ok "hostile corpus regenerates byte for byte" \
	                                || no "hostile corpus regenerates differently"
	cmp -s "$T/counts.txt" t/corpus/counts.txt && ok "construct counts regenerate" \
	                                || no "construct counts regenerate differently"
fi

# --- 2. floors, so that nothing here can pass vacuously ---------------
# A comparison over an empty corpus agrees with everything.  Each floor is
# a construct with code behind it: if the count is zero that code is
# untested however many other fields agree.
floor() { # name  minimum  actual
	if [ "$3" -ge "$2" ]; then ok "corpus has $3 $1 (floor $2)"
	else no "corpus has only $3 $1, floor is $2: that construct is untested"; fi
}
cnt() { awk -v k="$1" '$1==k{print $2; found=1} END{if(!found) print 0}' t/corpus/counts.txt; }

floor "records"             800 "$(cnt records)"
floor "quoted values"       800 "$(cnt quoted)"
floor "hex-encoded values"   90 "$(cnt hex-encoded)"
floor "multi-record events" 100 "$(cnt multi-record-events)"
floor "nested msg lists"     40 "$(cnt nested-msg)"
floor "prose prefixes"       10 "$(cnt prose-prefix)"
floor "node= prefixes"        2 "$(cnt node-prefix)"
floor "empty values"          2 "$(cnt edge-empty)"
floor "PATH items"           80 "$(cnt path-items)"
floor "x86_64 syscalls"      60 "$(cnt syscall-x86_64)"
floor "i386 syscalls"        20 "$(cnt syscall-i386)"
floor "seccomp records"      80 "$(cnt seccomp)"
floor "errno exits"          25 "$(cnt errno-exit)"
floor "hostile text values"  12 "$(cnt edge-text)"

ntyp=$(cut -d" " -f1 "$CORPUS" | sed "s/^node=[^ ]* //" | sort -u | wc -l)
floor "distinct record types" 45 "$ntyp"

# --- 3. the parser loses nothing --------------------------------------
# Unparse writes the parsed records back out.  Byte-for-byte equality with
# the input is the one check that notices a field the splitter swallowed:
# it reads only our side, so it is not an oracle, but a splitter that drops
# a value cannot satisfy it.
./auditp -o unparse "$CORPUS" > "$T/rt.log" 2>"$T/rt.err"
if cmp -s "$CORPUS" "$T/rt.log"; then ok "round trip: $(wc -l < "$CORPUS") records reproduced byte for byte"
else no "round trip differs: $(cmp "$CORPUS" "$T/rt.log" 2>&1 | head -1)"; fi

# --- 4. the oracle, field by field ------------------------------------
./auditp -o flat "$CORPUS" > "$T/ours.flat" || no "auditp -o flat exited non-zero"
python3 t/oracle.py "$CORPUS" > "$T/orc.flat" 2>"$T/orc.err"
if [ -s "$T/orc.flat" ]; then
	python3 t/compare.py --no-refusals --ours "$T/ours.flat" --oracle "$T/orc.flat" \
		> "$T/cmp.txt" 2>&1
	rc=$?
	# Anchored to end of line: an unanchored extractor also matched the
	# example lines below the summary and returned 1300 of them as one
	# number, which the shell then compared as a string.
	num() { awk -v k="$1" '$1==k && $2 ~ /^[0-9]+$/ && NF==2 {print $2; exit}' "$T/cmp.txt"; }
	n=$(awk '$1=="compared"{print $2; exit}' "$T/cmp.txt")
	nn=$(awk '$1=="compared"{print $4; exit}' "$T/cmp.txt")
	w=$(num WRONG)
	r=$(num REFUSED)
	mo=$(num MISSING-ours)
	mc=$(num MISSING-oracle)
	if [ "$rc" -eq 0 ]; then
		ok "raw: $n fields over $nn names identical to ausearch, 0 wrong, 0 missing"
	else
		no "raw: $w wrong, $r differing, $mo missing from us, $mc missing from the oracle"
		sed -n '1,30p' "$T/cmp.txt"
	fi
	[ "${n:-0}" -ge 10000 ] && ok "raw comparison covered $n fields (floor 10000)" \
	                        || no "raw comparison covered only ${n:-0} fields"
	[ "${nn:-0}" -ge 100 ] && ok "raw comparison covered $nn distinct field names (floor 100)" \
	                       || no "raw comparison covered only ${nn:-0} field names"
else
	no "t/oracle.py produced nothing: $(head -2 "$T/orc.err")"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

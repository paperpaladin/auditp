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

# AUDITP lets the mutation harness point the whole suite at a binary built
# from patched sources in a scratch directory, so a mutation run never
# edits the working tree.
AUDITP=${AUDITP:-./auditp}
[ -x "$AUDITP" ] || { echo "no $AUDITP binary: run make, not t/run.sh" >&2; exit 2; }
# A binary older than its source is the stale-binary trap METHOD warns about:
# three terminfo mutants were recorded as surviving against one.
for f in *.go go.mod; do
	[ "$f" -nt "$AUDITP" ] && { echo "$f is newer than $AUDITP: run make" >&2; exit 2; }
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
	if [ "$3" -ge "$2" ]; then ok "$3 $1 (floor $2)"
	else no "only $3 $1, floor is $2: that is untested"; fi
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

# --- 3. the parser loses nothing, and the oracle, field by field -----
# Two corpora.  gen.log is the main one; interleaved.log holds two events
# whose records alternate in the file, which is what a busy machine
# produces and what a correlator that only looks at adjacent lines gets
# wrong.  A mutation that merged a record only into the most recent event
# survived the whole suite while the second corpus was not being read.
compare_corpus() {
	label=$1
	log=$2
	# Round trip.  Reads only our side, so it is not an oracle, but a
	# splitter that swallows a field cannot satisfy it.
	"$AUDITP" -o unparse "$log" > "$T/$label.rt" 2>"$T/$label.rt.err"
	if cmp -s "$log" "$T/$label.rt"; then
		ok "$label round trip: $(wc -l < "$log") records reproduced byte for byte"
	else
		no "$label round trip differs: $(cmp "$log" "$T/$label.rt" 2>&1 | head -1)"
	fi

	"$AUDITP" -o flat "$log" > "$T/$label.ours" || no "$label: auditp -o flat exited non-zero"
	python3 t/oracle.py "$log" > "$T/$label.orc" 2>"$T/$label.orc.err"
	if [ ! -s "$T/$label.orc" ]; then
		no "$label: t/oracle.py produced nothing: $(head -2 "$T/$label.orc.err")"
		return
	fi
	python3 t/compare.py --no-refusals --ours "$T/$label.ours" \
		--oracle "$T/$label.orc" > "$T/$label.cmp" 2>&1
	rc=$?
	num() { awk -v k="$1" '$1==k && $2 ~ /^[0-9]+$/ && NF==2 {print $2; exit}' "$T/$label.cmp"; }
	n=$(awk '$1=="compared"{print $2; exit}' "$T/$label.cmp")
	nn=$(awk '$1=="compared"{print $4; exit}' "$T/$label.cmp")
	if [ "$rc" -eq 0 ]; then
		ok "$label raw: $n fields over $nn names identical to ausearch, 0 wrong, 0 missing"
	else
		no "$label raw: $(num WRONG) wrong, $(num REFUSED) differing, $(num MISSING-ours) missing from us, $(num MISSING-oracle) missing from the oracle"
		sed -n '1,30p' "$T/$label.cmp"
	fi
	echo "$n" > "$T/$label.nfields"
	echo "$nn" > "$T/$label.nnames"
}

compare_corpus main "$CORPUS"
compare_corpus interleaved t/corpus/interleaved.log
floor "fields compared raw in the main corpus" 10000 "$(cat "$T/main.nfields")"
floor "distinct field names compared raw" 100 "$(cat "$T/main.nnames")"
floor "fields compared raw in the interleaved corpus" 90 "$(cat "$T/interleaved.nfields")"

# --- 5. the tables, against the two sources each was built from --------
# t/tables.py reads ausyscall AND the uapi headers, ausearch AND
# linux/audit.h, and fails if they disagree about which number is which
# call.  A table checked against the tool it was copied from is checked
# against nothing.
skip=0
for src in /usr/bin/ausyscall /usr/lib/linux/uapi/x86/asm/unistd_64.h \
           /usr/lib/linux/uapi/x86/asm/unistd_32.h /usr/include/linux/audit.h \
           /usr/include/linux/elf-em.h /usr/include/asm-generic/errno.h; do
	[ -e "$src" ] || { echo "SKIP table check: $src is missing"; skip=1; }
done
if [ "$skip" -eq 0 ]; then
	python3 t/tables.py --out "$T/tables.go" --report "$T/tables.rep" 2>"$T/tables.err"
	rc=$?
	if [ $rc -ne 0 ]; then
		no "t/tables.py exited $rc: $(grep -v "^ " "$T/tables.rep" | tail -3)"
		sed -n "/^problems/,\$p" "$T/tables.rep" | head -12
	else
		cmp -s "$T/tables.go" tables.go && ok "tables.go matches what its sources say today" \
		                               || no "tables.go is stale: regenerate with t/tables.py"
		cmp -s "$T/tables.rep" t/tables.expect && ok "the known source disagreements are exactly the recorded ones" \
		                               || { no "the set of source disagreements changed"; diff t/tables.expect "$T/tables.rep" | head -12; }
	fi
	tnum() { awk -v k="$1" '$1==k{print $2; exit}' "$T/tables.rep"; }
	floor "x86_64 syscalls agreed by two sources" 370 "$(tnum syscall-x86_64-two-source-agree)"
	floor "i386 syscalls agreed by two sources"   448 "$(tnum syscall-i386-two-source-agree)"
	floor "audit types agreed by two sources"      70 "$(tnum audit-types-two-source-agree)"
	floor "errno names agreed by two sources"     125 "$(tnum errno-two-source-agree)"
	floor "signal names agreed by two sources"     30 "$(tnum signal-two-source-agree)"
	floor "arch names agreed by two sources"       10 "$(tnum arch-two-source-agree)"
fi

# --- 6. the oracle again, interpreted ---------------------------------
# Here the refusal channel is live.  WRONG is the only failure: a field
# auditp declined to translate and ausearch did is a gap, counted and
# named, and a field auditp translated differently is a defect.
"$AUDITP" -o flat -i "$CORPUS" > "$T/oursi.flat" || no "auditp -i -o flat exited non-zero"
python3 t/oracle.py --interpret "$CORPUS" > "$T/orci.flat" 2>"$T/orci.err"
if [ -s "$T/orci.flat" ]; then
	python3 t/compare.py --known t/known-diff.txt \
		--ours "$T/oursi.flat" --oracle "$T/orci.flat" \
		> "$T/cmpi.txt" 2>&1
	rc=$?
	num() { awk -v k="$1" '$1==k && $2 ~ /^[0-9]+$/ && NF==2 {print $2; exit}' "$T/cmpi.txt"; }
	ni=$(awk '$1=="compared"{print $2; exit}' "$T/cmpi.txt")
	ai=$(num AGREE-i); ap=$(num AGREE-p); rf=$(num REFUSED)
	w=$(num WRONG); mo=$(num MISSING-ours); mc=$(num MISSING-oracle)
	am=$(num AMBIGUOUS); au=$(num AMBIGUOUS-unmet)
	if [ "$rc" -eq 0 ]; then
		ok "interpreted: $ni fields, $ai translated and identical, $ap passed through and identical, $rf refused, $am ambiguous, 0 wrong"
	else
		no "interpreted: $w wrong, $mo missing from us, $mc missing from the oracle, $au stale exemptions"
		sed -n '1,40p' "$T/cmpi.txt"
	fi
	# A floor on the translations, because 0 wrong is also what a build
	# with every interpreter deleted would report.
	floor "fields translated and agreeing" 5000 "${ai:-0}"
	# And a ceiling on the refusals, so the gap cannot quietly grow.
	if [ "${rf:-99999}" -le 3000 ]; then ok "refusals: $rf (ceiling 3000)"
	else no "refusals grew to $rf, ceiling is 3000"; fi
else
	no "t/oracle.py --interpret produced nothing: $(head -2 "$T/orci.err")"
fi

# --- 7. the decoder against the bytes that were encoded ---------------
# The only comparison here that does not involve ausearch.  Agreeing with
# a second decoder and recovering what was encoded are different claims,
# and the hex encoding exists for exactly the bytes two decoders are most
# likely to mangle the same way.
"$AUDITP" -o decode "$CORPUS" > "$T/dec.tsv" || no "auditp -o decode exited non-zero"
python3 t/truth.py --decoded "$T/dec.tsv" --truth "$TRUTH" > "$T/truth.txt" 2>&1
rc=$?
tn() { awk -v k="$1" '$1==k{print $2; exit}' "$T/truth.txt"; }
if [ $rc -eq 0 ]; then
	ok "decoder: $(tn agree) of $(tn truth-rows) values are the bytes the generator encoded"
else
	no "decoder: $(tn differ) differ, $(tn missing) missing of $(tn truth-rows)"
	head -12 "$T/truth.txt"
fi
floor "ground-truth values compared" 1000 "$(tn truth-rows)"

# --- 8. the hex-decode table, against ausearch's behaviour ------------
# Which field names the kernel hex-encodes is a table inside libaudit.
# t/escaped.py puts a hex value into every (record type, field name) pair
# the corpus contains and reads back which ones ausearch decoded.  This is
# derived from the oracle rather than from an independent source, which
# the README says; what it buys is that the compiled-in table cannot go
# stale without this turning red.
python3 t/escaped.py "$CORPUS" > "$T/esc.probe" 2>"$T/esc.err"
if [ -s "$T/esc.probe" ]; then
	"$AUDITP" -o census "$CORPUS" | sed -n 's/^escaped-pair //p' | sort > "$T/esc.ours"
	sort "$T/esc.probe" > "$T/esc.theirs"
	np=$(wc -l < "$T/esc.theirs")
	if cmp -s "$T/esc.ours" "$T/esc.theirs"; then
		ok "hex-decode table: $np (type, field) pairs, identical to what ausearch decodes"
	else
		no "hex-decode table differs from ausearch by $(diff "$T/esc.ours" "$T/esc.theirs" | grep -c '^[<>]') pairs"
		diff "$T/esc.ours" "$T/esc.theirs" | head -10
	fi
	floor "(type, field) pairs that hex-decode" 70 "$np"
	nq=$(sed -n 's/.*: \([0-9]*\) pairs, \([0-9]*\) answered.*/\1 \2/p' "$T/esc.err")
	set -- $nq
	if [ "${1:-0}" -gt 0 ] && [ "${1:-0}" -eq "${2:-0}" ]; then
		ok "hex-decode probe: ausearch answered all $1 pairs it was asked about"
	else
		no "hex-decode probe: ausearch answered ${2:-0} of ${1:-0} pairs, so the rest were not tested"
	fi
else
	no "t/escaped.py produced nothing: $(head -2 "$T/esc.err")"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

# auditp

Reads a Linux kernel audit log, reassembles the records that belong to one
event, decodes every field value out of whichever of the three encodings
the kernel used, and translates syscall numbers, uids, modes, flags and
syscall arguments into the names `ausearch -i` prints for them. Go,
standard library only, no `require` block in `go.mod`.

```
auditp [-i] [-o FORM] [-strict] FILE

  -i          interpret: syscall names, uids, modes, flags, a0 to a3
  -o text     one block per event, one line per record (default)
  -o json     one JSON object per event, one per line
  -o flat     one tab-separated row per field, for comparison
  -o census   what the input contained, per construct
  -o unparse  the records written back out, byte for byte the input
  -o decode   the decoded bytes of every field, backslash escaped
  -strict     exit 1 on a line that will not parse, instead of counting it
```

`make test` builds and runs the suite. It needs `/usr/sbin/ausearch` and
refuses to run without it, because every fact it checks is checked against
ausearch and a reduced run would print a pass count having compared
nothing.

## What it is measured against

`/usr/sbin/ausearch` 4.0.2 is a complete second implementation of this
exact job, written by the people who define the format. `ausearch -i -if
FILE` is the main oracle and where the two disagree auditp is wrong until
shown otherwise. It is not on `PATH` here and is called by absolute path.

`/usr/bin/ausyscall` gives the syscall number to name mapping, and
`/usr/lib/linux/uapi/x86/asm/unistd_64.h` and `unistd_32.h` give the same
fact from a second source. Every table in `tables.go` is built by
`t/tables.py` from two sources and the suite regenerates it and compares,
so a table copied out of the tool it is checked against cannot pass.

`/usr/include/linux/audit.h` is the second source for record type numbers
and arch constants, `/usr/include/asm-generic/errno.h` and `errno-base.h`
for errno names, `/usr/include/linux/elf-em.h` for the machine types
inside an `arch=` value.

`python3` 3.13.5 is an independent second parser: `t/oracle.py` reduces
ausearch's output to flat per-field rows, `t/escaped.py` asks ausearch
which `(record type, field)` pairs it hex-decodes, and `t/truth.py`
compares the decoder against the bytes the generator encoded rather than
against a second decoder.

The corpus generator is ours and is the weakest link here; see what the
corpus holds, below.

Oracles that were tried and do not work on this machine, measured rather
than assumed:

- `/usr/sbin/auditctl -s` answers "You must be root to run this program",
  so no audit rule can be loaded and nothing can be made to emit a
  rule-driven SYSCALL or PATH record on demand.
- `/var/log/audit/audit.log` is mode 0600 and root-owned: "Permission
  denied". Nothing here reads it.
- `ausearch` itself prints "Error opening config file (Permission denied)"
  on every run as uid 1000 and then works, using its built-in
  `end_of_event_timeout` of 2. Both lines go to stderr and the harness
  reads stdout.
- `ausyscall --version` is not a version flag. It answers "Unknown syscall
  --version using x86_64 lookup table", which is the same answer it gives
  for a syscall it does not know, so the version of the table cannot be
  asked for.

## Numbers

Measured on 2 November 2026, auditd 4.0.2, kernel 7.2.13-200.fc44.x86_64,
go 1.24.4. `make test` prints all of them and takes about 20 seconds.

| what | measured |
|---|---|
| assertions | 103 passed, 0 failed |
| fields compared against `ausearch -i`, whole corpus | 20,903 over 119 distinct names |
| of those, translated by auditp and identical | 15,270 |
| of those, passed through by auditp and identical | 5,588 |
| of those, refused by auditp where ausearch translated | 42 |
| of those, different | 0 |
| of those, ausearch's output is ambiguous | 3 |
| fields compared without `-i` | 20,903, 0 different, 0 missing on either side |
| the interleaved corpus, without `-i` | 99 fields over 38 names |
| event assembly: `(event, position, type)` triples | 1,152, identical to ausearch |
| `@time` compared again in a second timezone | 1,152 |
| decoded values against the bytes the generator encoded | 1,644 of 1,644 |
| `(type, field)` pairs that hex-decode, against ausearch | 92, identical |
| pairs the hex-decode probe put to ausearch | 538 asked, 538 answered |
| `sockaddr` shapes put to both sides | 89, of which 84 identical and 5 refused |
| TTY keystroke renderings put to both sides | 363 of 363 identical |
| fuzzed fields, 3 seeds | 10,985 compared, 10,420 identical, 0 wrong |
| truncated and corrupted inputs | 1,116 cases, 0 crashes, 0 misread |
| malformed lines put to both parsers | 24, no over-refusal either way |
| round trip: records written back out byte for byte | 1,152 of 1,152, and 9 of 9 |
| `ausearch --format csv` rows against auditp's events | 874, over 6 of its 16 columns |
| `aureport -s --summary -i` syscall names | 91 counted identically over 602 records |
| mutants (`make mutants`, not part of `make test`) | 118 applied, 114 killed, 4 survived, 0 did not apply, 0 did not build |

Sixteen tables are each built from two sources and compared every run:
372 x86_64 and 450 i386 syscall numbers, 73 record types, 128 errno
names, 30 signal names, 10 arch constants, 31 fcntl commands, 36 bpf
commands, 39 ptrace requests, 28 mount and 20 message flags, 22 clone
flags, 20 socketcall and 12 ipc call names, and the TTY tables probed out
of ausearch, 28 control bytes and 143 key sequences.

Refusals are counted apart from disagreements, in both directions, because
they need different work. A disagreement is a bug. A refusal is a feature
that is not written yet. 42 fields in the corpus are refused, all of them
`a0`, `a1` or `a2` on one of the 18 `(argument, syscall)` pairs ausearch
interprets and auditp has no kind for. The corpus holds a record for every
one of those pairs and the suite requires the set of refused pairs to be
exactly the set the census calls the gap: a pair the corpus never reaches
is an untested refusal, and a refusal the gap does not list is a field
auditp stopped interpreting without anyone noticing. Five more refusals
are in the `sockaddr` probe rather than the corpus, three address families
whose byte string ausearch octal-escapes.

"Passed through and identical" is the third count and is the one to be
careful with. 5,588 fields agree because neither tool translates them, and
that is not evidence that auditp got anything right. It is reported
separately for exactly that reason, and the floor the suite asserts is on
the translated count only.

Every number above moved when the corpus grew on 21 October and the table
here was not revisited, so for eleven days this section described a corpus
of 903 records with 49 assertions over it. The mutation row was the worst
of them and has its own paragraph below.

## Where auditp and ausearch disagree

Three fields of two kinds, listed in `t/known-diff.txt`, which the suite
requires to be exactly that set: a new entry fails, and an entry that stops firing fails
too, because a stale exemption is how a real defect gets excused later.

**Signal 30.** ausearch prints `IGPWR`, with no S. Both sources auditp
builds its table from say `SIGPWR`, and auditp prints `SIGPWR` and takes
the disagreement rather than copying a defect into a second
implementation, which is how a defect becomes the format. 29 and 31 either
side of it are right in ausearch, so it is one entry and not a shift. It
shows up twice, once as `sig=` in an ANOM_ABEND record and once as `a1=`
on a `kill`. Found by the two-source table check; nothing else here could
have found it, because a table built from ausearch would have agreed with
ausearch.

**An EXECVE argument that is one space.** `ausearch -i` writes a space
after every field, so a field whose whole value is a space and a field
whose value is empty come out of its output identically. The kernel
hex-encodes that argument as `20` and auditp reads back one space.
Neither side can do anything about it: `ausearch -i` is not a
round-trippable format and this is the record that proves it.

## The other two views inside auditd

`ausearch -i` prints fields. `ausearch --format csv` prints one row per
event with the subject, the object, the action and the result worked out
by a higher layer. `aureport --summary` walks the events and counts.
The second and third are derived differently from the first inside the
same tool, so each can disagree with it about an event the per-field
comparison agrees on. Both were sitting unused and both are wired up
now, in `t/csvview.py` and `t/aureport.py`.

Neither replaces the field comparison. A count over a corpus is a weaker
instrument than a comparison per field, and the reason to run these is
the derivation rather than the number.

The csv gives 874 rows for 874 events and six of its columns are a
restatement of something auditp already has: `NODE` and `SERIAL_NUM`
from the event key, `DATE` and `TIME` from the timestamp formatted a
second way, `EVENT`, `SESSION`, `SUBJ_PRIME`, `SUBJ_SEC` and `RESULT`.
All of them agree. `aureport -s --summary -i` counts records per syscall
NAME, and the name depends on the record's own arch, so 91 names over
602 records put both syscall tables and the choice between them under a
third derivation. All 91 agree.

What lining them up required is the interesting part, and every rule
below is ausearch being different from itself rather than auditp being
wrong:

- The csv leaves `EVENT` empty for a record type libaudit has no number
  for, where `ausearch -i` prints the name out of the record's own text.
  Three in the corpus: LANDLOCK_ACCESS, LANDLOCK_DOMAIN and
  `UNKNOWN[9999]`.
- The csv leaves `SUBJ_SEC` empty for 6 events, all USER_LOGIN or
  DAEMON_START/END, where `-i` prints a uid.
- `SUBJ_PRIME` is the nested `acct=` for a USER_LOGIN, `system` for an
  unset login uid, and the login uid's name otherwise. The first version
  of that rule took `acct=` wherever there was one and differed on 25
  events, because libaudit prefers it only for a login, where the
  account is the one being logged into rather than the subject doing it.
- `RESULT` is derived from the record type and its fields when there is
  no `success=` to restate, which is 178 of the 874 events, so only the
  512 that have one are compared.
- aureport leaves syscall 0 out of its syscall summary entirely. Four
  records in the corpus call it, two x86_64 `read` and two i386
  `restart_syscall`, and both names appear in the report with the counts
  of the other records that call them, so this is not a missing table
  entry.
- aureport does not fold i386's multiplexers into the syscall name.
  `ausearch -i` prints `socketcall(bind)` and `ipc(msgsnd)`; aureport
  prints `socketcall` and `ipc`, 11 and 9 of them, and names no sub-call
  anywhere.

One trap in the alignment was ours. An audit key is not unique: the
corpus holds a USER_AUTH and a BPF event at the same timestamp and
serial, and ausearch emits them in the other order from auditp. Pairing
by position reported both as a disagreement about the record type, which
is an ordering difference between two events both tools agree exist
arriving dressed as a parse defect. `t/jsoncheck.py` documents the same
trap from the other side, where keying on the string collapsed the pair
and invented 17 field disagreements.

Both checks were watched to fail. The csv comparison over the main
corpus kills `uid-no-unset` with 244 subject disagreements and
`key-ignores-node` by leaving 2 events unpaired in each direction, and
over the interleaved corpus it kills `events-adjacent-only`, which the
main corpus cannot reach. The aureport comparison kills
`syscall-ignores-arch` with 62 names differing and `syscall-off-by-one`
with 132. All five are already killed elsewhere in the suite; what the
runs establish is that these checks can tell.

## What the corpus holds

1,152 records in 874 events, 18,215 fields, 371 subfields inside nested
`msg='...'` lists, 52 record types, 115 distinct field names. Five files
are committed under
`t/corpus/`: the log, the ground truth for every decoded value, a log of
malformed lines, a log whose two events interleave, and the construct
counts. `t/gen.py` writes all five from a fixed seed and the suite
regenerates and compares them byte for byte, because a corpus that drifts
takes every number above with it.

It is generated and not harvested, and that is a deliberate loss. An
earlier session built this corpus out of records taken off this machine
with `journalctl _TRANSPORT=audit` and committed them. A real audit log
says who logged in, what is installed and where their files are, and these
repositories are published, so the history was reset and the records are
gone. Nothing in `t/gen.py` names a real host, user, path, package or
process: the hosts are `node-a` and `node-b`, the programs are `widgetd`,
`bargen` and `mesh-agent` under `/opt/widget`, the accounts are `root`,
`svcop`, `widget` and `nobody`.

What is not invented, and must not be, is every kernel constant: each
syscall number, errno, signal, address family, mode bit, open flag and
record type in the corpus is the real one. Substituting those would make
the comparison agree about nothing.

Two things generating buys back. The ground truth file records the exact
bytes the generator encoded into every hex and quoted value, so the
decoder is checked against what was meant and not only against a second
decoder; a hex value holding a newline, a NUL, a double quote or a byte
above 0x7f is a construct no log on this machine happened to contain. And
constructs can be written on demand: without privilege to load an audit
rule, nothing here emits a PATH record at all.

The counts below are `t/corpus/counts.txt` as committed, in the
generator's own order, and the suite asserts a floor on the ones with
code behind them. A hex decoder over a corpus with
no hex-encoded value passes and proves nothing, and so does an i386
syscall table over a corpus with no i386 records.

```
lines 1152               truth-rows 1645          anom-abend 16
avc 12                   bare 15512               bpf 40
bpf-cmd 7                clone-flag 14            config-change 4
edge-cap 7               edge-data 7              edge-duplicate 1
edge-empty 2             edge-hexshape 7          edge-no-fields 1
edge-node 2              edge-nul 6               edge-proctitle 3
edge-seccomp-code 5      edge-text 12             epoll-op 5
errno-exit 26            event-openat 60          execve 4
fcntl-cmd 42             fcntl-i386 2             gap-record 32
hex-encoded 99           ipc-call 9               kill-signal 16
mmap-prot 40             mount-flag 10            msg-flag 60
multi-record-events 125  nested-msg 50            netfilter-cfg 6
node-prefix 2            openat-flags 44          pam-record 30
path-items 91            path-mode 60             proctitle 125
prose-prefix 13          ptrace-req 9             quoted 1554
records 1152             seccomp 89               sockaddr 5
socket-family 20         socketcall 9             split-event 7
syscall-i386 24          syscall-records 502      syscall-x86_64 65
type-zoo 23              uid-value 8              umount-flag 8
user-cmd 10
```

`type-zoo` is 23 record types that appear once or twice each, to put the
type table under something. Five of them are written the way auditd writes
a type its own table has no name for, `type=UNKNOWN[1100]`, which auditp
resolves back to `USER_AUTH` under `-i`.

The counter is produced by the generator rather than by the parser, which
is the right way round: a construct the parser cannot see is still counted.
What it cannot catch is a construct neither the generator nor the parser
knows about, and that is the whole weakness of a written corpus.

## Mutation testing

`make mutants` applies one deliberate defect at a time to the sources,
rebuilds in a scratch directory, and runs the whole suite against the
result. Nothing patches the working tree. Four outcomes are kept apart:
KILLED, SURVIVED, NOPATCH for an entry whose pattern is not in the file
any more or now matches twice, and NOBUILD for a patch that applied and
did not compile.

**118 mutants, 114 killed, 4 survived, 0 did not apply, 0 did not
build.** Measured 2 November 2026, every entry in `t/mutants.txt` run
against the suite, 31 minutes. The run was made before the csv and
aureport comparisons below were added, which can only turn a survivor
into a kill, so each of the four survivors was then put to both new
checks on its own and survived both: the figures hold for the suite as
committed.

They are spread over the lexer (the quoted and single-quoted encodings,
the field-name rule, the value terminator, the prose prefix), the event
key (dropping the node, the serial or the milliseconds from it, and
merging a record only into the most recently seen event), the hex
decoder (nibble order, the odd trailing nibble, the rule for which bare
value is hex at all, each of the three escape cases), the packed
`sockaddr`, the TTY keystroke renderer, the JSON writer, and every
interpreter: syscall names and their arch dependence, uid and gid
resolution, file modes, exit codes, capability masks, the seccomp mask,
`res`, signals, netfilter families, mmap flags, open flags, the
timestamp, the record type name, the nested `msg='...'` list, and each
of the syscall argument kinds.

### The number this section used to carry

It said 58 mutants, 57 killed, 1 survived, dated 20 October. That was
true of a table of 58 entries. The table reached 115 across ten commits
the following day and nothing re-ran the sweep, so the published claim
was about a catalogue that no longer existed, and the only honest trace
left of where the figure came from was the sentence below saying one
mutant "survived the first run of 58".

Worse than the stale count, four of the 115 entries had gone dead. A
mutation entry is a pattern to find and a replacement to put in its
place; when the source around it is rewritten the pattern stops matching
and the entry tests nothing at all. It is neither killed nor surviving,
so no number in a sweep can show it. The four, and each for a different
reason:

- `hex-escape-in-hex` held a Go character literal for a backslash with
  one level of escaping too few. `t/patch.py` unescapes `\\` to a single
  backslash, so the pattern it looked for was `'\'` where the source has
  `'\\'`. The file's own docstring documents this trap, having been
  rewritten once already for the same reason.
- `syscall-off-by-one` quoted `if name, ok := tab[nr]; ok {`. The
  lookup is now `name, ok := tab[nr]` on its own line with the test
  after it, and the only remaining `; ok {` form nearby is over `tab[n]`
  in the uid resolver.
- `oflag-accmode-ignored` quoted `n &^= 3`, which is not in `interp.go`
  any more: masking the access-mode bits out was wrong about what
  ausearch prints and was replaced by printing the base name only when
  the low two bits are zero. The entry now mutates that rule instead.
- `flags-empty-is-zero` still matched, twice, because `cloneText` grew
  the same three lines as `flagsOrRaw`. `t/patch.py` refuses an ambiguous
  pattern, which is right, and the entry is re-quoted with the function
  that follows it as an anchor.

`t/run.sh` now asks the question the sweep cannot: `t/patch.py --check`
replays the unescaping, counts the matches for every entry, and exits
non-zero if any pattern does not match exactly once. It takes about a
second, so it runs in `make test` where the hour-long sweep cannot, and
it was watched to go red against each of the three ways an entry dies, a
pattern that is gone, a pattern that matches twice, and a backslash
escaped one level too few, and green again after each.

The separation of NOPATCH from NOBUILD is the other half of it. Both
were printed as NOBUILD, and a pattern that no longer applies and a
mutant that does not compile are different problems with different
fixes.

### The four survivors

Three are equivalent and stay in the catalogue so that the claim can be
checked. The fourth is not equivalent and is a gap.

`field-name-needs-two-chars` starts the name scan one byte later. The
caller has already established that the first byte is a letter, and a
letter is a name byte, so the loop's first iteration could only have
advanced past it. The two versions compute the same length for every
input, one-character names included.

`tty-escape-shortest-match` takes the first matching escape sequence
instead of the longest. No entry in the probed table is a proper prefix
of another, over all 143 of them, so the two rules always pick the same
sequence. That is a property of this ausearch's table and not of the
code, which is why the longest-match loop stays.

`clone-flags-from-bit-zero` starts clone's flag scan at bit 0 instead of
bit 8. The table it reads is generated with a floor of bit 8, because
probing the low byte as flags records bit 0 as SIGHUP, so there is
nothing below bit 8 for the loop to find.

`proctitle-leading-nul-becomes-space` deletes the skip of a single
leading NUL in a `proctitle` value, which would put a space at the front
of the command line instead. It survives because no `proctitle` in the
corpus starts with a NUL byte, and it cannot be killed by comparison:
handed `proctitle=002F62696E2F6C73002D6C`, ausearch 4.0.2 answers
`/bin/ls -l C73002D6C`, consuming the leading `00` as two characters
rather than one byte and then running off the end of its own buffer into
the remaining hex digits. There is no correct answer on the other side
to compare against. Killing it means a corpus record plus a third entry
in `t/known-diff.txt` recording that ausearch is wrong here, and that is
queued rather than done.

Two results from earlier runs that were worth more than the count.
`arg-prot-no-none` survived the first run of 58 and was not equivalent:
the corpus held no mmap protection with the PROT_SEM bit set and no
other bit, which is the only value the two versions disagree about. The
fix was to the corpus. And `arg-table-not-per-arch` was reported
NOBUILD, because replacing a call with `if false` left a parameter
unused and Go refuses to compile that; it had been in the catalogue
testing nothing. Rewritten to point the i386 lookup at the x86_64 table,
it dies, by one wrong field.

`time-forced-to-utc` is the mutant that the second-timezone check
exists for. It appends `.UTC()` to the timestamp formatter, passes every
assertion the suite had before that check was added, and is wrong on
every machine not in UTC.

### A check pointed at the wrong binary

The suite names `$AUDITP` everywhere, which is how the mutation harness
runs the whole suite against a binary built from patched sources without
touching the working tree. One line did not: the JSON check was invoked
with `--auditp ./auditp`, so under a mutation run it read the unmutated
program and compared it with itself. Nothing in the JSON writer was
mutated either, so the hole had no witness on either side.

Both halves are fixed. The pin is one word, and three mutants of the
JSON-only code were added to the catalogue: dropping a nested field from
the `order` list, letting a repeated field name overwrite the first
instead of being suffixed, and emitting the hex form of the values that
are not valid UTF-8 for the valid ones instead. All three survive with
`./auditp` in that line and all three die with `$AUDITP`, which is how
the pin was found.

## What does not work

**42 fields are refused, over 18 syscall arguments.** ausearch
interprets the argument of a particular syscall for more pairs than
auditp has a kind for, and the 18 left are `a0` of `clock_settime`,
`getrlimit`, `personality`, `prctl`, `setrlimit` and `unshare`, `a1` of
`fsconfig`, `fsmount`, `fsopen`, `getsockopt`, `sched_setscheduler`,
`setns` and `setsockopt`, and `a2` of `fsmount`, `getsockopt`,
`mq_open`, `setsockopt` and `shmget`. Each prints the raw value and is
counted, rather than printing a plausible number, which would be a wrong
answer rather than a gap. The corpus holds a record for every one of the
18 and the suite requires the refused set and the gap the census
enumerates to be equal.

**Three sockaddr families are refused.** ax25, atmpvc and x25 carry a
raw byte string that ausearch octal-escapes, and for an ax25 address
shorter than nine bytes it writes `call=` and then nothing. Five of the
89 shapes the probe builds fall in those families and auditp prints the
hex it was given for all five. `saddr` for the other families and TTY
`data` were both in this list and are not any more: 84 of the 89
sockaddr shapes and all 363 TTY renderings are identical to ausearch.

**The corpus is written by us.** Every number above is measured over
1,152 records that `t/gen.py` produced. ausearch reads them exactly as
it reads a kernel's own log, so the oracle is external, but the inputs
are not: a
construct nobody thought of is a construct the corpus does not hold. The
deleted harvest is the thing that would have fixed this and it cannot be
published.

**Hostile input is read now, and the ceilings are not zero.** The 24
malformed lines and the 1,116 truncation and byte-flip cases are put to
both parsers, and the two directions are counted apart: 131 corrupted
lines ausearch reads and auditp refuses, 155 the other way. Both are
ceilings in the suite rather than zeroes, because every one of them is a
byte moved inside the record header, where ausearch hunts for
`msg=audit(` anywhere in the line and auditp requires it where the
format puts it. Which of the two is right about such a line is not
established.

**Ten of the csv's sixteen columns are not compared.** `EVENT_KIND`,
`SUBJ_KIND`, `ACTION` and `OBJ_KIND` are libaudit's classification of an
event, which auditp does not do and lists as a non-goal; `OBJ_PRIME`,
`OBJ_SEC` and `HOW` are assembled from several fields by a rule that is
not a restatement of any one of them. `HOW` is the executable for 594 of
the 874 events, the syscall name for 15, empty for 179 and something
else for 86. `OBJ_PRIME` is the `name` field for 60, empty for 549 and
something else for 265. Those counts are printed every run instead of
being compared, which is the measured form of saying auditp does not
classify events.

**One aureport summary of eleven is compared.** `-s --summary -i` is the
syscall names, and it is the one whose counting rule could be worked
out. `-u` and `-x` are counted and reported: aureport says 248 records
have an unset login uid where 245 carry `auid=4294967295`, and its
executable summary prints `(null)` for a record with no `exe=` and
counts two of the ten real executables 1 and 2 below the number of
records naming them. Neither is understood, so neither is asserted. The
other eight summaries, including the file and host ones, are not read at
all: aureport renders a file name with its own escaping, so comparing
those means a third rendering rule rather than a third derivation of the
same value.

**The field splitter is shared code on both sides of the comparison.**
`t/oracle.py` splits ausearch's output into fields with the same rule
auditp uses. What is compared is the value, which is ausearch's, but a
splitter wrong in the same way on both sides would agree with itself. Two
things bound it: the round trip, which reads only auditp's side and
notices a field that went missing, and the floor on distinct field names.
Neither is a substitute for a third splitter.

**The hex-decode table is checked against the oracle and not against a
second source.** Which `(record type, field)` pairs libaudit hex-decodes
is a table inside libaudit, and `t/escaped.py` recovers it by handing
ausearch a hex value in each pair and seeing what comes back. That cannot
catch auditp and ausearch being wrong together, only auditp drifting from
ausearch. The uapi headers say nothing about it.

**uids are resolved from the files, not through NSS.** auditp reads
`/etc/passwd` and `/etc/group` directly. ausearch calls `getpwuid`, so on
a machine with LDAP or systemd-homed in `nsswitch.conf` the two would
disagree about a uid for a reason that has nothing to do with parsing an
audit log. `nsswitch.conf` here is `files systemd` for both, so the
difference is live and not hypothetical: a uid belonging to a
DynamicUser service would resolve for ausearch and not for auditp. The
seven uids in the corpus resolve identically through `getent` and
through `/etc/passwd`, which is why the comparison agrees, and that is
a property of the corpus rather than of the code. Going through NSS
means cgo, which costs more than the limitation.

**One auditd, one kernel, one machine.** Everything here is auditd 4.0.2
on 7.2.11-200.fc44.x86_64. The signal 30 defect, the set of syscall
arguments ausearch interprets, and the exact spelling of several
interpreted values are all facts about this version.

**Only x86_64 and i386.** Those are the two architectures the corpus
contains. A third syscall table with no record to apply it to is a table
nothing checks, so there is not one.

**`subj=` is one opaque string.** No SELinux context parsing. ausearch
does the same, so the comparison agrees, which means the comparison says
nothing about it either.

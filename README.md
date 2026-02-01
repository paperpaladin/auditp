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

Measured on 20 October 2026, auditd 4.0.2, kernel 7.2.11-200.fc44.x86_64,
go 1.24.4. `make test` prints all of them.

| what | measured |
|---|---|
| assertions | 49 passed, 0 failed |
| fields compared against `ausearch -i`, whole corpus | 14,655 over 119 distinct names |
| of those, translated by auditp and identical | 10,409 |
| of those, passed through by auditp and identical | 4,227 |
| of those, refused by auditp where ausearch translated | 16 |
| of those, different | 0 |
| of those, ausearch's output is ambiguous | 3 |
| fields compared without `-i` | 14,655, 0 different, 0 missing on either side |
| the interleaved corpus, without `-i` | 99 fields over 38 names |
| `@time` compared again in a second timezone | 903 |
| decoded values against the bytes the generator encoded | 1,212 of 1,212 |
| `(type, field)` pairs that hex-decode, against ausearch | 82, identical |
| pairs the hex-decode probe put to ausearch | 524 asked, 524 answered |
| x86_64 syscall numbers agreed by two sources | 372 |
| i386 syscall numbers agreed by two sources | 450 |
| audit record types agreed by two sources | 73 |
| errno names agreed by two sources | 128 |
| signal names agreed by two sources | 30 |
| arch constants agreed by two sources | 10 |
| round trip: records written back out byte for byte | 903 of 903, and 9 of 9 |
| mutants (`make mutants`, not part of `make test`) | 58 applied, 57 killed, 1 survived, 0 did not build |

Refusals are counted apart from disagreements, in both directions, because
they need different work. A disagreement is a bug. A refusal is a feature
that is not written yet, and there are 16 of them left: 5 `saddr`, 1 TTY
`data` and 10 `a0` to `a3` on syscalls whose argument auditp does not
interpret. They are listed by name every run and the suite fails if the
count passes 40.

"Passed through and identical" is the third count and is the one to be
careful with. 4,227 fields agree because neither tool translates them, and
that is not evidence that auditp got anything right. It is reported
separately for exactly that reason, and the floor the suite asserts is on
the translated count only.

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

## What the corpus holds

903 records in 629 events, 12,465 fields, 371 subfields inside nested
`msg='...'` lists, 52 record types. Five files are committed under
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

The counts below are `t/corpus/counts.txt`, written by the generator, and
the suite asserts a floor on each one. A hex decoder over a corpus with
no hex-encoded value passes and proves nothing, and so does an i386
syscall table over a corpus with no i386 records.

```
records 903          lines 903            truth-rows 1213
bare 10541           quoted 1121          hex-encoded 100
nested-msg 50        prose-prefix 13      node-prefix 2
multi-record-events 125                   syscall-records 287
syscall-x86_64 65    syscall-i386 24      seccomp 89
path-items 89        path-mode 60         proctitle 125
event-openat 60      openat-flags 36      errno-exit 26
mmap-prot 40         socket-family 20     kill-signal 16
anom-abend 16        avc 12               user-cmd 10
sockaddr 5           execve 4             bpf 40
pam-record 30        netfilter-cfg 6      config-change 4
type-zoo 23          uid-value 8
edge-text 12         edge-cap 7           edge-hexshape 7
edge-proctitle 3     edge-node 2          edge-empty 2
edge-duplicate 1     edge-no-fields 1
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
result. Nothing patches the working tree. Three outcomes are kept apart:
KILLED, SURVIVED, and NOBUILD for a patch that did not apply or did not
compile, which is not a result about the suite at all and would be the
easiest number to inflate.

58 mutants, 57 killed, 1 survived, 0 failed to build. Measured 20
October 2026 against the suite as committed.

They are spread over the lexer (the quoted and single-quoted encodings,
the field-name rule, the value terminator, the prose prefix), the event
key (dropping the node, the serial or the milliseconds from it, and
merging a record only into the most recently seen event), the hex
decoder (nibble order, the odd trailing nibble, the rule for which bare
value is hex at all, each of the three escape cases), and every
interpreter: syscall names and their arch dependence, uid and gid
resolution, file modes, exit codes, capability masks, the seccomp mask,
`res`, signals, netfilter families, mmap flags, open flags, the
timestamp, the record type name, the nested `msg='...'` list, and each
of the eighteen syscall argument kinds.

The survivor is equivalent and stays in the catalogue so that the claim
can be checked. `field-name-needs-two-chars` starts the name scan one
byte later; the caller has already established that the first byte is a
letter, and a letter is a name byte, so the loop's first iteration could
only have advanced past it. The two versions compute the same length for
every input, one-character names included.

Two results the run produced that were worth more than the count.
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

## What does not work

**16 fields are refused.** `saddr` in a SOCKADDR record is carried as the
hex string; ausearch decodes the `sockaddr` and prints
`{ saddr_fam=inet laddr=10.0.0.1 lport=443 }`. TTY `data` is carried as
hex; ausearch renders it as text with control characters named,
`"ls -l /srv",<ret>`. The other ten are syscall arguments, refused under
nine names: `a0/bpf`, `a0/ptrace`, `a0/socketcall`, `a1/epoll_ctl`,
`a1/fcntl`, `a1/umount2`, `a2/clone`, `a3/mount` and `a3/sendto`. Each
prints the raw value and is counted, rather than printing a plausible
number, which would be a wrong answer rather than a gap. Across both
architecture tables there are 31 and 34 such pairs ausearch interprets
and auditp does not; the corpus reaches ten of them.

**The corpus is written by us.** Every number above is measured over 903
records that `t/gen.py` produced. ausearch reads them exactly as it reads
a kernel's own log, so the oracle is external, but the inputs are not: a
construct nobody thought of is a construct the corpus does not hold. The
deleted harvest is the thing that would have fixed this and it cannot be
published.

**The hostile corpus is generated and never read.** `t/corpus/hostile.log`
holds 20 malformed lines, the suite checks that it regenerates byte for
byte, and then nothing feeds it to auditp. There is no truncation sweep,
no byte-flip sweep, and no measurement of whether auditp refuses more or
less than ausearch refuses on bad input. An audit log is
attacker-influenced in any tool that ships one off a machine.

**`ausearch --format csv` and `aureport` are not used.** Both are second
views of the same events derived differently inside the same tool, so they
can disagree with `-i` about an event the field comparison agrees on.
Neither is wired up.

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

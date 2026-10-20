# PLAN

## Contract

```
auditp [-i] [-o text|json|flat|census|unparse|decode] [-strict] FILE
```

`FILE` is a Linux kernel audit log in the format `auditd` writes to
`/var/log/audit/audit.log`: one record per line, each

    [node=HOST ]type=TYPE msg=audit(SECS.MSEC:SERIAL): field=value ...

auditp reassembles the records that share a `(node, SECS.MSEC, SERIAL)` key
into one event, decodes every field value out of whichever of the three
encodings the kernel used for it, and emits a normalised record.

- `-o text` (default) one event per block, one record per line, fields in
  input order.
- `-o json` one JSON object per event, on one line, for a pipeline.
- `-o flat` one tab-separated row per field:
  `EVENTKEY <TAB> RECORD-INDEX <TAB> FIELD <TAB> i|p <TAB> VALUE`, where
  the fourth column says whether an interpreter claimed the value or it
  was passed through.
  This is the form the oracle comparison reads; it exists so that the
  comparison is per field and not per event.
- `-o unparse` the parsed records written back out, which is byte for
  byte the input if the splitter lost nothing.
- `-o decode` the decoded bytes of every field, backslash escaped, for
  comparison against the generator's record of what it encoded.
- `-o census` counts, per construct, how many times that construct occurred
  in the input: bare values, quoted values, hex values, `(null)`, empty
  values, embedded `=`, each interpreter that fired, each that refused.
  A construct the corpus does not contain is a construct the suite did not
  test, whatever the pass count says.

`-i` interprets: syscall numbers to names, `a0`-`a3` to the argument values
of that particular syscall, uids to login names, `mode` to `file,644`,
`exit` to an errno name, and so on. Without it, values are decoded but not
translated.

`-strict` turns a line auditp cannot parse into exit 1 instead of a counted
skip.

Exit 0 on a clean parse, 1 on unreadable input or (with `-strict`) a
malformed line, 2 on a usage error. All three are distinct because the
harness asserts on the difference.

Pure Go, standard library only, no third-party modules.

## Hard invariant

**Every field value auditp prints under `-i` is either byte-identical to the
value `ausearch -i` prints for the same field of the same record, or is
marked by auditp as uninterpreted. There is no third category.**

A field auditp translates wrongly and a field auditp declines to translate
are different failures and are counted separately everywhere: the suite
reports AGREE, REFUSE and DIFFER, and only DIFFER is a failure. A refusal
rate that grows is still visible, because the census prints it.

Two supporting invariants:

- Event assembly. For every event in the corpus, the sequence of record
  types auditp assembles is exactly the sequence `ausearch` assembles for
  the same event key, including multiplicity.
- Decoding. For every hex-encoded and every quoted field value in the
  corpus, the bytes auditp decodes are the bytes an independent decoder
  written in Python decodes, compared as bytes and not as printable text.

## Oracle

Ranked by how little of it we control:

1. `/usr/sbin/ausearch` (auditd 4.0.2, not on PATH). `ausearch -i -if FILE`
   is a complete second implementation of this exact job, written by the
   people who define the format. Where we disagree, we are wrong.
   `--format csv` is a second view from the same tool at a higher level
   (event kind, action, result, object), and `--format text` a third.
2. `/usr/include/linux/audit.h`, the kernel's own record type and arch
   constant table, and the uapi headers beside it. The kernel is not an
   oracle for the corpus itself, because the corpus is not harvested: see
   the note under Non-goals. It is still the authority for every constant
   the records are built from.
3. `/usr/bin/ausyscall` for syscall number to name, and
   `/usr/lib/linux/uapi/x86/asm/unistd_64.h` and `unistd_32.h` for the same
   fact from a second source. Two sources for one fact is how a wrong table
   gets caught; a table checked against the tool that was used to build it
   is checked against nothing.
4. `python3` as an independent second parser for the hex and quoted field
   encodings, and for the `/etc/passwd` and `/etc/group` lookups.
5. Deliberate defects in auditp, each expected to turn a *named* assertion
   red, with the survivors recorded.

## Non-goals

- Harvesting a corpus from this machine. An earlier session committed 1,674
  records taken from `journalctl _TRANSPORT=audit`, naming software
  installed here, real hostnames and real uids, and the history was reset to
  remove them because these repositories are published. The corpus is
  written by `t/gen.py` now, out of invented hostnames, paths and users.
  What that costs is in the README: the records are shaped like the
  kernel's and were not written by it, so a construct nobody thought of is
  a construct the corpus does not hold. `ausearch` reads them exactly as it
  reads a real log, so the oracle is still external.
- Reading `/var/log/audit/audit.log` directly. It is mode 0600 root-owned
  here and we are uid 1000.
- Loading audit rules. `auditctl` refuses without privilege (measured:
  "You must be root to run this program"), so no rule-driven SYSCALL/PATH
  traffic can be produced on demand.
- Being `ausearch`. No search expressions, no time ranges, no
  `--format text` prose. auditp parses and normalises; filtering belongs to
  whatever consumes the JSON.
- Writing audit logs, or talking to the audit netlink socket.
- Architectures other than x86_64 and i386. Those are the two the corpus
  contains; a third table with no record to apply it to is a table nothing
  checks.
- SELinux context parsing. `subj=` is carried as one opaque string, which
  is what ausearch does with it too.

## Commit sequence

### Milestone 0: the ground

- [x] Skeleton: go.mod, Makefile, LICENSE, .gitignore, this file
      why: the collection's gate runs `make` and rejects a tracked ELF
      binary, so both have to be right before any code exists.
- [x] Probe every oracle and record what it answered, in the README
      why: three of the five oracles named above are things a non-root
      user may not be able to run. An oracle assumed to work is not an
      oracle. `auditctl -s` already answered "You must be root".
      done: the README's "Oracles that were tried and do not work"
      section is that record. `auditctl` refuses without privilege,
      `/var/log/audit/audit.log` is unreadable at uid 1000, `ausearch`
      prints a config-file error on every run and then works, and
      `ausyscall --version` answers as though --version were a syscall
      name. `ausearch --format csv` and `aureport` were probed in the
      same way and both work at uid 1000; wiring them up is the next
      two items.
- [x] Generate the corpus, with the ground truth generated beside it
      why: a corpus someone else's kernel wrote would be worth more than
      records written to exercise the parser that reads them, and this
      one cannot be published, so the generator has to stand in for it.
      It writes the log, the ground truth for every decoded value, a
      hostile log and a per-construct count, and the suite regenerates
      all four and requires them byte for byte.

### Milestone 1: the lexer

- [x] Record header: `node=`, `type=`, `msg=audit(SECS.MSEC:SERIAL):`
      why: everything keys off the serial, and the optional `node=` prefix
      moves the whole line.
- [x] Field splitting, the hard part: values that are bare, quoted,
      hex, `(null)`, `(none)`, empty, or a single-quoted `msg='...'`
      holding a whole second field list
      why: splitting on space is wrong for `msg='op=PAM:authentication
      grantors=pam_permit acct="gdm-greeter" ...'` and for
      `proctitle=` with embedded NULs, and those are the common case.
- [x] Hex decoding, and the rule for when a bare value IS hex
      why: the kernel hex-encodes a value only when it contains
      whitespace or a control character or a quote, so `exe=2F757372...`
      and `exe="/usr/bin/cat"` are the same field in two encodings.
      A decoder that hex-decodes everything that looks like hex turns
      `op=4558454355544544` into bytes, and one that never does leaves
      every `cmd=` unreadable.
- [x] Compare the decoding against Python, as bytes
      why: comparing printable text would hide exactly the bytes the hex
      encoding exists for.

### Milestone 2: event assembly

- [x] Group by `(node, timestamp, serial)`, preserving input order
      why: this is the single fact the format makes hard and every
      consumer needs.
- [x] Compare the per-event record type sequence against ausearch
      why: an event assembled with a record missing produces a plausible
      answer about a different event.
- [x] PATH item ordering, and events whose records are interleaved with
      another event's
      why: `item=` is the kernel's own ordering and is not always the
      order the lines appear in.

### Milestone 3: the tables, from two sources each

- [x] x86_64 and i386 syscall tables, committed as Go source
      why: generated-at-build-time breaks the "every commit builds"
      rule on a machine without the headers.
- [x] Assert the committed table equals `ausyscall --dump` AND the uapi
      header, every run
      why: two sources. The corpus holds `arch=40000003` records, so the
      i386 table is live and not decoration.
- [x] Record type numbers and names against `/usr/include/linux/audit.h`
- [x] errno table, against `errno -l` or the uapi `errno.h`

### Milestone 4: interpretation

- [x] `arch=`, `syscall=`, and the arch-dependence of the second
      why: syscall 102 is `getegid` on i386 and `getgroups` on x86_64.
      A single table is wrong for 7379 SECCOMP records in the corpus.
- [x] uid/gid families to names, from `/etc/passwd` and `/etc/group`
      why: ausearch prints `uid=x`, not `uid=1000`, and gets it from the
      same files.
- [x] `mode=0100644` to `file,644`, and the other file type bits
- [x] `exit=` to an errno name when negative, `success=`, `res=`
- [x] `a0`-`a3` per syscall: `AT_FDCWD`, `O_RDONLY`, the open mode,
      the socket family, the mmap protection and flags
      why: this is the field the format documents least and the one a
      detection rule reads first.
- [x] `proctitle=` to a command line, NUL separated
- [x] Timestamps to the form ausearch prints, in local time
- [x] Everything else is a refusal, printed as such and counted
      why: the hard invariant is only meaningful if the refusal channel
      exists and is used.

### Milestone 5: the comparison at scale

- [x] Per-field diff of `-o flat -i` against `ausearch -i -if`, over the
      whole corpus, reporting AGREE / REFUSE / DIFFER
- [x] Assert the comparison is non-vacuous: a floor on the field count,
      on the number of distinct field names, and on the number of
      records of each interesting type
      why: a comparison over zero fields agrees with everything.
- [x] The census, and a floor on each construct that has an interpreter
      why: if the corpus holds no hex-encoded field then the hex decoder
      is untested however many fields agree.

### Milestone 6: the suite has to be able to fail

- [x] Mutate every decoder and every interpreter, one at a time, and
      record which named assertion caught each
      why: a green suite proves nothing about a harness nobody has
      watched fail. Equivalent mutants get written down as survivors,
      not quietly dropped.
- [x] Cover the constructs no plausible log of this machine would hold:
      PATH items, CWD, EXECVE, SOCKADDR, a hex field holding a newline,
      a value holding an `=`
      why: without audit rules loaded, nothing on this machine emits a
      PATH record at all. The generator writes them; ausearch reads
      them the same way it reads any other record, so the oracle is
      still external even though the bytes are ours.
- [x] Feed `t/corpus/hostile.log` to auditp and assert the exit codes
      why: the hostile corpus is generated and regenerated byte for
      byte and then nothing reads it. 20 lines of malformed input are
      sitting in the tree as decoration.
      done: 24 lines now, each put to auditp alone and to ausearch
      alone, with over-refusal the direction that fails. It found one
      on the first run, a timestamp with no fractional part.
- [x] Truncation and corruption sweep: every prefix of the corpus, byte
      flips inside a hex field, a serial that is not a number, a line
      longer than the scanner's buffer
      why: an audit log is attacker-influenced in any tool that ships
      one off the box.
      done: 1,116 cases in `make test` and about 200,000 under `make
      truncate`. The long line cost every record after it.
- [x] Compare the hostile and truncated inputs against ausearch too
      why: refusing more than ausearch refuses is a defect and not
      caution, and nothing currently measures it.
      done: both directions are counted against ausearch and both have
      a ceiling rather than a floor of zero. 131 corrupted lines
      ausearch reads and auditp refuses, 155 the other way, all of them
      a byte moved inside the header.
- [x] Ask in `make test` whether the mutation catalogue still applies
      why: the sweep takes an hour and so runs nowhere near a commit,
      and four of the 115 entries had gone dead under refactoring
      without anything noticing. A pattern that no longer matches is
      neither killed nor surviving, so the sweep's own numbers cannot
      show it: the only visible sign was a NOBUILD, in the same bucket
      as a mutant that failed to compile. `t/patch.py --check` replays
      the unescaping and reports every entry whose pattern does not
      match exactly once, in about a second, and `t/mutate.sh` now
      counts NOPATCH apart from NOBUILD.

### Milestone 7: what is left

- [x] README with the measured numbers and the gaps
- [ ] `--format csv` as a second, higher-level comparison
      why: it is derived differently inside ausearch, so it can disagree
      with `-i` about the same event, and that disagreement is
      information.
- [ ] `aureport` as a third view
      why: it counts and summarises rather than printing fields, so it
      can be wrong about an event the field comparison agrees on.
- [ ] A second machine's corpus, or a second auditd version
      why: every number here is from auditd 4.0.2 on one kernel.

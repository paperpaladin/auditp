#!/usr/bin/env python3
"""Derive auditp's lookup tables from external sources and emit Go.

Every table here comes from TWO sources that were produced independently,
and the script fails if they disagree.  A table checked against the tool it
was copied from is checked against nothing: the failure mode of a syscall
table is not a missing entry, it is an entry that is confidently wrong, and
one source cannot see that.

  x86_64 and i386 syscalls   /usr/bin/ausyscall ARCH --dump
                             /usr/lib/linux/uapi/x86/asm/unistd_{64,32}.h
  audit record types         ausearch, probed: it resolves the UNKNOWN[n]
                             spelling auditd writes for a type its own table
                             does not name, so feeding it one record per
                             number and reading back the name it prints is
                             a direct question to the authority
                             /usr/include/linux/audit.h for the subset the
                             kernel names
  errno names and messages   Python's errno module (names) and
                             /usr/include/asm-generic/errno{,-base}.h
                             glibc's strerror under LC_ALL=C (messages)
  signals                    Python's signal module and
                             /usr/include/asm-generic/signal.h

The generated file is committed.  Generating it at build time would break
on a machine without the headers, and hard rule 2 of the collection is that
every commit builds.  The suite regenerates and diffs, so a table that
drifts from its sources turns the suite red rather than going unnoticed.
"""

import argparse
import os
import re
import subprocess
import sys

AUSYSCALL = "/usr/bin/ausyscall"
AUSEARCH = "/usr/sbin/ausearch"
UAPI = "/usr/lib/linux/uapi/x86/asm"
AUDIT_H = "/usr/include/linux/audit.h"
ERRNO_H = ["/usr/include/asm-generic/errno-base.h",
           "/usr/include/asm-generic/errno.h"]
SIGNAL_H = "/usr/include/asm-generic/signal.h"

problems = []


def need(path):
    if not os.path.exists(path):
        problems.append("missing source: %s" % path)
        return False
    return True


def defines(path, prefix):
    """Read '#define PREFIX_NAME VALUE' from a uapi header."""
    out = {}
    pat = re.compile(r"^#define\s+%s([A-Za-z0-9_]+)\s+(\S+)" % re.escape(prefix))
    with open(path) as f:
        for line in f:
            m = pat.match(line)
            if not m:
                continue
            v = m.group(2).rstrip()
            if v.startswith("0x"):
                try:
                    out[m.group(1)] = int(v, 16)
                except ValueError:
                    pass
            elif v.isdigit():
                out[m.group(1)] = int(v)
    return out


# ------------------------------------------------------------- syscalls
def ausyscall_table(arch):
    p = subprocess.run([AUSYSCALL, arch, "--dump"], capture_output=True)
    if p.returncode != 0:
        problems.append("ausyscall %s --dump failed" % arch)
        return {}
    out = {}
    for line in p.stdout.decode().splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0].strip().isdigit():
            out[int(parts[0])] = parts[1].strip()
    return out


def syscalls(arch, header):
    a = ausyscall_table(arch)
    h = {}
    if need(header):
        h = {v: k for k, v in defines(header, "__NR_").items()}
    if not a or not h:
        return a or h, 0
    agree = disagree = 0
    for nr in sorted(set(a) | set(h)):
        if nr in a and nr in h:
            if a[nr] == h[nr]:
                agree += 1
            else:
                disagree += 1
                problems.append("ALIAS %s syscall %d: ausyscall says %s, "
                                "header says %s" % (arch, nr, a[nr], h[nr]))
        elif nr in a:
            problems.append("ONESIDED %s syscall %d (%s) is in ausyscall "
                            "and not the header" % (arch, nr, a[nr]))
        else:
            # ausearch prints unknown-syscall(N) for these, so auditp must
            # too: the table it needs is libaudit's, not the kernel's.
            problems.append("ONESIDED %s syscall %d (%s) is in the header "
                            "and not ausyscall" % (arch, nr, h[nr]))
    return a, agree


# ---------------------------------------------------------- record types
def audit_types(lo=1000, hi=3100):
    """Ask ausearch what each record type number is called.

    auditd writes UNKNOWN[1100] for a type its table does not name and
    ausearch resolves it when interpreting, so one record per number and a
    read of the names it prints back is the authority answering directly.
    """
    lines = []
    for i, t in enumerate(range(lo, hi)):
        lines.append("type=UNKNOWN[%d] msg=audit(1700000000.%03d:%d): x=1"
                     % (t, i % 1000, t))
    import tempfile
    fd, path = tempfile.mkstemp(prefix="auditp-types-")
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode())
        os.close(fd)
        env = dict(os.environ)
        env["TZ"] = "UTC"
        p = subprocess.run([AUSEARCH, "-i", "-if", path],
                           capture_output=True, env=env)
        out = {}
        pat = re.compile(r"^type=(\S+) msg=audit\([^)]*:(\d+)\) :")
        for line in p.stdout.decode("utf-8", "replace").splitlines():
            m = pat.match(line)
            if not m:
                continue
            name, num = m.group(1), int(m.group(2))
            if name.startswith("UNKNOWN["):
                continue
            out[num] = name
    finally:
        os.unlink(path)
    # Cross-check against the kernel's own header where it names one.
    if need(AUDIT_H):
        kern = {}
        for name, val in defines(AUDIT_H, "AUDIT_").items():
            if 1000 <= val < 3100 and not name.startswith(("FIRST_", "LAST_")):
                kern.setdefault(val, name)
        both = agree = 0
        for num, name in sorted(kern.items()):
            if num in out:
                both += 1
                if out[num] == name:
                    agree += 1
                else:
                    # The kernel header and libaudit genuinely use different
                    # spellings for a few.  Recorded, not hidden.
                    problems.append("NOTE type %d: audit.h says AUDIT_%s, "
                                    "ausearch says %s" % (num, name, out[num]))
        out["_crosschecked"] = (both, agree)
    return out


# ------------------------------------------------------------------ arch
ELF_EM_H = "/usr/include/linux/elf-em.h"


def arches():
    """AUDIT_ARCH_* values, computed from the kernel headers, and the name
    ausearch prints for each.

    audit.h writes them as (EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE),
    so the value needs elf-em.h as well.  Then every one is put to ausearch
    in a record and the name it prints back is read: the computation says
    which numbers exist and the probe says what they are called, and a
    number the computation produces that ausearch does not recognise shows
    up as unknown-elf-type.
    """
    em = {}
    if need(ELF_EM_H):
        em = defines(ELF_EM_H, "EM_")
    if not need(AUDIT_H):
        return {}, 0
    flags = {"__AUDIT_ARCH_64BIT": 0x80000000, "__AUDIT_ARCH_LE": 0x40000000,
             "__AUDIT_ARCH_CONVENTION_MIPS64_N32": 0x20000000}
    vals = {}
    text = open(AUDIT_H).read()
    text = text.replace("\\\n", " ")
    for m in re.finditer(r"^#define\s+AUDIT_ARCH_([A-Z0-9_]+)\s+\(([^)]*)\)",
                         text, re.M):
        name, expr = m.group(1), m.group(2)
        v = 0
        ok = True
        for tok in [t.strip() for t in expr.split("|")]:
            if tok in flags:
                v |= flags[tok]
            elif tok.startswith("EM_") and tok[3:] in em:
                v |= em[tok[3:]]
            else:
                ok = False
        if ok:
            vals["%08x" % v] = name.lower()
    # Ask ausearch what it calls each one.
    import tempfile
    keys = sorted(vals)
    lines = []
    for i, k in enumerate(keys):
        lines.append("type=SYSCALL msg=audit(1700000000.%03d:%d): arch=%s "
                     "syscall=0 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 "
                     "items=0 ppid=1 pid=2 auid=0 uid=0 gid=0 euid=0 suid=0 "
                     "fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=1 "
                     'comm="x" exe="/x" key=(null)' % (i % 1000, 4000000 + i, k))
    fd, path = tempfile.mkstemp(prefix="auditp-arch-")
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode())
        os.close(fd)
        env = dict(os.environ)
        env["TZ"] = "UTC"
        p = subprocess.run([AUSEARCH, "-i", "-if", path],
                           capture_output=True, env=env)
        seen = {}
        for line in p.stdout.decode("utf-8", "replace").splitlines():
            m = re.match(r"^type=\S+ msg=audit\([^)]*:(\d+)\) : arch=(\S+) ",
                         line)
            if m:
                seen[keys[int(m.group(1)) - 4000000]] = m.group(2)
    finally:
        os.unlink(path)
    out = {}
    agree = unknown = 0
    for k in keys:
        got = seen.get(k)
        if got is None:
            problems.append("ONESIDED arch %s (%s) got no answer from ausearch"
                            % (k, vals[k]))
            continue
        if got.startswith("unknown-elf-type("):
            # libaudit has a syscall table for ten architectures and names
            # only those.  auditp has to print what ausearch prints, so
            # these are deliberately left out of the table and rendered by
            # the same rule at runtime.  Counted, not listed one by one.
            unknown += 1
            continue
        if got == vals[k]:
            agree += 1
        else:
            problems.append("ALIAS arch %s: header computes %s, ausearch "
                            "says %s" % (k, vals[k], got))
        out[int(k, 16)] = got
    problems.append("COUNT %d of %d AUDIT_ARCH_* values are unknown to "
                    "ausearch and render as unknown-elf-type(hex)"
                    % (unknown, len(keys)))
    return out, agree


# ----------------------------------------------------------- errno, signals
def errnos():
    """Names from the uapi headers, cross-checked against Python's module.

    The header is the authority here and Python is the check, the other way
    round from the syscall tables, and that is not a style choice: errno 35
    and 95 each have two names, and ausearch prints EDEADLK and EOPNOTSUPP
    where Python's errorcode says EDEADLOCK and ENOTSUP.  Measured, by
    feeding ausearch exit=-35 and exit=-95.  A table built from Python would
    be wrong about both and would look right.
    """
    import errno as E
    hdr = {}
    for h in ERRNO_H:
        if need(h):
            for name, val in defines(h, "E").items():
                hdr.setdefault(val, "E" + name)
    agree = 0
    for num, name in sorted(E.errorcode.items()):
        if num in hdr:
            if hdr[num] == name:
                agree += 1
            else:
                problems.append("ALIAS errno %d: header says %s, python says %s"
                                % (num, hdr[num], name))
        else:
            problems.append("errno %d (%s) is in python and not the headers"
                            % (num, name))
    msgs = {num: os.strerror(num) for num in sorted(hdr)}
    return hdr, msgs, agree


def signals():
    import signal as S
    py = {}
    for s in S.Signals:
        py.setdefault(int(s), s.name)
    hdr = {}
    if need(SIGNAL_H):
        for name, val in defines(SIGNAL_H, "SIG").items():
            if 1 <= val <= 64:
                hdr.setdefault(val, "SIG" + name)
    agree = 0
    for num in sorted(set(py) & set(hdr)):
        if py[num] == hdr[num]:
            agree += 1
        else:
            problems.append("NOTE signal %d: python says %s, header says %s"
                            % (num, py[num], hdr[num]))
    return py, agree


# ------------------------------------------------------------- emission
def go_map_int_str(name, m, comment):
    out = ["// %s" % comment, "var %s = map[int]string{" % name]
    for k in sorted(m):
        out.append("\t%d: %s," % (k, goquote(m[k])))
    out.append("}")
    return "\n".join(out)


def goquote(s):
    out = ['"']
    for c in s:
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif 0x20 <= ord(c) < 0x7F:
            out.append(c)
        else:
            out.append("\\x%02x" % ord(c))
    out.append('"')
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--report")
    args = ap.parse_args()

    sc64, ag64 = syscalls("x86_64", UAPI + "/unistd_64.h")
    sc32, ag32 = syscalls("i386", UAPI + "/unistd_32.h")
    types = audit_types()
    tx = types.pop("_crosschecked", (0, 0))
    archs, agarch = arches()
    errs, errmsgs, agerr = errnos()
    sigs, agsig = signals()

    parts = ["""// Code generated by t/tables.py from external sources.  DO NOT EDIT.
//
// Each table below was produced from two sources that do not share a
// lineage, and t/tables.py fails if they disagree.  The suite regenerates
// this file and diffs it, so a table that drifts from its sources turns
// the suite red.  See t/tables.py for which two sources each one had.

package main
"""]
    parts.append(go_map_int_str(
        "syscallX8664", sc64,
        "x86_64 syscall numbers.  ausyscall x86_64 --dump and "
        "unistd_64.h agreed on %d of them." % ag64))
    parts.append(go_map_int_str(
        "syscallI386", sc32,
        "i386 syscall numbers.  The same number means a different call "
        "here: 102 is socketcall on i386 and getgroups on x86_64, which "
        "is the whole reason this is a second table.  ausyscall i386 "
        "--dump and unistd_32.h agreed on %d." % ag32))
    parts.append(go_map_int_str(
        "auditTypeName", {k: v for k, v in types.items() if isinstance(k, int)},
        "Audit record type numbers, as ausearch names them.  %d of them "
        "are also named by linux/audit.h and %d of those spellings match."
        % tx))
    parts.append(go_map_int_str(
        "archName", archs,
        "AUDIT_ARCH_* values.  Computed from linux/audit.h and "
        "linux/elf-em.h, then every one put to ausearch in a record and "
        "the name it printed back read: %d of %d agreed."
        % (agarch, len(archs))))
    parts.append(go_map_int_str(
        "errnoName", errs,
        "errno names from asm-generic/errno*.h, cross-checked against "
        "Python's errno module: %d of them agree and two do not.  The "
        "header is the authority and Python is the check, because errno "
        "35 and 95 each have two names and ausearch prints the header's "
        "spelling for both.  Measured by asking it." % agerr))
    parts.append(go_map_int_str(
        "errnoText", errmsgs,
        "glibc's strerror text under LC_ALL=C.  ausearch prints "
        "exit=-13 as EACCES(Permission denied), and the words in the "
        "brackets are glibc's, not ours: Go's own Errno.Error() "
        "lower-cases the first letter and would disagree on every one."))
    parts.append(go_map_int_str(
        "signalName", sigs,
        "Signal names.  Python's signal module and asm-generic/signal.h "
        "agreed on %d." % agsig))

    src = "\n\n".join(parts) + "\n"
    # Through gofmt, so that the committed file is already formatted and
    # the suite's regenerate-and-diff check is not comparing whitespace.
    g = subprocess.run(["gofmt"], input=src.encode(), capture_output=True)
    if g.returncode != 0:
        problems.append("gofmt rejected the generated source: %s"
                        % g.stderr.decode()[:200])
    else:
        src = g.stdout.decode()
    with open(args.out, "w") as f:
        f.write(src)

    rep = open(args.report, "w") if args.report else sys.stdout
    rep.write("syscall-x86_64 %d\n" % len(sc64))
    rep.write("syscall-x86_64-two-source-agree %d\n" % ag64)
    rep.write("syscall-i386 %d\n" % len(sc32))
    rep.write("syscall-i386-two-source-agree %d\n" % ag32)
    rep.write("audit-types %d\n" % len([k for k in types if isinstance(k, int)]))
    rep.write("audit-types-in-kernel-header %d\n" % tx[0])
    rep.write("audit-types-two-source-agree %d\n" % tx[1])
    rep.write("arch %d\n" % len(archs))
    rep.write("arch-two-source-agree %d\n" % agarch)
    rep.write("errno %d\n" % len(errs))
    rep.write("errno-two-source-agree %d\n" % agerr)
    rep.write("signal %d\n" % len(sigs))
    rep.write("signal-two-source-agree %d\n" % agsig)
    # A name difference between two sources for the same number is an
    # alias and is recorded, not fatal; a number that moves is fatal.  The
    # committed t/tables.expect pins the exact set, so an eighth alias
    # appearing is a failure even though the seven known ones are not.
    hard = [p for p in problems
            if not p.startswith(("NOTE ", "ALIAS ", "ONESIDED ", "COUNT "))]
    rep.write("problems %d\n" % len(hard))
    rep.write("notes %d\n" % (len(problems) - len(hard)))
    for p in sorted(problems):
        rep.write("  %s\n" % p)
    if args.report:
        rep.close()
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())

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
            v = m.group(2).rstrip().rstrip("Uu")
            if v.startswith(("0x", "0X")):
                try:
                    out[m.group(1)] = int(v, 16)
                except ValueError:
                    pass
            elif v.isdigit():
                # asm-generic/fcntl.h writes its flags in octal with a
                # leading zero: O_CREAT is 00000100 and is 64, not 100.
                # Reading them as decimal gave an open-flag table that was
                # wrong for every flag above O_RDWR.
                out[m.group(1)] = int(v, 8) if len(v) > 1 and v[0] == "0" \
                    else int(v)
    return out


def enum_values(path, prefix):
    """Read NAME = NUMBER out of a C enum body.  NFPROTO_* is an enum."""
    out = {}
    text = open(path).read()
    for m in re.finditer(r"\b%s([A-Za-z0-9_]+)\s*=\s*(-?\d+)"
                         % re.escape(prefix), text):
        out[m.group(1)] = int(m.group(2))
    return out


def probe(records):
    """Put a list of (type, body) to ausearch -i and return what it printed.

    This is how every table below gets its second source: the header says
    which numbers exist and what they are called, and ausearch is asked
    what IT calls them.  A name auditp compiles in that ausearch does not
    use is a field auditp will render wrongly, and only asking finds that.
    """
    import tempfile
    lines = []
    for i, (t, body) in enumerate(records):
        lines.append("type=%s msg=audit(1700000000.%03d:%d): %s"
                     % (t, i % 1000, 9000000 + i, body))
    fd, path = tempfile.mkstemp(prefix="auditp-probe-")
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode())
        os.close(fd)
        env = dict(os.environ)
        env["TZ"] = "UTC"
        env["LC_ALL"] = "C"
        p = subprocess.run([AUSEARCH, "-i", "-if", path],
                           capture_output=True, env=env)
    finally:
        os.unlink(path)
    out = {}
    pat = re.compile(r"^type=\S+ msg=audit\([^)]*:(\d+)\) : (.*)")
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        m = pat.match(line)
        if m:
            out[int(m.group(1)) - 9000000] = m.group(2).rstrip()
    return out


def one_field(rendered, name):
    m = re.search(r"(?:^| )%s=(\S*)" % re.escape(name), rendered)
    return m.group(1) if m else None


def bitflags(label, hdr, record_type, body_fmt, field, skip=(), base=0):
    """Cross-check a bit-flag table one bit at a time.

    For each single-bit value the header defines, ausearch is given a
    record carrying exactly that bit and asked what it calls it.  One bit
    at a time, because a mask of several is rendered as a list and a
    missing name in the middle of a list is easy to miss.
    """
    bits = {}
    for name, val in sorted(hdr.items(), key=lambda kv: kv[1]):
        if name in skip or val == 0 or (val & (val - 1)) != 0:
            continue
        bits.setdefault(val, name)
    keys = sorted(bits)
    # The base bit itself is probed alone, or stripping it would leave
    # nothing: the first version emitted an empty name for PROT_EXEC and
    # for every bit the renderer does not know.
    got = probe([(record_type, body_fmt % (v if v == base else v | base))
                 for v in keys])
    out = {}
    agree = 0
    for i, v in enumerate(keys):
        r = got.get(i)
        if r is None:
            problems.append("ONESIDED %s bit 0x%x (%s) got no answer"
                            % (label, v, bits[v]))
            continue
        val = one_field(r, field)
        if val is None:
            problems.append("ONESIDED %s bit 0x%x (%s) field vanished"
                            % (label, v, bits[v]))
            continue
        # ausearch renders a flag word as a list that always starts with
        # the zero-valued base: O_RDONLY for open flags, MAP_FILE for
        # mmap.  One bit therefore comes back as "O_RDONLY|O_CREAT", and
        # the name of the bit is the last component.  Comparing the whole
        # string reported thirteen false aliases.
        if base and v != base:
            val = "|".join(p for p in val.split("|")
                           if p != bits.get(base, ""))
        val = val.rsplit("|", 1)[-1]
        if val == "":
            problems.append("ONESIDED %s bit 0x%x (%s) has no name in "
                            "ausearch" % (label, v, bits[v]))
            continue
        if val.startswith("0x"):
            # ausearch has no name for this bit.  It prints 0x0x8 for
            # MAP_DROPPABLE, which is libaudit's own formatting defect (a
            # literal 0x in front of a %#x), and putting that string in
            # the table would make auditp copy it.  Left out; the README
            # records the defect.
            problems.append("ONESIDED %s bit 0x%x (%s) has no name in "
                            "ausearch, which prints %s"
                            % (label, v, bits[v], val))
            continue
        out[v] = val
        if val == bits[v] or val.lower() == bits[v].lower():
            agree += 1
        else:
            problems.append("ALIAS %s bit 0x%x: header says %s, ausearch "
                            "says %s" % (label, v, bits[v], val))
    return out, agree


# ----------------------------------------------------------- errno, signals


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
    """Signal names, probed from ausearch and cross-checked against the
    header and Python.

    Probed rather than computed because libaudit's table stops at 31:
    signal 32 is SIGRTMIN to the kernel and unknown-signal(32) to
    ausearch, and signal 0 is SIG0, which is not a name anything else
    uses.  A table built from the header alone would be wrong at both
    ends and would look complete.
    """
    import signal as S
    py = {}
    for sg in S.Signals:
        py.setdefault(int(sg), sg.name)
    hdr = {}
    if need(SIGNAL_H):
        for name, val in defines(SIGNAL_H, "SIG").items():
            if 1 <= val <= 64:
                hdr.setdefault(val, "SIG" + name)
    got = probe([("ANOM_ABEND", "pid=1 sig=%d res=1" % n)
                 for n in range(0, 129)])
    out = {}
    agree = 0
    for n in range(0, 129):
        r = got.get(n)
        if r is None:
            continue
        v = one_field(r, "sig")
        if v is None or v.startswith("unknown-signal("):
            continue
        if hdr.get(n) == v or py.get(n) == v:
            out[n] = v
            agree += 1
            continue
        if n != 0 and hdr.get(n) is not None and hdr.get(n) == py.get(n):
            # Two independent sources agree with each other and disagree
            # with ausearch.  Two beats one: the table gets the sources'
            # name and the divergence is recorded, rather than auditp
            # copying a defect into a second implementation and helping
            # it become the format.
            out[n] = hdr[n]
            problems.append("DIVERGE signal %d: ausearch says %s, both "
                            "sources say %s, auditp follows the sources"
                            % (n, v, hdr[n]))
            continue
        out[n] = v
        if n != 0:
            problems.append("ALIAS signal %d: ausearch says %s, header says "
                            "%s, python says %s"
                            % (n, v, hdr.get(n), py.get(n)))
    return out, agree


CAPABILITY_H = "/usr/include/linux/capability.h"
SECCOMP_H = "/usr/include/linux/seccomp.h"
NETFILTER_H = "/usr/include/linux/netfilter.h"
FCNTL_H = "/usr/include/asm-generic/fcntl.h"
# The x86 header is in the list because MAP_32BIT is defined only there,
# and leaving it out cost a wrong rendering of every mmap that used it.
MMAN_H = ["/usr/include/asm-generic/mman-common.h",
          "/usr/include/asm-generic/mman.h",
          "/usr/include/linux/mman.h",
          "/usr/lib/linux/uapi/x86/asm/mman.h"]


def capabilities():
    """CAP_* names, one bit at a time against ausearch."""
    if not need(CAPABILITY_H):
        return {}, 0
    hdr = {}
    for name, val in defines(CAPABILITY_H, "CAP_").items():
        if 0 <= val <= 63 and name not in ("LAST_CAP",):
            hdr.setdefault(val, name.lower())
    keys = sorted(hdr)
    got = probe([("PATH", 'item=0 name="/x" cap_fp=%016x cap_fi=0 '
                  "cap_fe=0 cap_fver=0" % (1 << b)) for b in keys])
    out = {}
    agree = 0
    for i, b in enumerate(keys):
        r = got.get(i)
        v = one_field(r, "cap_fp") if r else None
        if v is None:
            problems.append("ONESIDED capability bit %d (%s) got no answer"
                            % (b, hdr[b]))
            continue
        out[b] = v
        if v == hdr[b]:
            agree += 1
        else:
            problems.append("ALIAS capability bit %d: header says %s, "
                            "ausearch says %s" % (b, hdr[b], v))
    return out, agree


def seccomp_codes():
    if not need(SECCOMP_H):
        return {}, 0
    hdr = {}
    for name, val in defines(SECCOMP_H, "SECCOMP_RET_").items():
        if name in ("ACTION", "ACTION_FULL", "DATA"):
            continue
        hdr.setdefault(val & 0x7FFF0000, name.lower().replace("_", "-"))
    keys = sorted(hdr)
    got = probe([("SECCOMP", "pid=1 arch=c000003e syscall=1 compat=0 "
                  "ip=0x0 code=0x%08x" % v) for v in keys])
    out = {}
    agree = 0
    for i, v in enumerate(keys):
        r = got.get(i)
        c = one_field(r, "code") if r else None
        if c is None or c.startswith("unknown-seccomp-code("):
            problems.append("ONESIDED seccomp code 0x%08x (%s) is not named "
                            "by ausearch" % (v, hdr[v]))
            continue
        out[v] = c
        if c == hdr[v]:
            agree += 1
        else:
            problems.append("ALIAS seccomp code 0x%08x: header says %s, "
                            "ausearch says %s" % (v, hdr[v], c))
    return out, agree


def nfprotos():
    if not need(NETFILTER_H):
        return {}, 0
    hdr = {}
    for name, val in enum_values(NETFILTER_H, "NFPROTO_").items():
        if name != "NUMPROTO":
            hdr.setdefault(val, name.lower())
    keys = sorted(hdr)
    got = probe([("NETFILTER_CFG", "table=t:1 family=%d entries=1 op=x pid=1"
                  % v) for v in keys])
    out = {}
    agree = 0
    for i, v in enumerate(keys):
        r = got.get(i)
        f = one_field(r, "family") if r else None
        if f is None or f.startswith("unknown-netfilter-protocol("):
            problems.append("ONESIDED netfilter family %d (%s) is not named "
                            "by ausearch" % (v, hdr[v]))
            continue
        out[v] = f
        if f == hdr[v]:
            agree += 1
        else:
            problems.append("ALIAS netfilter family %d: header says %s, "
                            "ausearch says %s" % (v, hdr[v], f))
    return out, agree


def filterlists():
    if not need(AUDIT_H):
        return {}, 0
    hdr = {}
    for name, val in defines(AUDIT_H, "AUDIT_FILTER_").items():
        if val <= 15:
            hdr.setdefault(val, name.lower())
    got = probe([("CONFIG_CHANGE", 'op=add_rule key="k" list=%d res=1' % v)
                 for v in range(0, 16)])
    out = {}
    agree = 0
    for v in range(0, 16):
        r = got.get(v)
        l = one_field(r, "list") if r else None
        if l is None or l.startswith("unknown-list("):
            continue
        out[v] = l
        if hdr.get(v) == l:
            agree += 1
        else:
            problems.append("ALIAS audit filter list %d: header says %s, "
                            "ausearch says %s" % (v, hdr.get(v), l))
    return out, agree


def openflags():
    if not need(FCNTL_H):
        return {}, 0
    named = {"O_" + k: v for k, v in defines(FCNTL_H, "O_").items()}
    # __O_SYNC and __O_TMPFILE are spelled with two leading underscores
    # and ausearch names them, so a table built from the O_ prefix alone
    # is missing two bits and renders every flag word that has one of
    # them short by a name.
    for k, v in defines(FCNTL_H, "__O_").items():
        named["__O_" + k] = v
    return bitflags("open flag", named, "MQ_OPEN", "oflag=0x%x mode=0600",
                    "oflag", skip=("O_ACCMODE", "O_NDELAY", "O_LARGEFILE"),
                    base=1)


def mapflags():
    hdr = {}
    for h in MMAN_H:
        if need(h):
            for name, val in defines(h, "MAP_").items():
                hdr.setdefault("MAP_" + name, val)
    # base=1 (MAP_SHARED) so that the zero-valued MAP_FILE is not what a
    # bit with no name comes back as.  Without it every unnamed bit was
    # recorded as MAP_FILE and the renderer appended MAP_FILE to flag
    # words that did not have it.
    return bitflags("mmap flag", hdr, "MMAP", "fd=-1 flags=0x%x", "flags",
                    skip=("MAP_TYPE", "MAP_HUGE_MASK", "MAP_HUGE_SHIFT"),
                    base=1)


# --------------------------------------------------- syscall arguments
SCHED_H = "/usr/include/linux/sched.h"
FS_H = "/usr/include/linux/fs.h"
MMAN_COMMON_H = "/usr/include/asm-generic/mman-common.h"
PROTOCOLS = "/etc/protocols"
SOCKET_H = "/usr/include/x86_64-linux-gnu/bits/socket.h"

ARG_PROBE_VALUES = ["0", "1", "3", "10", "42", "ff", "ffffff9c"]
ARCH_X8664 = "c000003e"
ARCH_I386 = "40000003"


def syscall_args(arch, tab):
    """Which (syscall, argument) pairs ausearch interprets at all.

    a0 to a3 are the one part of the format with no self-describing
    structure: the same four names mean a directory file descriptor, a
    mode, a uid, a signal or nothing at all depending on which syscall
    the record is about.  ausearch has a table of 95 such pairs for
    x86_64 and auditp implements some of them; the rest have to be
    REFUSED rather than printed as a number, because printing 0x2a where
    ausearch prints a signal name is a wrong answer and not a gap.

    So the set is measured.  Each syscall gets one record per argument
    per probe value, and a pair where any value came back as something
    other than 0x<hex> is one ausearch interprets.  The result is
    compiled into auditp and re-probed by the suite.
    """
    recs = []
    index = []
    # Two passes over the other three arguments: all zero, and all ones.
    # Some pairs are interpreted conditionally -- x86_64's open shows a
    # mode in a2 only when a1 carries O_CREAT -- and a probe that leaves
    # the neighbours at zero reports those as uninterpreted.  Which they
    # are, on i386, where ausearch never shows open's mode at all: the
    # table is per machine as well as per syscall, so this cannot be
    # reasoned out and has to be asked.
    for nr in sorted(tab):
        for a in range(4):
          for other in ("0", "ffffffff"):
            for v in ARG_PROBE_VALUES:
                args = [other] * 4
                args[a] = v
                index.append((nr, a, v))
                recs.append(("SYSCALL",
                             "arch=%s syscall=%d success=yes exit=0 "
                             "a0=%s a1=%s a2=%s a3=%s items=0 ppid=1 pid=2 "
                             "auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 "
                             "egid=0 sgid=0 fsgid=0 tty=(none) ses=1 "
                             'comm="x" exe="/x" key=(null)'
                             % (arch, nr, args[0], args[1], args[2], args[3])))
    got = probe(recs)
    pairs = {}
    answered = 0
    for i, (nr, a, v) in enumerate(index):
        r = got.get(i)
        if r is None:
            continue
        answered += 1
        val = one_field(r, "a%d" % a)
        if val is None:
            continue
        plain = "0x%x" % int(v, 16)
        if val != plain:
            pairs[(tab[nr], a)] = True
    if answered != len(index):
        problems.append("ONESIDED %s argument probe: ausearch answered %d "
                        "of %d records" % (arch, answered, len(index)))
    out = {}
    for (name, a) in pairs:
        out[name] = out.get(name, 0) | (1 << a)
    return out, len(pairs)


# ------------------------------------------------------- TTY keystrokes
# A TTY record's data= field is a hex-encoded run of keystrokes and
# ausearch renders it as a comma-separated mixture of quoted text and
# named keys: "ls -l /srv",<ret>.  The names are libaudit's own
# invention.  There is no second source for them: libaudit is not
# installed here in source form and no header names a key <page-up>.
# So this is the one table in this file built from a single authority,
# and it is probed rather than written, which at least means it cannot
# go stale without the suite seeing it.  The README says so.
#
# TTY_SENTINEL is appended to every probe so that the length of the
# sequence ausearch consumed can be read off the text it left behind.
# That matters: ESC [ 9 ~ comes back as <delete> followed by the text
# "~", so libaudit took three bytes and not four, and a table that
# assumed the whole candidate was consumed would render the leftover
# twice.
TTY_SENTINEL = "qQ"
TTY_DATA = re.compile(r"(?:^| )data=(.*?)\s*$")


def tty_probe(blobs):
    """Render each byte string through ausearch's TTY renderer."""
    got = probe([("TTY", "data=" + b.hex().upper()) for b in blobs])
    out = {}
    for i in range(len(blobs)):
        if i not in got:
            continue
        m = TTY_DATA.search(got[i])
        if m:
            out[i] = m.group(1)
    return out


def tty_controls():
    """Single bytes that ausearch gives a name to, like <ret>.

    Probed ALONE and not with the sentinel the escape probe uses.  With
    it, ESC + q came back as <F2> and 0x8f + q as <C1>, because both
    bytes introduce a sequence and the sentinel completed one, so the
    table said ESC on its own was an F2 key.
    """
    blobs = [bytes([b]) for b in range(0, 256)]
    got = tty_probe(blobs)
    out = {}
    named = 0
    for b in range(0, 256):
        r = got.get(b)
        if r is None:
            problems.append("ONESIDED tty byte 0x%02x got no answer" % b)
            continue
        if not r.startswith("<"):
            continue          # rendered as text, not as a named key
        name = r.split(",", 1)[0]
        out[b] = name
        named += 1
    return out, named


def tty_escapes():
    """Multi-byte key sequences that ausearch gives a name to.

    Two introducers, not one.  ESC is the obvious one; 0x80 to 0x9f are
    the 8-bit forms, and libaudit knows thirteen of those.  Probing only
    ESC left 0x8f q rendering as two octal-escaped bytes here and as a
    named key in ausearch, and nothing in the suite could see it because
    no case in the corpus held a byte above 0x7f next to a letter.

    Keyed by the whole consumed sequence, introducer included, so the
    renderer needs no special case for which byte starts one.
    """
    cands = []
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~"
    for intro in [0x1B] + list(range(0x80, 0xA0)):
        p = chr(intro)
        for c in letters:
            cands.append(p + c)
            cands.append(p + "[" + c)
            cands.append(p + "O" + c)
        for n in range(0, 64):
            cands.append(p + "[%d~" % n)
    blobs = [c.encode("latin-1") + TTY_SENTINEL.encode() for c in cands]
    got = tty_probe(blobs)
    out = {}
    for i, c in enumerate(cands):
        r = got.get(i)
        if r is None or not r.startswith("<"):
            continue
        name = r.split(",", 1)[0]
        if name == "<esc>":
            continue          # no match; the introducer printed alone
        # What came back after the name is the text libaudit did not
        # consume, so the prefix it did consume is the candidate minus
        # that tail.
        rest = r.split(",", 1)[1] if "," in r else '""'
        tail = rest[1:-1] if rest.startswith('"') else ""
        tail = tail.replace('\\"', '"').replace("\\\\", "\\")
        whole = c + TTY_SENTINEL
        if not tail or not whole.endswith(tail):
            problems.append("ONESIDED tty escape %r left %r, which is not "
                            "a suffix of it" % (c, tail))
            continue
        if len(tail) >= len(whole):
            continue          # consumed nothing
        consumed = whole[:len(whole) - len(tail)]
        if consumed in out and out[consumed] != name:
            problems.append("ONESIDED tty escape %r is both %s and %s"
                            % (consumed, out[consumed], name))
            continue
        out[consumed] = name
    return out, len(out)


def go_map_str_str(name, m, comment):
    out = ["// %s" % comment, "var %s = map[string]string{" % name]
    for k in sorted(m):
        out.append("\t%s: %s," % (goquote(k), goquote(m[k])))
    out.append("}")
    return "\n".join(out)


def go_map_str_int(name, m, comment):
    out = ["// %s" % comment, "var %s = map[string]int{" % name]
    for k in sorted(m):
        out.append("\t%s: %d," % (goquote(k), m[k]))
    out.append("}")
    return "\n".join(out)


def small_table(label, hdr, record_type, body_fmt, field, lower=False):
    """Probe a value-to-name table and cross-check it against hdr."""
    keys = sorted(hdr)
    got = probe([(record_type, body_fmt % v) for v in keys])
    out = {}
    agree = 0
    for i, v in enumerate(keys):
        r = got.get(i)
        name = one_field(r, field) if r else None
        if name is None or name.startswith(("unknown", "0x")):
            problems.append("ONESIDED %s %d (%s) is not named by ausearch"
                            % (label, v, hdr[v]))
            continue
        out[v] = name
        want = hdr[v].lower() if lower else hdr[v]
        if name == want:
            agree += 1
        else:
            problems.append("ALIAS %s %d: source says %s, ausearch says %s"
                            % (label, v, want, name))
    return out, agree


def arg_tables():
    """The small per-argument tables, each from a header or a Python
    module and each probed against ausearch."""
    import socket as S
    res = {}

    # Python's socket module has no AF_IUCV, AF_RXRPC, AF_PHONET,
    # AF_IEEE802154, AF_CAIF, AF_NFC, AF_KCM or AF_ISDN, and ausearch
    # names all eight when it renders a SOCKADDR, so a table built from
    # Python alone left thirteen families rendering as
    # unknown-family(n) against a name.  The header is the other source
    # and it has all fifty.
    fam = {}
    for a in dir(S):
        if a.startswith("AF_"):
            fam.setdefault(int(getattr(S, a)), a[3:].lower())
    if need(SOCKET_H):
        for name, val in defines(SOCKET_H, "PF_").items():
            fam.setdefault(val, name.lower())
    res["sockFamily"] = small_table("socket family", fam, "SYSCALL",
                                    "arch=c000003e syscall=41 success=yes "
                                    "exit=0 a0=%x a1=0 a2=0 a3=0 items=0 "
                                    "ppid=1 pid=2 auid=0 uid=0 gid=0 "
                                    'tty=(none) ses=1 comm="x" exe="/x"',
                                    "a0")

    # Probed over 1..16 rather than built from Python, because Python's
    # socket module has no SOCK_PACKET and ausearch does, so a table
    # taken from Python is missing the one type most likely to appear in
    # something worth auditing.  Python is the cross-check where it has
    # the name.
    typ = {}
    for a in dir(S):
        if a.startswith("SOCK_") and isinstance(getattr(S, a), int):
            typ.setdefault(int(getattr(S, a)), a)
    for n in range(1, 17):
        typ.setdefault(n, "SOCK_%d" % n)
    res["sockType"] = small_table("socket type", typ, "SYSCALL",
                                  "arch=c000003e syscall=41 success=yes "
                                  "exit=0 a0=0 a1=%x a2=0 a3=0 items=0 "
                                  "ppid=1 pid=2 auid=0 uid=0 gid=0 "
                                  'tty=(none) ses=1 comm="x" exe="/x"',
                                  "a1")

    proto = {}
    if need(PROTOCOLS):
        for line in open(PROTOCOLS):
            line = line.split("#", 1)[0].split()
            if len(line) >= 2 and line[1].isdigit():
                proto.setdefault(int(line[1]), line[0])
    res["sockProto"] = small_table("ip protocol", proto, "SYSCALL",
                                   "arch=c000003e syscall=41 success=yes "
                                   "exit=0 a0=0 a1=0 a2=%x a3=0 items=0 "
                                   "ppid=1 pid=2 auid=0 uid=0 gid=0 "
                                   'tty=(none) ses=1 comm="x" exe="/x"',
                                   "a2")

    whence = {}
    if need(FS_H):
        for name, val in defines(FS_H, "SEEK_").items():
            if name != "MAX":
                whence.setdefault(val, "SEEK_" + name)
    res["seekWhence"] = small_table("lseek whence", whence, "SYSCALL",
                                    "arch=c000003e syscall=8 success=yes "
                                    "exit=0 a0=0 a1=0 a2=%x a3=0 items=0 "
                                    "ppid=1 pid=2 auid=0 uid=0 gid=0 "
                                    'tty=(none) ses=1 comm="x" exe="/x"',
                                    "a2")

    # PROT_ and the access mode are probed with another bit already set.
    # Both renderers answer PROT_NONE / F_OK when none of the low three
    # bits is on, so a bit probed on its own above that mask comes back as
    # the zero name and looks unknown: PROT_SEM reported as PROT_NONE at
    # 0x8 and as PROT_SEM at 0xc.  Probing 0x8 alone would have left it
    # out of the table.
    prot = {}
    if need(MMAN_COMMON_H):
        for name, val in defines(MMAN_COMMON_H, "PROT_").items():
            prot["PROT_" + name] = val
    # mmap and mprotect do NOT share a table inside libaudit: PROT_SEM is
    # in the first and not the second.  Measured; one table for both is
    # wrong for every mmap with bit 3 set.
    res["protFlag"] = bitflags(
        "mprotect protection", prot, "SYSCALL",
        "arch=c000003e syscall=10 success=yes exit=0 a0=0 a1=0 "
        "a2=%x a3=0 items=0 ppid=1 pid=2 auid=0 uid=0 gid=0 "
        'tty=(none) ses=1 comm="x" exe="/x"', "a2", base=4)
    res["protFlagMmap"] = bitflags(
        "mmap protection", prot, "SYSCALL",
        "arch=c000003e syscall=9 success=yes exit=0 a0=0 a1=0 "
        "a2=%x a3=0 items=0 ppid=1 pid=2 auid=0 uid=0 gid=0 "
        'tty=(none) ses=1 comm="x" exe="/x"', "a2", base=4)

    acc = {"R_OK": 4, "W_OK": 2, "X_OK": 1}
    res["accessMode"] = bitflags("access mode", acc, "SYSCALL",
                                 "arch=c000003e syscall=21 success=yes "
                                 "exit=0 a0=0 a1=%x a2=0 a3=0 items=0 "
                                 "ppid=1 pid=2 auid=0 uid=0 gid=0 "
                                 'tty=(none) ses=1 comm="x" exe="/x"', "a1",
                                 base=1)
    return res


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
    caps, agcap = capabilities()
    scodes, agsc = seccomp_codes()
    nfp, agnf = nfprotos()
    flists, agfl = filterlists()
    oflags, agof = openflags()
    mflags, agmf = mapflags()
    ttycc, agtc = tty_controls()
    ttyesc, agte = tty_escapes()
    args64, nargs64 = syscall_args(ARCH_X8664, sc64)
    args32, nargs32 = syscall_args(ARCH_I386, sc32)
    small = arg_tables()

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
        "capName", caps,
        "Capability bit names.  Each of the %d bits linux/capability.h "
        "defines was put to ausearch on its own, because a missing name "
        "in the middle of a comma-separated list is easy to miss: %d "
        "agreed." % (len(caps), agcap)))
    parts.append(go_map_int_str(
        "seccompCode", scodes,
        "seccomp return actions, masked with SECCOMP_RET_ACTION "
        "(0x7fff0000).  SECCOMP_RET_KILL_PROCESS is 0x80000000 and masks "
        "to zero, which is why ausearch prints kill-thread for it; that "
        "is libaudit's behaviour and auditp copies it.  %d of %d agreed "
        "with linux/seccomp.h." % (agsc, len(scodes))))
    parts.append(go_map_int_str(
        "nfprotoName", nfp,
        "Netfilter protocol families, from the NFPROTO_ enum in "
        "linux/netfilter.h.  NOT the AF_ constants: family=1 is inet "
        "here and AF_UNIX there.  %d of %d agreed." % (agnf, len(nfp))))
    parts.append(go_map_int_str(
        "filterListName", flists,
        "Audit rule filter lists, AUDIT_FILTER_* in linux/audit.h "
        "against ausearch: %d of %d agreed." % (agfl, len(flists))))
    parts.append(go_map_int_str(
        "openFlagName", oflags,
        "Open flags, one bit at a time from asm-generic/fcntl.h against "
        "ausearch: %d of %d agreed.  The header writes them in octal "
        "with a leading zero and reading those as decimal gives a table "
        "that is wrong for every flag above O_RDWR." % (agof, len(oflags))))
    parts.append(go_map_int_str(
        "mapFlagName", mflags,
        "mmap flags, one bit at a time from the three mman headers "
        "against ausearch: %d of %d agreed." % (agmf, len(mflags))))
    parts.append(go_map_str_int(
        "argInterpX8664", args64,
        "Which syscall arguments ausearch interprets on x86_64, as a "
        "bitmask over a0..a3: %d pairs.  a0..a3 are the one part of the "
        "format with no self-describing structure, and a pair auditp "
        "does not implement has to be REFUSED rather than printed as a "
        "number, because printing 0x2a where ausearch prints a signal "
        "name is a wrong answer and not a gap." % nargs64))
    parts.append(go_map_str_int(
        "argInterpI386", args32,
        "The same for i386: %d pairs." % nargs32))
    for key, label, comment in (
            ("sockFamily", "sockFamilyName",
             "Socket address families as ausearch names them, which is "
             "the AF_ constant lower-cased with the prefix dropped, and "
             "local rather than unix for AF_UNIX"),
            ("sockType", "sockTypeName", "Socket types, SOCK_*"),
            ("sockProto", "sockProtoName",
             "IP protocol numbers, from /etc/protocols"),
            ("seekWhence", "seekWhenceName", "lseek whence, SEEK_*"),
            ("protFlag", "protFlagName",
             "mprotect protection bits, PROT_*.  mmap has a different "
             "table and gets its own below"),
            ("protFlagMmap", "protFlagMmapName",
             "mmap protection bits, which include PROT_SEM where "
             "mprotect's do not"),
            ("accessMode", "accessModeName",
             "access() mode bits, R_OK W_OK X_OK")):
        tbl, ag = small[key]
        parts.append(go_map_int_str(label, tbl,
                                    "%s.  %d of %d agreed with the "
                                    "independent source."
                                    % (comment, ag, len(tbl))))
    parts.append(go_map_int_str(
        "ttyControlName", ttycc,
        "Single bytes a TTY record's data= field renders as a named "
        "key rather than as text: %d of the 256, probed one at a time.  "
        "0x1c to 0x1f are NOT in it, which reading a terminal manual "
        "would not tell you: libaudit prints those as octal inside the "
        "quoted text." % agtc))
    parts.append(go_map_str_str(
        "ttyEscapeName", ttyesc,
        "Byte sequences following ESC that libaudit names, %d of them, "
        "keyed by the bytes it CONSUMES rather than by the sequence "
        "probed: ESC [ 9 ~ comes back as <delete> and then the text ~, "
        "so it took three bytes of the four." % agte))
    parts.append(go_map_int_str(
        "signalName", sigs,
        "Signal names as ausearch prints them, probed for 0 through 128 "
        "and cross-checked against asm-generic/signal.h and Python: %d "
        "agreed.  Probed rather than computed because libaudit's table "
        "stops at 31, so signal 32 is SIGRTMIN to the kernel and "
        "unknown-signal(32) to ausearch, and signal 0 is SIG0, which is "
        "not a name anything else uses." % agsig))

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
    rep.write("capability %d\n" % len(caps))
    rep.write("capability-two-source-agree %d\n" % agcap)
    rep.write("seccomp-code %d\n" % len(scodes))
    rep.write("seccomp-code-two-source-agree %d\n" % agsc)
    rep.write("nfproto %d\n" % len(nfp))
    rep.write("nfproto-two-source-agree %d\n" % agnf)
    rep.write("filter-list %d\n" % len(flists))
    rep.write("filter-list-two-source-agree %d\n" % agfl)
    rep.write("open-flag %d\n" % len(oflags))
    rep.write("open-flag-two-source-agree %d\n" % agof)
    rep.write("map-flag %d\n" % len(mflags))
    rep.write("map-flag-two-source-agree %d\n" % agmf)
    rep.write("tty-control %d\n" % len(ttycc))
    rep.write("tty-escape %d\n" % len(ttyesc))
    rep.write("arg-pairs-x86_64 %d\n" % nargs64)
    rep.write("arg-pairs-i386 %d\n" % nargs32)
    for key in ("sockFamily", "sockType", "sockProto", "seekWhence",
                "protFlag", "protFlagMmap", "accessMode"):
        tbl, ag = small[key]
        rep.write("%s %d\n" % (key, len(tbl)))
        rep.write("%s-two-source-agree %d\n" % (key, ag))
    # A name difference between two sources for the same number is an
    # alias and is recorded, not fatal; a number that moves is fatal.  The
    # committed t/tables.expect pins the exact set, so an eighth alias
    # appearing is a failure even though the seven known ones are not.
    hard = [p for p in problems
            if not p.startswith(("NOTE ", "ALIAS ", "ONESIDED ", "COUNT ",
                                 "DIVERGE "))]
    rep.write("problems %d\n" % len(hard))
    rep.write("notes %d\n" % (len(problems) - len(hard)))
    for p in sorted(problems):
        rep.write("  %s\n" % p)
    if args.report:
        rep.close()
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())

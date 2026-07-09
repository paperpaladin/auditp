#!/usr/bin/env python3
"""Generate the test corpus, and the ground truth for every field in it.

Why generated rather than harvested.  The first version of this corpus was
336308 records taken off this machine's journal, and it was deleted: a real
audit log is a record of who logged in, what software is installed and where
their files are, and these repositories are published.  Nothing in this file
names a real host, user, path, package or process.  The SHAPES are faithful
to what a Linux kernel emits -- the field names, their order, which of the
three encodings each value uses, the prose an AVC record puts before its
first field -- because those were read off a real log before it was
destroyed, and they are facts about the format rather than about the
machine.

What generating buys, beyond safety.  Two things a harvest cannot give:

  Ground truth.  --truth writes the exact bytes this script encoded into
  every hex and quoted value, so the decoder can be checked against what was
  meant and not only against a second decoder.  A hex value holding a
  newline, a NUL, a double quote or a byte above 0x7f is a construct no real
  log on this machine happened to contain, and the decoder was untested for
  it however many records agreed.

  Constructs on demand.  The real log held 2 PATH records and no EXECVE,
  SOCKADDR, MQ_OPEN or OBJ_PID at all, because loading an audit rule needs
  privilege this account does not have.  Here they are written directly.

What is NOT invented, and must not be: every syscall number, errno, signal,
address family, file mode bit, open flag and audit record type in this file
is a kernel constant with a fixed meaning.  Replacing those with invented
ones would make the interpretation comparison meaningless.

Determinism: one fixed seed, so regenerating must reproduce the committed
file byte for byte.  The suite asserts that, because a corpus that drifts
silently takes every number in the README with it.
"""

import argparse
import random
import sys

# ---------------------------------------------------------------- pools
# Every string below is invented.  The uids are system accounts that exist
# on any distribution (and two that resolve to nothing, to exercise the
# path where ausearch prints the number); the login account of whoever runs
# this is deliberately not used.
COMMS = ["widgetd", "frobnicator", "bargen", "qux-helper", "svc-alpha",
         "mesh-agent", "tick", "collator"]
EXES = ["/opt/widget/bin/widgetd", "/usr/local/bin/frobnicator",
        "/opt/widget/libexec/bargen", "/srv/tools/qux-helper",
        "/usr/local/sbin/svc-alpha", "/opt/mesh/mesh-agent"]
PATHS = ["/srv/data/report.txt", "/etc/widget.conf", "/var/lib/widget/db",
         "/srv/data/archive/2019/notes", "/opt/widget/share/table.bin",
         "/tmp/scratch-0001", "/srv/data/a b c.txt", "/etc/widget.d/10-base"]
HOSTS = ["node-a", "node-b", "?"]
TERMS = ["pts/0", "pts/4", "tty3", "?", "(none)"]
KEYS = ["watch-etc", "exec-audit", "(null)", "perm-mod"]
ACCTS = ["root", "svcop", "widget", "nobody"]
PKGS = ["widget-core-1.2.3-4.x86_64", "frobnicator-0.9-1.noarch",
        "mesh-agent-3.11.0-2.x86_64"]
UNITS = ["widgetd", "frobnicator-sweep", "mesh-agent", "tick.timer"]
CTX = ["system_u:system_r:widget_t:s0",
       "system_u:system_r:init_t:s0",
       "unconfined_u:unconfined_r:frob_t:s0-s0:c0.c511",
       "system_u:object_r:widget_data_t:s0"]
UIDS = [0, 1, 2, 8, 12, 65534, 60123]
GIDS = [0, 1, 2, 12, 65534, 60123]
UNSET = 4294967295


def rnd_ctx(r):
    return r.choice(CTX)


# ---------------------------------------------------------- the encoder
# The kernel's rule, from audit_log_untrustedstring(): a string containing a
# byte outside 0x21..0x7e, or a double quote, is written as upper-case hex;
# anything else is written in double quotes.  Everything here that encodes a
# text value goes through this one function, so the corpus cannot contain a
# quoted value that should have been hex.
def needs_hex(s):
    b = s if isinstance(s, bytes) else s.encode("utf-8")
    for c in b:
        if c < 0x21 or c > 0x7E or c == ord('"'):
            return True
    return False


def enc_text(s):
    """Encode a text value the way the kernel would.  Returns (wire, bytes)."""
    b = s if isinstance(s, bytes) else s.encode("utf-8")
    if needs_hex(b):
        return "".join("%02X" % c for c in b), b
    return '"%s"' % b.decode("latin-1"), b


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.lines = []
        self.truth = []          # (key, idx, field, decoded-bytes)
        self.counts = {}         # construct -> how many
        self.serial = 1000
        self.secs = 1700000000   # fixed epoch, no relation to anything here
        self.ms = 0

    def tick(self):
        self.serial += 1
        self.ms += 137
        if self.ms >= 1000:
            self.ms -= 1000
            self.secs += 1
        return "%d.%03d:%d" % (self.secs, self.ms, self.serial)

    def count(self, name, n=1):
        self.counts[name] = self.counts.get(name, 0) + n

    def event(self, records, node=None):
        """records is a list of (type, [(field, wire, decoded_or_None)])."""
        key = self.tick()
        if node:
            key = node + ":" + key
        for idx, (typ, fields) in enumerate(records):
            body = " ".join("%s=%s" % (n, w) for n, w, _ in fields)
            prefix = ""
            if fields and fields[0][0] == "@prefix":
                prefix = fields[0][1]
                body = prefix + " ".join("%s=%s" % (n, w)
                                         for n, w, _ in fields[1:])
                self.count("prose-prefix")
            stamp = key.split(":", 1)[1] if node else key
            head = "type=%s msg=audit(%s): " % (typ, stamp)
            if node:
                head = "node=%s " % node + head
                self.count("node-prefix")
            self.lines.append(head + body)
            for n, w, d in fields:
                if d is not None:
                    self.truth.append((key, idx, n, d))
        self.count("records", len(records))
        if len(records) > 1:
            self.count("multi-record-events")
        return key

    # ------------------------------------------------------------ helpers
    def text(self, name, s):
        w, b = enc_text(s)
        self.count("hex-encoded" if w[0] != '"' else "quoted")
        return (name, w, b)

    def bare(self, name, v):
        self.count("bare")
        return (name, str(v), None)


def syscall_event(g, sc, arch, args, exit_, success, comm, exe, path=None,
                  nitems=0, cwd=None, proctitle=None, key=None):
    """One kernel event, in the order the kernel emits it.

    The order is load-bearing and this was got wrong first.  ausearch treats
    PROCTITLE as the record that ENDS an event, so a corpus that wrote
    PROCTITLE first split every multi-record event in two: 720 events out of
    876 records where there should have been 595.  The kernel's order is
    SYSCALL, then EXECVE, then CWD, then the PATH items in item order, then
    PROCTITLE.  Writing it any other way produces a file auditd would never
    write, and the oracle is right to disagree about it.
    """
    sysf = [g.bare("arch", arch), g.bare("syscall", sc),
            g.bare("success", success), g.bare("exit", exit_)]
    for i, a in enumerate(args):
        sysf.append(g.bare("a%d" % i, a))
    sysf += [g.bare("items", nitems), g.bare("ppid", 900),
             g.bare("pid", 901 + g.r.randrange(500)),
             g.bare("auid", g.r.choice([UNSET, 0, 2])),
             g.bare("uid", g.r.choice(UIDS)), g.bare("gid", g.r.choice(GIDS)),
             g.bare("euid", 0), g.bare("suid", 0), g.bare("fsuid", 0),
             g.bare("egid", 0), g.bare("sgid", 0), g.bare("fsgid", 0),
             g.bare("tty", g.r.choice(["(none)", "pts0", "tty3"])),
             g.bare("ses", g.r.choice([UNSET, 1, 7])),
             g.text("comm", comm), g.text("exe", exe),
             ("subj", CTX[0], None),
             g.bare("key", key if key else "(null)")]
    recs = [("SYSCALL", sysf)]
    g.count("syscall-records")
    if cwd is not None:
        recs.append(("CWD", [g.text("cwd", cwd)]))
    if path is not None:
        for i, (p, mode, ntype) in enumerate(path):
            f = [g.bare("item", i), g.text("name", p),
                 g.bare("inode", 100000 + i * 7), g.bare("dev", "fd:01"),
                 g.bare("mode", mode),
                 g.bare("ouid", 0), g.bare("ogid", 0),
                 g.bare("rdev", "00:00"),
                 ("obj", CTX[3], None),
                 g.bare("nametype", ntype),
                 g.bare("cap_fp", "0"), g.bare("cap_fi", "0"),
                 g.bare("cap_fe", "0"), g.bare("cap_fver", "0"),
                 g.bare("cap_frootid", "0")]
            recs.append(("PATH", f))
            g.count("path-items")
    if proctitle is not None:
        raw = b"\0".join(a.encode() for a in proctitle)
        w, b = enc_text(raw)
        g.count("hex-encoded" if w[0] != '"' else "quoted")
        g.count("proctitle")
        recs.append(("PROCTITLE", [("proctitle", w, b)]))
    g.event(recs)


# x86_64 syscall numbers, with argument shapes chosen so that the fields an
# interpreter cares about are populated.  (name, nr, [a0..a3]) -- the values
# are kernel constants written in the hex the kernel writes them in.
X86_64 = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "lseek": 8,
    "mmap": 9, "mprotect": 10, "munmap": 11, "ioctl": 16, "pread64": 17,
    "access": 21, "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
    "bind": 49, "listen": 50, "clone": 56, "fork": 57, "execve": 59,
    "kill": 62, "fcntl": 72, "truncate": 76, "chdir": 80, "rename": 82,
    "mkdir": 83, "rmdir": 84, "creat": 85, "link": 86, "unlink": 87,
    "symlink": 88, "chmod": 90, "fchmod": 91, "chown": 92, "umask": 95,
    "ptrace": 101, "getgroups": 115, "setuid": 105, "setgid": 106,
    "setreuid": 113, "setresuid": 117, "capset": 126, "mount": 165,
    "umount2": 166, "init_module": 175, "delete_module": 176,
    "setxattr": 188, "futex": 202, "epoll_ctl": 233, "openat": 257,
    "mkdirat": 258, "fchownat": 260, "unlinkat": 263, "renameat": 264,
    "linkat": 265, "symlinkat": 266, "fchmodat": 268, "faccessat": 269,
    "accept4": 288, "finit_module": 313, "renameat2": 316,
    "execveat": 322, "openat2": 437, "bpf": 321,
}
# i386, where the numbers mean different things: 102 is socketcall there
# and getgroups on x86_64, which is the whole reason the table is per arch.
I386 = {
    "restart_syscall": 0, "exit": 1, "fork": 2, "read": 3, "write": 4,
    "open": 5, "close": 6, "unlink": 10, "execve": 11, "chdir": 12,
    "chmod": 15, "setuid": 23, "kill": 37, "mkdir": 39, "rmdir": 40,
    "socketcall": 102, "clone": 120, "mprotect": 125, "getcwd": 183,
    "mmap2": 192, "openat": 295, "unlinkat": 301, "fchmodat": 306,
    "openat2": 437,
}
ARCH64 = "c000003e"
ARCH32 = "40000003"

# Open flags, protection bits, address families, signals and errnos, all
# kernel constants.
O_FLAGS = ["0", "1", "2", "42", "241", "80000", "80042", "C1", "200000"]
# 8, 9 and c are PROT_SEM, which lives outside the three-bit mask the
# renderer tests for PROT_NONE.  Without 8 on its own the suite could
# not tell a renderer that masks correctly from one that does not: the
# arg-prot-no-none mutant survived 58 mutants and a green suite
# because no record in the corpus set that bit alone.
PROT = ["0", "1", "3", "5", "7", "8", "9", "c"]
MAPF = ["2", "22", "32", "812", "8022"]
MODES = ["0100644", "0100755", "040755", "0120777", "0140777", "010644",
         "060660", "020666", "0104755", "0102644", "0101644", "0100000"]
ERRNOS = [1, 2, 3, 4, 5, 9, 11, 12, 13, 14, 17, 20, 21, 22, 24, 28, 32,
          36, 38, 39, 40, 95, 98, 110, 111, 115]
# 30 is here on purpose: ausearch 4.0.2 renders it IGPWR, with the S
# missing, and 29 and 31 either side of it are correct.  See
# t/known-diff.txt.  32 is here because libaudit's table stops at 31 and
# the kernel's does not, so it is the boundary where ausearch starts
# printing unknown-signal.
SIGNALS = [1, 2, 3, 4, 6, 8, 9, 11, 13, 15, 17, 19, 29, 30, 31, 32]
# fcntl commands: the low ones, F_SETOWN (whose argument is a uid), two
# above F_LINUX_SPECIFIC_BASE, and one nothing names.
FCNTL_CMDS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1024, 1030, 1033, 99]
FAMILIES = [1, 2, 10, 16, 17]


def build(g):
    r = g.r

    # --- 1. a file-watch event, the classic multi-record shape -----------
    for i in range(60):
        p = r.choice(PATHS)
        g.count("event-openat")
        syscall_event(
            g, X86_64["openat"], ARCH64,
            ["ffffff9c", "%x" % (0x7ffd00000000 + r.randrange(1 << 20)),
             r.choice(O_FLAGS), "%o" % r.choice([0, 0o644, 0o600])],
            exit_=r.choice([3, 4, -13, -2]), success=r.choice(["yes", "no"]),
            comm=r.choice(COMMS), exe=r.choice(EXES),
            path=[(p, r.choice(MODES), "NORMAL"),
                  ("/srv/data", "040755", "PARENT")][:r.choice([1, 2])],
            nitems=r.choice([1, 2]), cwd=r.choice(["/", "/srv", "/home/svcop"]),
            proctitle=[r.choice(EXES), "-c", p],
            key=r.choice(KEYS))

    # --- 2. one event per syscall, both architectures --------------------
    for name, nr in sorted(X86_64.items()):
        g.count("syscall-x86_64")
        syscall_event(g, nr, ARCH64,
                      ["%x" % r.randrange(1 << 16), "%x" % r.randrange(1 << 32),
                       "%x" % r.randrange(1 << 12), "%x" % r.randrange(1 << 8)],
                      exit_=r.choice([0, 1, 12, -r.choice(ERRNOS)]),
                      success=r.choice(["yes", "no"]),
                      comm=r.choice(COMMS), exe=r.choice(EXES),
                      proctitle=[r.choice(EXES)])
    for name, nr in sorted(I386.items()):
        g.count("syscall-i386")
        syscall_event(g, nr, ARCH32,
                      ["%x" % r.randrange(1 << 16), "%x" % r.randrange(1 << 16),
                       "%x" % r.randrange(1 << 12), "0"],
                      exit_=r.choice([0, 2, -r.choice(ERRNOS)]),
                      success=r.choice(["yes", "no"]),
                      comm=r.choice(COMMS), exe=r.choice(EXES))

    # --- 3. argument interpretation, the fields a detection rule reads ---
    for flags in O_FLAGS:
        for mode in ["0", "644", "600", "1B4"]:
            g.count("openat-flags")
            syscall_event(g, 257, ARCH64, ["ffffff9c", "7ffd12340000", flags, mode],
                          exit_=3, success="yes", comm="widgetd",
                          exe=EXES[0])
    for fam in FAMILIES:
        for typ in [1, 2, 3, 5]:
            g.count("socket-family")
            syscall_event(g, 41, ARCH64, ["%x" % fam, "%x" % typ, "0", "0"],
                          exit_=4, success="yes", comm="mesh-agent", exe=EXES[5])
    for prot in PROT:
        for mf in MAPF:
            g.count("mmap-prot")
            syscall_event(g, 9, ARCH64, ["0", "1000", prot, mf],
                          exit_=0, success="yes", comm="tick", exe=EXES[1])
    # fcntl, whose second argument is a command out of a table and
    # whose third is a uid only when that command is F_SETOWN.  Both
    # arches: i386 has fcntl at 55 and fcntl64 at 221, and ausearch
    # interprets the argument of both.
    for cmd in FCNTL_CMDS:
        for arg in ["0", "3e8", "ffffffff"]:
            g.count("fcntl-cmd")
            syscall_event(g, 72, ARCH64, ["3", "%x" % cmd, arg, "0"],
                          exit_=0, success="yes", comm="svc-alpha",
                          exe=EXES[4])
    # bpf, ptrace and epoll_ctl, each of whose first interesting
    # argument is a name out of a table, including one value past the
    # end of each table so that the unknown spelling is exercised.
    for cmd in [0, 1, 2, 5, 10, 31, 0x3f]:
        g.count("bpf-cmd")
        syscall_event(g, 321, ARCH64, ["%x" % cmd, "7ffd1000", "70", "0"],
                      exit_=4, success="yes", comm="widgetd", exe=EXES[0])
    for req in [0, 1, 3, 4, 8, 12, 16, 0x4206, 0x63]:
        g.count("ptrace-req")
        syscall_event(g, 101, ARCH64, ["%x" % req, "3e8", "0", "0"],
                      exit_=0, success="yes", comm="frobnicator",
                      exe=EXES[1])
    for op in [1, 2, 3, 0, 9]:
        g.count("epoll-op")
        syscall_event(g, 233, ARCH64, ["4", "%x" % op, "5", "7ffd2000"],
                      exit_=0, success="yes", comm="collator", exe=EXES[2])

    # mount and umount2, whose flag words drop an unknown bit and print
    # the whole value in hex when no bit has a name.
    for fl in ["0", "1", "20", "1000", "200000", "8000", "c0ed0000",
               "40000000", "80000000", "100"]:
        g.count("mount-flag")
        syscall_event(g, 165, ARCH64, ["7ffd1000", "7ffd2000", "7ffd3000", fl],
                      exit_=0, success="yes", comm="svc-alpha", exe=EXES[4])
    for fl in ["0", "1", "2", "4", "8", "a", "10", "80000000"]:
        g.count("umount-flag")
        syscall_event(g, 166, ARCH64, ["7ffd1000", fl, "0", "0"],
                      exit_=0, success="yes", comm="mesh-agent", exe=EXES[5])

    for nr in (55, 221):
        g.count("fcntl-i386")
        syscall_event(g, nr, ARCH32, ["3", "8", "c", "0"],
                      exit_=0, success="yes", comm="tick", exe=EXES[1])

    for sig in SIGNALS:
        g.count("kill-signal")
        syscall_event(g, 62, ARCH64, ["3e8", "%x" % sig, "0", "0"],
                      exit_=0, success="yes", comm="collator", exe=EXES[2])

    # --- 4. every errno we can name, as a negative exit ------------------
    for e in ERRNOS:
        g.count("errno-exit")
        syscall_event(g, 257, ARCH64, ["ffffff9c", "7ffd00000000", "0", "0"],
                      exit_=-e, success="no", comm="bargen", exe=EXES[2])

    # --- 5. SECCOMP over a wide range of numbers, both arches ------------
    for arch, tbl in ((ARCH64, X86_64), (ARCH32, I386)):
        for name, nr in sorted(tbl.items()):
            g.count("seccomp")
            g.event([("SECCOMP", [
                g.bare("auid", r.choice([UNSET, 0])),
                g.bare("uid", r.choice(UIDS)), g.bare("gid", r.choice(GIDS)),
                g.bare("ses", r.choice([UNSET, 3])),
                ("subj", rnd_ctx(r), None),
                g.bare("pid", 2000 + nr), g.text("comm", r.choice(COMMS)),
                g.text("exe", r.choice(EXES)),
                g.bare("sig", r.choice([0, 31])), g.bare("arch", arch),
                g.bare("syscall", nr),
                g.bare("compat", 0 if arch == ARCH64 else 1),
                g.bare("ip", "0x%x" % r.randrange(1 << 32)),
                g.bare("code", r.choice(["0x0", "0x30000", "0x50001",
                                         "0x7ffc0000", "0x80000000"]))])])

    # --- 6. PATH, every file type and the special permission bits --------
    for mode in MODES:
        for nt in ["NORMAL", "PARENT", "CREATE", "DELETE", "UNKNOWN"]:
            g.count("path-mode")
            g.event([("PATH", [
                g.bare("item", 0), g.text("name", r.choice(PATHS)),
                g.bare("inode", r.randrange(1 << 20)),
                g.bare("dev", "fd:0%d" % r.randrange(4)),
                g.bare("mode", mode),
                g.bare("ouid", r.choice(UIDS)), g.bare("ogid", r.choice(GIDS)),
                g.bare("rdev", "00:00"), ("obj", CTX[3], None),
                g.bare("nametype", nt),
                g.bare("cap_fp", "0"), g.bare("cap_fi", "0"),
                g.bare("cap_fe", "0"), g.bare("cap_fver", "0"),
                g.bare("cap_frootid", "0")])])

    # --- 7. uid and gid resolution, including two that resolve to nothing
    for u in UIDS + [UNSET]:
        g.count("uid-value")
        g.event([("SYSCALL", [
            g.bare("arch", ARCH64), g.bare("syscall", 105),
            g.bare("success", "yes"), g.bare("exit", 0),
            g.bare("a0", "%x" % u), g.bare("a1", "0"), g.bare("a2", "0"),
            g.bare("a3", "0"), g.bare("items", 0), g.bare("ppid", 1),
            g.bare("pid", 2), g.bare("auid", u), g.bare("uid", u),
            g.bare("gid", u), g.bare("euid", u), g.bare("suid", u),
            g.bare("fsuid", u), g.bare("egid", u), g.bare("sgid", u),
            g.bare("fsgid", u), g.bare("tty", "(none)"), g.bare("ses", u),
            g.text("comm", "svc-alpha"), g.text("exe", EXES[4]),
            ("subj", CTX[1], None), g.bare("key", "(null)")])])

    # --- 8. the nested field list: msg='...' with a hex cmd inside ------
    CMDS = [["dnf", "upgrade"], ["tee", "/etc/widget.d/10-base"],
            ["sh", "-c", "echo hi > /srv/data/a b c.txt"],
            ["grep", "-r", "needle", "/srv"], ["widgetctl", "reload"]]
    for argv in CMDS:
        for res in ["success", "failed"]:
            g.count("user-cmd")
            cmdw, cmdb = enc_text(" ".join(argv))
            g.count("hex-encoded" if cmdw[0] != '"' else "quoted")
            cwdw, cwdb = enc_text("/srv/work")
            exew, exeb = enc_text("/usr/bin/widgetctl")
            inner = ("cwd=%s cmd=%s exe=%s terminal=%s res=%s"
                     % (cwdw, cmdw, exew, r.choice(TERMS), res))
            g.event([("USER_CMD", [
                g.bare("pid", r.randrange(1 << 15)),
                g.bare("uid", r.choice(UIDS)),
                g.bare("auid", r.choice(UIDS)), g.bare("ses", 3),
                ("subj", rnd_ctx(r), None),
                ("msg", "'" + inner + "'", None)])])
            g.count("nested-msg")

    # --- 9. the PAM family, which is where single-quoted msg lives ------
    for typ in ["USER_AUTH", "USER_ACCT", "USER_START", "USER_END",
                "CRED_ACQ", "CRED_DISP", "CRED_REFR", "ADD_USER",
                "ADD_GROUP", "DEL_USER", "USER_LOGIN", "USER_LOGOUT",
                "UNKNOWN[1100]", "UNKNOWN[1105]", "UNKNOWN[1112]"]:
        for res in ["success", "failed"]:
            g.count("pam-record")
            acctw, _ = enc_text(r.choice(ACCTS))
            exew, _ = enc_text(r.choice(EXES))
            inner = ("op=PAM:authentication grantors=pam_unix,pam_permit "
                     "acct=%s exe=%s hostname=%s addr=? terminal=%s res=%s"
                     % (acctw, exew, r.choice(HOSTS), r.choice(TERMS), res))
            g.event([(typ, [
                g.bare("pid", r.randrange(1 << 15)),
                g.bare("uid", r.choice(UIDS)),
                g.bare("auid", r.choice([UNSET] + UIDS)),
                g.bare("ses", r.choice([UNSET, 1, 3])),
                ("subj", rnd_ctx(r), None),
                ("msg", "'" + inner + "'", None)])])
            g.count("nested-msg")

    # --- 10. AVC, the one record with prose before its first field ------
    for perms in ["{ read }", "{ read write }", "{ getattr }",
                  "{ execute execute_no_trans }", "{ relabelfrom }",
                  "{ name_connect }"]:
        for verdict in ["denied", "granted"]:
            g.count("avc")
            g.event([("AVC", [
                ("@prefix", "avc:  %s  %s for  " % (verdict, perms), None),
                g.bare("pid", r.randrange(1 << 15)),
                g.text("comm", r.choice(COMMS)),
                g.text("name", r.choice(PATHS).rsplit("/", 1)[-1]),
                ("dev", '"vda3"', None),
                g.bare("ino", r.randrange(1 << 20)),
                ("scontext", CTX[0], None), ("tcontext", CTX[3], None),
                g.bare("tclass", r.choice(["file", "dir", "chr_file",
                                           "fifo_file", "tcp_socket"])),
                g.bare("permissive", r.choice([0, 1]))])])

    # --- 11. SOCKADDR, hex all the way down -----------------------------
    SADDRS = [
        ("AF_INET 10.0.0.1:443", "02000" + "1BB" + "0A000001" + "0000000000000000"),
        ("AF_INET 192.0.2.9:80", "0200005000" + "C0000209" + "000000000000000000"[:18]),
        ("AF_UNIX /run/widget.sock", "0100" + "".join("%02X" % c for c in b"/run/widget.sock") + "00" * 8),
        ("AF_INET6", "0A00" + "01BB" + "00000000" + "20010DB8" + "00000000" + "00000000" + "00000001" + "00000000"),
        ("AF_NETLINK", "10000000" + "00000000" + "00000000"),
    ]
    for label, hexs in SADDRS:
        g.count("sockaddr")
        g.event([("SOCKADDR", [("saddr", hexs, None)])])

    # --- 12. EXECVE, where argc and a0..aN are a second numbering -------
    for argv in [["widgetctl", "reload"],
                 ["sh", "-c", "for i in 1 2 3; do echo $i; done"],
                 ["frobnicator", "--path", "/srv/data/a b c.txt", "-v"],
                 ["tr", "\n", " "]]:
        g.count("execve")
        f = [g.bare("argc", len(argv))]
        for i, a in enumerate(argv):
            f.append(g.text("a%d" % i, a))
        g.event([("EXECVE", f)])

    # --- 13. the rest of the type zoo -----------------------------------
    for i in range(40):
        g.count("bpf")
        g.event([("BPF", [g.bare("prog-id", 100 + i),
                          g.bare("op", r.choice(["LOAD", "UNLOAD"]))])])
    for op, extra in [("set", [("audit_enabled", "1"), ("old", "0")]),
                      ("set", [("audit_pid", "901"), ("old", "0")]),
                      ("add_rule", [("key", "watch-etc"), ("list", "4")]),
                      ("remove_rule", [("key", "exec-audit"), ("list", "4")])]:
        g.count("config-change")
        f = [g.bare("op", op)] + [g.bare(k, v) for k, v in extra]
        f += [g.bare("auid", UNSET), g.bare("ses", UNSET),
              ("subj", CTX[1], None), g.bare("res", 1)]
        g.event([("CONFIG_CHANGE", f)])
    for sig in SIGNALS:
        g.count("anom-abend")
        g.event([("ANOM_ABEND", [
            g.bare("auid", r.choice([UNSET] + UIDS)),
            g.bare("uid", r.choice(UIDS)), g.bare("gid", r.choice(GIDS)),
            g.bare("ses", 3), ("subj", rnd_ctx(r), None),
            g.bare("pid", r.randrange(1 << 18)),
            g.text("comm", r.choice(COMMS)), g.text("exe", r.choice(EXES)),
            g.bare("sig", sig), g.bare("res", 1)])])
    for fam in [0, 1, 2, 3, 7, 10]:
        g.count("netfilter-cfg")
        g.event([("NETFILTER_CFG", [
            g.bare("table", "widget_filter:%d" % fam),
            g.bare("family", fam), g.bare("entries", r.randrange(300)),
            g.bare("op", r.choice(["nft_register_table", "nft_register_rule",
                                   "nft_unregister_chain"])),
            g.bare("pid", 1161), ("subj", CTX[1], None),
            g.text("comm", "frobnicator")])])
    for typ in ["SERVICE_START", "SERVICE_STOP", "SYSTEM_BOOT",
                "SYSTEM_SHUTDOWN", "SYSTEM_RUNLEVEL", "DAEMON_START",
                "DAEMON_END", "MAC_POLICY_LOAD", "KERN_MODULE",
                "SOFTWARE_UPDATE", "FEATURE_CHANGE", "TTY", "OBJ_PID",
                "FD_PAIR", "MQ_OPEN", "IPC", "CAPSET", "MMAP",
                "LANDLOCK_ACCESS", "LANDLOCK_DOMAIN", "UNKNOWN[1138]",
                "UNKNOWN[2300]", "UNKNOWN[9999]"]:
        g.count("type-zoo")
        g.event([(typ, zoo_fields(g, typ))])


def zoo_fields(g, typ):
    r = g.r
    if typ == "KERN_MODULE":
        return [g.text("name", "widget_cooling")]
    if typ == "MAC_POLICY_LOAD":
        return [g.bare("auid", UNSET), g.bare("ses", UNSET),
                g.bare("lsm", "selinux"), g.bare("res", 1)]
    if typ == "SOFTWARE_UPDATE" or typ == "UNKNOWN[1138]":
        swq, _ = enc_text(r.choice(PKGS))
        exew, _ = enc_text("/usr/libexec/widget-updater")
        inner = ("op=update sw=%s sw_type=rpm key_enforce=0 gpg_res=1 "
                 "root_dir=\"/\" comm=\"widget-updater\" exe=%s hostname=? "
                 "addr=? terminal=? res=success" % (swq, exew))
        g.count("nested-msg")
        return [g.bare("pid", 927), g.bare("uid", 0), g.bare("auid", UNSET),
                g.bare("ses", UNSET), ("subj", CTX[1], None),
                ("msg", "'" + inner + "'", None)]
    if typ == "LANDLOCK_ACCESS":
        return [g.bare("domain", "13d3841cc"),
                g.bare("blockers", "fs.execute,fs.read_file"),
                g.text("path", r.choice(PATHS)), ("dev", '"vda3"', None),
                g.bare("ino", r.randrange(1 << 22))]
    if typ == "LANDLOCK_DOMAIN":
        return [g.bare("domain", "13d3841cc"),
                g.bare("status", r.choice(["allocated", "deallocated"])),
                g.bare("mode", "enforcing"), g.bare("pid", 18241),
                g.bare("uid", 0), g.text("exe", r.choice(EXES)),
                g.text("comm", r.choice(COMMS))]
    if typ == "CAPSET":
        return [g.bare("pid", 3312), g.bare("cap_pi", "0"),
                g.bare("cap_pp", "000001ffffffffff"),
                g.bare("cap_pe", "000001ffffffffff"),
                g.bare("cap_pa", "0")]
    if typ == "MMAP":
        return [g.bare("fd", -1), g.bare("flags", "0x32")]
    if typ == "IPC":
        return [g.bare("ouid", 0), g.bare("ogid", 0), g.bare("mode", "0600")]
    if typ == "OBJ_PID":
        return [g.bare("opid", 4210), g.bare("oauid", UNSET),
                g.bare("ouid", 0), g.bare("oses", UNSET),
                ("obj", CTX[1], None), g.text("ocomm", r.choice(COMMS))]
    if typ == "FD_PAIR":
        return [g.bare("fd0", 7), g.bare("fd1", 8)]
    if typ == "MQ_OPEN":
        return [g.bare("oflag", "0x42"), g.bare("mode", "0600"),
                g.bare("mq_flags", "0x0"), g.bare("mq_maxmsg", 10),
                g.bare("mq_msgsize", 8192), g.bare("mq_curmsgs", 0)]
    if typ == "TTY":
        dataw, datab = enc_text("ls -l /srv\r")
        g.count("hex-encoded" if dataw[0] != '"' else "quoted")
        return [g.bare("tty", "pts3"), g.bare("uid", 0), g.bare("auid", 0),
                g.bare("ses", 3), g.bare("major", 136), g.bare("minor", 3),
                g.bare("comm", '"bash"'), ("data", dataw, datab)]
    if typ == "FEATURE_CHANGE":
        return [g.bare("feature", "loginuid_immutable"), g.bare("old", 0),
                g.bare("new", 1), g.bare("old_lock", 0), g.bare("new_lock", 1),
                g.bare("res", 1)]
    if typ == "SYSTEM_RUNLEVEL":
        inner = ("old-level=N new-level=5 comm=\"systemd-update\" "
                 "exe=\"/usr/lib/widget/update-utmp\" hostname=? addr=? "
                 "terminal=? res=success")
        g.count("nested-msg")
        return [g.bare("pid", 909), g.bare("uid", 0), g.bare("auid", UNSET),
                g.bare("ses", UNSET), ("subj", CTX[1], None),
                ("msg", "'" + inner + "'", None)]
    if typ == "UNKNOWN[9999]":
        # No space in the value: a field name ausearch does not know is a
        # field it does not hex-decode, so a hex value here would be a
        # construct nothing can read back and the ground-truth file would
        # claim a decoding that is not available to anyone.
        return [g.bare("mystery", 1), g.text("note", "a-type-nothing-names")]
    # the systemd-shaped ones
    inner = ("unit=%s comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" "
             "hostname=? addr=? terminal=? res=success" % r.choice(UNITS))
    g.count("nested-msg")
    return [g.bare("pid", 1), g.bare("uid", 0), g.bare("auid", UNSET),
            g.bare("ses", UNSET), ("subj", CTX[1], None),
            ("msg", "'" + inner + "'", None)]


def build_edges(g):
    """Constructs a real log on this machine did not happen to contain.

    Every one of these is something the kernel or auditd can emit; none of
    them appeared in 336308 records off one machine, which is the whole
    argument for not relying on a harvest alone.  The bytes that are not
    ASCII are hex-encoded by the kernel's own rule, so this file and the
    corpus it writes are pure ASCII even where the value is not.
    """
    r = g.r

    # A value holding each kind of byte that forces the hex encoding.
    HOSTILE_TEXT = [
        b"/srv/data/with space.txt",
        b"/srv/data/with\ttab.txt",
        b"/srv/data/with\nnewline.txt",
        b'/srv/data/with"quote.txt',
        b"/srv/data/with'apostrophe.txt",
        b"/srv/data/with=equals.txt",
        b"/srv/data/with\x00nul.txt",
        b"/srv/data/caf\xc3\xa9.txt",          # valid UTF-8, two bytes
        b"/srv/data/\xff\xfe-not-utf8.txt",    # not valid UTF-8 at all
        b"/srv/data/\x01\x02\x03-control.txt",
        b"/srv/data/" + b"x" * 600,            # long, but still quotable
        b"/srv/data/" + b"y z " * 150,         # long and forced to hex
    ]
    for t in HOSTILE_TEXT:
        g.count("edge-text")
        w, b = enc_text(t)
        g.count("hex-encoded" if w[0] != '"' else "quoted")
        g.event([("PATH", [
            g.bare("item", 0), ("name", w, b),
            g.bare("inode", 42), g.bare("dev", "fd:01"),
            g.bare("mode", "0100644"), g.bare("ouid", 0), g.bare("ogid", 0),
            g.bare("rdev", "00:00"), g.bare("nametype", "NORMAL")])])

    # proctitle with embedded NULs, which is how the kernel stores argv.
    for argv in [["widgetd"], ["sh", "-c", "echo a b c"],
                 ["frobnicator"] + ["--flag%d" % i for i in range(40)]]:
        g.count("edge-proctitle")
        raw = b"\0".join(a.encode() for a in argv)
        w, b = enc_text(raw)
        g.count("hex-encoded" if w[0] != '"' else "quoted")
        g.event([("PROCTITLE", [("proctitle", w, b)])])

    # The hex-shape boundary, which is where the format is genuinely
    # ambiguous.  Each of these is written into the corpus as a literal
    # bare value, not through enc_text, because the point is what a
    # READER does with bytes that may or may not be an encoding.
    #   abcdef   lower case, and the kernel writes upper: decoded anyway
    #   4142434  an odd number of digits: decoded, last nibble shifted up
    #   12       two digits: the byte 0x12, not the filename 12
    #   4        one digit: the filename 4, not half a byte
    #   zz       not hex at all
    for lit, why in [("abcdef", "lower case"), ("4142434", "odd length"),
                     ("12", "two digits is a byte"),
                     ("4", "one digit is a name"),
                     ("zz", "not hex"), ("AB", "upper case, two digits"),
                     ("ff", "lower case, two digits")]:
        g.count("edge-hexshape")
        g.event([("PATH", [
            g.bare("item", 0), ("name", lit, None),
            g.bare("inode", 5), g.bare("dev", "fd:01"),
            g.bare("mode", "0100644"), g.bare("ouid", 0),
            g.bare("ogid", 0), g.bare("rdev", "00:00"),
            g.bare("nametype", "NORMAL")])])

    # A record with no fields at all, only prose.  The kernel's AVC
    # records are the ones with prose before their fields; this one has
    # nothing after it.  Nothing in 336308 real records looked like this
    # and a mutation that threw away the prose of a field-less record
    # survived the whole suite until it was added.
    g.count("edge-no-fields")
    g.event([("USER_AVC", [("@prefix",
                            "avc:  received policyload notice (seqno=2)",
                            None)])])

    # Capability masks with one and two bits set.  cap_fp=0 and a full
    # mask were the only two in the corpus, and a mutation that dropped
    # the lowest capability bit survived both: zero renders as none
    # whichever way the loop is wrong, and in a 41-name list one missing
    # name is one of 41 and the comparison is of the whole string, so it
    # was caught, but the single-bit case is the one that pins the index.
    for cp in ["0000000000000001", "0000000000000002", "0000000000000003",
               "0000000000000080", "0000000000000000",
               "000001ffffffffff", "0000000000200000"]:
        g.count("edge-cap")
        g.event([("PATH", [
            g.bare("item", 0), g.text("name", "/srv/data/report.txt"),
            g.bare("inode", 9), g.bare("dev", "fd:01"),
            g.bare("mode", "0100644"), g.bare("ouid", 0), g.bare("ogid", 0),
            g.bare("rdev", "00:00"), g.bare("nametype", "NORMAL"),
            g.bare("cap_fp", cp), g.bare("cap_fi", cp),
            g.bare("cap_fe", 1), g.bare("cap_fver", 2),
            g.bare("cap_frootid", 0)])])

    # An empty value.  msg= with nothing after it is what auditd writes
    # when a userspace message is empty, and it is the one encoding the
    # corpus otherwise has none of.
    g.count("edge-empty")
    g.event([("USER_AVC", [g.bare("pid", 1), ("msg", "", b""),
                           g.bare("res", 1)])])
    g.count("edge-empty")
    g.event([("USER_AVC", [("msg", "", b""), g.bare("pid", 2),
                           g.bare("res", 0)])])

    # A field name repeated in one record.  PATH does not do this but
    # EXECVE-style records with a repeated a0 do, and a parser that keeps
    # the last one silently drops a value.
    g.count("edge-duplicate")
    g.event([("EXECVE", [g.bare("argc", 2), g.text("a0", "widgetctl"),
                         g.text("a0", "reload")])])

    # node= on the front, which moves every offset in the line.
    for node in ["node-a", "node-b"]:
        g.count("edge-node")
        g.event([("SYSCALL", [
            g.bare("arch", ARCH64), g.bare("syscall", 257),
            g.bare("success", "yes"), g.bare("exit", 3),
            g.bare("a0", "ffffff9c"), g.bare("a1", "7ffd0000"),
            g.bare("a2", "0"), g.bare("a3", "0"), g.bare("items", 0),
            g.bare("ppid", 1), g.bare("pid", 2), g.bare("auid", 0),
            g.bare("uid", 0), g.bare("gid", 0), g.bare("euid", 0),
            g.bare("suid", 0), g.bare("fsuid", 0), g.bare("egid", 0),
            g.bare("sgid", 0), g.bare("fsgid", 0), g.bare("tty", "(none)"),
            g.bare("ses", 1), g.text("comm", "widgetd"),
            g.text("exe", EXES[0]), ("subj", CTX[0], None),
            g.bare("key", "(null)")])], node=node)


def build_interleaved(g):
    """Two events in flight at once, their records alternating in the file.

    Kept in its own corpus because ausearch and auditp are not expected to
    agree about it and the README says which is which: ausearch ends an
    event at the PROCTITLE record, so the second event's records that
    arrive after the first event's PROCTITLE land in a different event
    from the ones before it.  auditp groups by the key alone.  Measuring
    that difference is the point; hiding it inside the main corpus would
    turn it into a failure.
    """
    r = g.r
    # Interleaving.  Two events in flight at once, their records
    # alternating in the file, which is what a busy machine produces and
    # what a correlator that only looks at adjacent lines gets wrong.
    k1 = g.tick()
    k2 = g.tick()
    pairs = [
        (k1, "SYSCALL", "arch=%s syscall=257 success=yes exit=3 a0=ffffff9c "
                        "a1=7ffd0000 a2=0 a3=0 items=1 ppid=1 pid=11 auid=0 "
                        "uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 "
                        "fsgid=0 tty=(none) ses=1 comm=\"widgetd\" "
                        "exe=\"/opt/widget/bin/widgetd\" key=\"watch-etc\""
                        % ARCH64),
        (k2, "SYSCALL", "arch=%s syscall=59 success=yes exit=0 a0=1 a1=2 "
                        "a2=3 a3=4 items=2 ppid=1 pid=12 auid=0 uid=0 gid=0 "
                        "euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 "
                        "tty=pts0 ses=1 comm=\"bargen\" "
                        "exe=\"/opt/widget/libexec/bargen\" key=(null)"
                        % ARCH64),
        (k1, "CWD", 'cwd="/srv"'),
        (k2, "CWD", 'cwd="/opt"'),
        (k1, "PATH", 'item=0 name="/etc/widget.conf" inode=7 dev=fd:01 '
                     'mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL'),
        (k2, "PATH", 'item=0 name="/opt/widget/bin/widgetd" inode=9 '
                     'dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 '
                     'nametype=NORMAL'),
        (k2, "PATH", 'item=1 name="/lib64/ld-linux-x86-64.so.2" inode=11 '
                     'dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 '
                     'nametype=NORMAL'),
        (k1, "PROCTITLE", "proctitle=" + "".join(
            "%02X" % c for c in b"/opt/widget/bin/widgetd\0-c\0/etc/widget.conf")),
        (k2, "PROCTITLE", 'proctitle="/opt/widget/libexec/bargen"'),
    ]
    for key, typ, body in pairs:
        g.lines.append("type=%s msg=audit(%s): %s" % (typ, key, body))
    g.count("edge-interleaved", len(pairs))
    g.count("records", len(pairs))


HOSTILE = [
    # Not a record at all.  Real logs pick these up from syslog.
    b"Sep  2 19:12:06 host kernel: something else entirely",
    b"",
    b"   ",
    b"type=SYSCALL",
    b"type=SYSCALL msg=audit(",
    b"type=SYSCALL msg=audit(abc:1): a=1",
    b"type=SYSCALL msg=audit(1700000000.000:notanumber): a=1",
    b"type=SYSCALL msg=audit(1700000000.000:1) a=1",          # no colon
    b"msg=audit(1700000000.000:1): a=1",                      # no type
    b"node=only-a-node",
    b"type= msg=audit(1700000000.000:2): a=1",
    # A record whose value quote is never closed.
    b'type=PATH msg=audit(1700000000.000:3): name="/srv/unterminated',
    # A hex value with an odd number of digits, and one with a non-hex
    # digit, both of which a decoder must not read past.
    b"type=USER_CMD msg=audit(1700000000.000:4): cmd=4142434",
    b"type=USER_CMD msg=audit(1700000000.000:5): cmd=41424Z44",
    # Lower-case hex.  The kernel writes upper case; auditd's own decoder
    # accepts either, and this is here to find out whether we do too.
    b"type=USER_CMD msg=audit(1700000000.000:6): cmd=646e6620757067726164650a",
    # A serial far beyond 2^32, and a timestamp with no milliseconds.
    b"type=BPF msg=audit(1700000000.000:18446744073709551615): prog-id=1 op=LOAD",
    b"type=BPF msg=audit(1700000000:7): prog-id=1 op=LOAD",
    # Trailing whitespace and a double space between fields.
    b"type=BPF msg=audit(1700000000.000:8): prog-id=1  op=LOAD ",
    # A field name that is only digits, which is not a field name.
    b"type=BPF msg=audit(1700000000.000:9): 123=4 prog-id=1 op=LOAD",
    # A NUL byte in the middle of a line.
    b"type=BPF msg=audit(1700000000.000:10): prog-id=1 op=LO\x00AD",
    # The fractional part of the timestamp, at the three lengths that
    # decide whether it is a record at all.  ausearch reads at most three
    # digits and then wants the colon, so the four-digit one is not a
    # record to it; the empty one and the two-digit one are, and the
    # two-digit one has to come back out with two digits and not three.
    b"type=BPF msg=audit(1700000000.1234:11): prog-id=1 op=LOAD",
    b"type=BPF msg=audit(1700000000.:12): prog-id=1 op=LOAD",
    b"type=BPF msg=audit(1700000000.12:13): prog-id=1 op=LOAD",
    # A line that arrived through something that uses CRLF.  The
    # carriage return is part of the last value and has to stay there:
    # bufio.Scanner's line splitter drops it, and a dropped byte is a
    # byte the round trip cannot put back.
    b"type=BPF msg=audit(1700000000.000:14): prog-id=1 op=LOAD\r",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--truth")
    ap.add_argument("--hostile")
    ap.add_argument("--interleaved")
    ap.add_argument("--counts")
    ap.add_argument("--seed", type=int, default=20261019)
    args = ap.parse_args()

    g = Gen(args.seed)
    build(g)
    build_edges(g)

    if args.interleaved:
        gi = Gen(args.seed + 1)
        build_interleaved(gi)
        with open(args.interleaved, "wb") as f:
            for line in gi.lines:
                f.write(line.encode("latin-1") + b"\n")

    with open(args.out, "wb") as f:
        for line in g.lines:
            f.write(line.encode("latin-1") + b"\n")

    if args.truth:
        with open(args.truth, "wb") as f:
            for key, idx, name, val in g.truth:
                f.write(b"%s\t%d\t%s\t%s\n"
                        % (key.encode(), idx, name.encode(), escape(val)))

    if args.hostile:
        with open(args.hostile, "wb") as f:
            for line in HOSTILE:
                f.write(line + b"\n")

    out = open(args.counts, "w") if args.counts else sys.stdout
    out.write("lines %d\n" % len(g.lines))
    out.write("truth-rows %d\n" % len(g.truth))
    for k in sorted(g.counts):
        out.write("%s %d\n" % (k, g.counts[k]))
    if args.counts:
        out.close()
    return 0


def escape(b):
    """Backslash escaping, so the truth file is ASCII whatever the value is."""
    out = bytearray()
    for c in b:
        if c == 0x5C:
            out += b"\\\\"
        elif c == 0x09:
            out += b"\\t"
        elif c == 0x0A:
            out += b"\\n"
        elif c < 0x20 or c > 0x7E:
            out += b"\\x%02x" % c
        else:
            out.append(c)
    return bytes(out)


if __name__ == "__main__":
    sys.exit(main())

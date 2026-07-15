package main

import (
	"fmt"
	"strconv"
	"strings"
)

// a0 to a3 are the one part of the audit format with no self-describing
// structure.  The same four field names carry a directory file
// descriptor, an open flag word, a file mode, a uid, a signal number or
// nothing at all, and which one depends entirely on the syscall the
// record is about.  ausearch has a table of 97 (syscall, argument) pairs
// it interprets on x86_64 and 99 on i386; auditp implements them by
// kind and REFUSES by name the pairs it has no kind for.
//
// The refusal matters more than the coverage.  For a pair neither tool
// interprets, both print 0x2a and auditp claims the field.  For a pair
// ausearch interprets and auditp does not, printing 0x2a would be a
// WRONG answer, not a gap, so auditp passes the raw value through and
// counts the refusal under its own (syscall, argument) name.  The set of
// pairs ausearch interprets is in tables.go, probed from ausearch itself
// and re-probed by the suite, so the refusal list cannot silently rot
// into a list of wrong answers.

type argKind int

const (
	argPlain  argKind = iota // 0x%x, which is what ausearch prints
	argUnimpl                // ausearch interprets this and we do not
	argDirFD
	argOpenFlags
	argMode4    // %04o, with suid,sgid,sticky prefixes
	argModeFull // the same form as the mode= field: file,644
	argUID
	argGID
	argSignal
	argProt
	argProtMmap
	argMapFlags
	argSockFamily
	argSockType
	argSockProto
	argAccess
	argWhence
	argExitCode
	argOpenMode // a mode, but only when the flags argument has O_CREAT
	argFcntlCmd
	argFcntlArg // a uid, but only when the command argument is F_SETOWN
	argBpfCmd
	argPtraceReq
	argEpollOp
	argMountFlags
	argUmountFlags
	argCloneFlags
)

// oCreat is the value of O_CREAT, which is the same on x86_64 and i386.
const oCreat = 0x40

// fSetOwn is F_SETOWN, the one fcntl command whose argument ausearch
// resolves through the password file.
const fSetOwn = 8

// argKinds is the (syscall name, argument index) table.  Only the pairs
// auditp implements are here; anything else present in argInterpX8664 or
// argInterpI386 is argUnimpl, and anything in neither is argPlain.
var argKinds = map[string][4]argKind{
	"open":              {argPlain, argOpenFlags, argOpenMode, argPlain},
	"openat":            {argDirFD, argPlain, argOpenFlags, argOpenMode},
	"openat2":           {argDirFD, argPlain, argPlain, argPlain},
	"open_by_handle_at": {argPlain, argPlain, argOpenFlags, argPlain},
	"mq_open":           {argPlain, argOpenFlags, argPlain, argPlain},
	"creat":             {argPlain, argMode4, argPlain, argPlain},
	"chmod":             {argPlain, argMode4, argPlain, argPlain},
	"fchmod":            {argPlain, argMode4, argPlain, argPlain},
	"fchmodat":          {argDirFD, argPlain, argMode4, argPlain},
	"mkdir":             {argPlain, argMode4, argPlain, argPlain},
	"mkdirat":           {argDirFD, argPlain, argMode4, argPlain},
	"mknodat":           {argDirFD, argPlain, argMode4, argPlain},
	"mknod":             {argPlain, argModeFull, argPlain, argPlain},
	"faccessat":         {argDirFD, argPlain, argAccess, argPlain},
	"faccessat2":        {argDirFD, argPlain, argAccess, argPlain},
	"access":            {argPlain, argAccess, argPlain, argPlain},
	"fchownat":          {argDirFD, argPlain, argPlain, argPlain},
	"futimesat":         {argDirFD, argPlain, argPlain, argPlain},
	"linkat":            {argDirFD, argPlain, argDirFD, argPlain},
	"move_mount":        {argPlain, argPlain, argDirFD, argPlain},
	"name_to_handle_at": {argDirFD, argPlain, argPlain, argPlain},
	"newfstatat":        {argDirFD, argPlain, argPlain, argPlain},
	"readlinkat":        {argDirFD, argPlain, argDirFD, argPlain},
	"renameat":          {argDirFD, argPlain, argDirFD, argPlain},
	"renameat2":         {argDirFD, argPlain, argDirFD, argPlain},
	"unlinkat":          {argDirFD, argPlain, argPlain, argPlain},
	"utimensat":         {argDirFD, argPlain, argPlain, argPlain},
	"chown":             {argPlain, argUID, argPlain, argPlain},
	"setuid":            {argUID, argPlain, argPlain, argPlain},
	"setfsuid":          {argUID, argPlain, argPlain, argPlain},
	"setreuid":          {argUID, argUID, argPlain, argPlain},
	"setresuid":         {argUID, argUID, argUID, argPlain},
	"setgid":            {argGID, argPlain, argPlain, argPlain},
	"setfsgid":          {argGID, argPlain, argPlain, argPlain},
	"setregid":          {argGID, argGID, argPlain, argPlain},
	"setresgid":         {argGID, argGID, argGID, argPlain},
	"kill":              {argPlain, argSignal, argPlain, argPlain},
	"tkill":             {argPlain, argSignal, argPlain, argPlain},
	"tgkill":            {argPlain, argPlain, argSignal, argPlain},
	"rt_sigaction":      {argSignal, argPlain, argPlain, argPlain},
	"mmap":              {argPlain, argPlain, argProtMmap, argMapFlags},
	"mprotect":          {argPlain, argPlain, argProt, argPlain},
	"socket":            {argSockFamily, argSockType, argSockProto, argPlain},
	"lseek":             {argPlain, argPlain, argWhence, argPlain},
	"fcntl":             {argPlain, argFcntlCmd, argFcntlArg, argPlain},
	"bpf":               {argBpfCmd, argPlain, argPlain, argPlain},
	"ptrace":            {argPtraceReq, argPlain, argPlain, argPlain},
	"epoll_ctl":         {argPlain, argEpollOp, argPlain, argPlain},
	"mount":             {argPlain, argPlain, argPlain, argMountFlags},
	"clone":             {argPlain, argPlain, argCloneFlags, argPlain},
	"umount2":           {argPlain, argUmountFlags, argPlain, argPlain},
	"fcntl64":           {argPlain, argFcntlCmd, argFcntlArg, argPlain},
	"exit":              {argExitCode, argPlain, argPlain, argPlain},
	"exit_group":        {argExitCode, argPlain, argPlain, argPlain},
}

// atFDCWD is (int)-100 as the kernel logs it: a 32-bit value in hex.
const atFDCWD = 0xffffff9c

func (ip *Interp) arg(r *Record, f *Field, idx int, raw string) (string, string) {
	sysname, arch := ip.syscallOf(r)
	kind := argPlain
	if k, ok := argKinds[sysname]; ok {
		kind = k[idx]
	}
	// ausearch decides whether a pair is interpreted at all, per
	// architecture, and auditp follows.  argKinds says only HOW.  i386's
	// open takes a mode in a2 exactly as x86_64's does and ausearch
	// interprets the second and not the first; a table keyed by syscall
	// name alone was wrong about that and there is no reason to think it
	// is the only such pair.
	if !argInterpreted(arch, sysname, idx) {
		kind = argPlain
	} else if kind == argPlain {
		kind = argUnimpl
	}
	if kind == argFcntlArg {
		// fcntl's third argument is a pid or a uid only when the
		// command says so.  ausearch resolves it through the password
		// file for F_SETOWN and prints it as a number for every other
		// command, which is the same shape as open's mode and the
		// same reason: the register holds whatever the caller put
		// there.
		if cmd, ok := ip.argValue(r, 1); ok && cmd == fSetOwn {
			kind = argUID
		} else {
			kind = argPlain
		}
	}
	if kind == argOpenMode {
		// open's mode argument is only a mode when the flags say a file
		// may be created.  Without O_CREAT the register holds whatever
		// userspace left there and ausearch prints it as a number.
		if flags, ok := ip.argValue(r, openFlagsIndex[sysname]); ok &&
			flags&oCreat != 0 {
			kind = argMode4
		} else {
			kind = argPlain
		}
	}
	if kind == argUnimpl {
		return raw, ip.refuse("a" + strconv.Itoa(idx) + "/" + sysname)
	}
	if kind == argPlain {
		// ausearch does not reformat an uninterpreted argument, it
		// prepends 0x to the bytes that were in the log.  a3=1B4 comes
		// out as 0x1B4, upper case and all, and a reader that parses
		// the number and prints %x disagrees on every argument whose
		// hex digits are not already lower case.
		return "0x" + raw, ip.claim("arg-plain")
	}
	n, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		// Not hex.  ausearch's own parse fails too and it prints the
		// field unchanged; so do we, as a refusal rather than a guess.
		return raw, ip.refuse("a" + strconv.Itoa(idx))
	}
	what := "arg-" + argKindName[kind]
	switch kind {
	case argDirFD:
		if n == atFDCWD {
			return "AT_FDCWD", ip.claim(what)
		}
	case argOpenFlags:
		return flagsText(raw, openFlagName, "O_RDONLY", true), ip.claim(what)
	case argMode4:
		return mode4Text(n), ip.claim(what)
	case argModeFull:
		return modeText(strconv.FormatUint(n, 8)), ip.claim(what)
	case argUID:
		return ip.id32(n, ip.passwd), ip.claim(what)
	case argGID:
		return ip.id32(n, ip.group), ip.claim(what)
	case argSignal:
		if name, ok := signalName[int(n)]; ok {
			return name, ip.claim(what)
		}
		return fmt.Sprintf("unknown-signal(0x%x)", n), ip.claim(what)
	case argProt:
		return protText(n, protFlagName), ip.claim(what)
	case argProtMmap:
		return protText(n, protFlagMmapName), ip.claim(what)
	case argMapFlags:
		return mapFlagsText(raw), ip.claim(what)
	case argSockFamily:
		return lookup(n, sockFamilyName, "unknown-family(0x%x)"), ip.claim(what)
	case argSockType:
		// Masked with 0xff: SOCK_CLOEXEC and SOCK_NONBLOCK live in the
		// high bits of the same argument and ausearch drops them.
		// 0xff0a is SOCK_PACKET and 0x1a is unknown-type(1a), so the
		// mask is 0xff and not the kernel's own SOCK_TYPE_MASK of 0xf.
		return lookup(n&0xff, sockTypeName, "unknown-type(%x)"), ip.claim(what)
	case argSockProto:
		return lookup(n, sockProtoName, "unknown-proto(%x)"), ip.claim(what)
	case argAccess:
		return bitsOrZero(n, accessModeName, 7, "F_OK"), ip.claim(what)
	case argFcntlCmd:
		if name, ok := fcntlCmdName[int(n)]; ok {
			return name, ip.claim(what)
		}
		return fmt.Sprintf("unknown-fcntl-command(%d)", n), ip.claim(what)
	case argBpfCmd:
		// Three tables, three spellings of "I have no name for this",
		// none of them guessable: bpf's is hex with no 0x, ptrace's is
		// hex with one, and epoll_ctl's is decimal.
		if name, ok := bpfCmdName[int(n)]; ok {
			return name, ip.claim(what)
		}
		return fmt.Sprintf("unknown-bpf-cmd(%x)", n), ip.claim(what)
	case argPtraceReq:
		if name, ok := ptraceReqName[int(n)]; ok {
			return name, ip.claim(what)
		}
		return fmt.Sprintf("unknown-ptrace(0x%x)", n), ip.claim(what)
	case argEpollOp:
		if name, ok := epollOpName[int(n)]; ok {
			return name, ip.claim(what)
		}
		// Signed, and 32-bit: ausearch prints operation 0xfd5a7b6c as
		// -44451156.  The random-argument records in the corpus found
		// that; the three real operations are 1, 2 and 3 and no
		// hand-written case would have.
		return fmt.Sprintf("unknown-epoll_ctl-operation(%d)",
			int32(uint32(n))), ip.claim(what)
	case argCloneFlags:
		return cloneText(n, raw), ip.claim(what)
	case argMountFlags:
		return flagsOrRaw(n, raw, mountFlagName), ip.claim(what)
	case argUmountFlags:
		return flagsOrRaw(n, raw, umountFlagName), ip.claim(what)
	case argWhence:
		return lookup(n, seekWhenceName, "unknown-whence(%x)"), ip.claim(what)
	case argExitCode:
		switch n {
		case 0:
			return "EXIT_SUCCESS", ip.claim(what)
		case 1:
			return "EXIT_FAILURE", ip.claim(what)
		}
		return "UNKNOWN", ip.claim(what)
	}
	return fmt.Sprintf("0x%x", n), ip.claim(what)
}

var argKindName = map[argKind]string{
	argPlain: "plain", argDirFD: "dirfd", argOpenFlags: "openflags",
	argMode4: "mode4", argModeFull: "modefull", argUID: "uid",
	argGID: "gid", argSignal: "signal", argProt: "prot",
	argProtMmap: "prot-mmap", argMapFlags: "mapflags",
	argSockFamily: "sockfamily", argSockType: "socktype",
	argSockProto: "sockproto", argAccess: "access", argWhence: "whence",
	argExitCode: "exitcode", argOpenMode: "openmode",
	argFcntlCmd: "fcntlcmd", argFcntlArg: "fcntlarg",
	argBpfCmd: "bpfcmd", argPtraceReq: "ptracereq", argEpollOp: "epollop",
	argMountFlags: "mountflags", argUmountFlags: "umountflags",
	argCloneFlags: "cloneflags",
}

// openFlagsIndex says which argument of each open-family syscall holds
// the flag word that decides whether the next one is a mode.
var openFlagsIndex = map[string]int{"open": 1, "openat": 2}

func (ip *Interp) argValue(r *Record, idx int) (uint64, bool) {
	name := "a" + strconv.Itoa(idx)
	for i := range r.Fields {
		if r.Fields[i].Name == name {
			n, err := strconv.ParseUint(string(r.Fields[i].Value()), 16, 64)
			return n, err == nil
		}
	}
	return 0, false
}

func lookup(n uint64, tab map[int]string, unknown string) string {
	if name, ok := tab[int(n)]; ok {
		return name
	}
	return fmt.Sprintf(unknown, n)
}

// bitsOrZero renders a small bit set, with a name for the case where
// none of the bits under mask is set.  Both the access mode and the mmap
// protection work this way: 0x8 on its own is PROT_NONE because PROT_SEM
// is outside the mask, and 0xc is PROT_EXEC|PROT_SEM because PROT_EXEC
// is inside it.  Measured; it is not what reading the bit table suggests.
func bitsOrZero(n uint64, tab map[int]string, mask uint64, zero string) string {
	if n&mask == 0 {
		return zero
	}
	var parts []string
	for b := 0; b < 32; b++ {
		bit := uint64(1) << uint(b)
		if n&bit == 0 {
			continue
		}
		if name, ok := tab[int(bit)]; ok {
			parts = append(parts, name)
		}
	}
	if len(parts) == 0 {
		return zero
	}
	return strings.Join(parts, "|")
}

// cloneText renders clone's flag argument, which is two fields in one
// register: CSIGNAL in the low byte is the signal the child sends its
// parent when it dies, and the flags are above it.  a2=0x11 is SIGCHLD
// with no flags at all, a2=0x1200011 is two flags and SIGCHLD, and
// a2=0x7f is neither, because 127 is not a signal, so it comes back as
// the plain hex.  The signal goes last.
func cloneText(n uint64, raw string) string {
	var parts []string
	for b := 8; b < 64; b++ {
		bit := uint64(1) << uint(b)
		if n&bit == 0 {
			continue
		}
		if name, ok := cloneFlagName[int(bit)]; ok {
			parts = append(parts, name)
		}
	}
	if sig, ok := signalName[int(n&0xff)]; ok && n&0xff != 0 {
		parts = append(parts, sig)
	}
	if len(parts) == 0 {
		return "0x" + raw
	}
	return strings.Join(parts, "|")
}

// flagsOrRaw renders a flag word as the names of the bits in it, or as
// the hex it was written with when none of them has a name.  Three
// details, all measured: an unknown bit is dropped rather than printed
// as a number, a value with no known bit at all comes back as the whole
// value in hex, and the hex is the bytes the log held rather than a
// reformatting of them, which is the same rule argPlain follows.
func flagsOrRaw(n uint64, raw string, tab map[int]string) string {
	var parts []string
	for b := 0; b < 64; b++ {
		bit := uint64(1) << uint(b)
		if n&bit == 0 {
			continue
		}
		if name, ok := tab[int(bit)]; ok {
			parts = append(parts, name)
		}
	}
	if len(parts) == 0 {
		return "0x" + raw
	}
	return strings.Join(parts, "|")
}

func protText(n uint64, tab map[int]string) string {
	return bitsOrZero(n, tab, 7, "PROT_NONE")
}

// mode4Text is chmod's rendering of a mode: four octal digits, with the
// three special bits named in front.  Not the same as the mode= field,
// which also names the file type; mknod's a1 uses that one instead.
func mode4Text(n uint64) string {
	var b strings.Builder
	if n&04000 != 0 {
		b.WriteString("suid,")
	}
	if n&02000 != 0 {
		b.WriteString("sgid,")
	}
	if n&01000 != 0 {
		b.WriteString("sticky,")
	}
	// The three special bits are named in front AND stripped from the
	// digits: a mode of suid|sticky|0300 is "suid,sticky,0300", not
	// "suid,sticky,5300".
	fmt.Fprintf(&b, "%04o", n&0777)
	return b.String()
}

// id32 resolves a uid or gid that arrived as a 32-bit register value.
// ausearch sign-extends it: a0=ffffff9c on setuid is unknown(-100), not
// unknown(4294967196).
func (ip *Interp) id32(n uint64, tab map[uint64]string) string {
	if n == unsetID {
		return "unset"
	}
	if name, ok := tab[n]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", int32(uint32(n)))
}

// syscallOf returns the syscall name and the arch value of a record, so
// that a0..a3 can be read with the right table.
func (ip *Interp) syscallOf(r *Record) (string, int) {
	a, ok := archOf(r)
	if !ok {
		return "", 0
	}
	var tab map[int]string
	switch archName[a] {
	case "x86_64":
		tab = syscallX8664
	case "i386":
		tab = syscallI386
	default:
		return "", a
	}
	for i := range r.Fields {
		if r.Fields[i].Name == "syscall" {
			nr, err := strconv.Atoi(string(r.Fields[i].Value()))
			if err != nil {
				return "", a
			}
			return tab[nr], a
		}
	}
	return "", a
}

func argInterpreted(arch int, sysname string, idx int) bool {
	var tab map[string]int
	switch archName[arch] {
	case "x86_64":
		tab = argInterpX8664
	case "i386":
		tab = argInterpI386
	default:
		return false
	}
	return tab[sysname]&(1<<uint(idx)) != 0
}

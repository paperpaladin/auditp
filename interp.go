package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Interp turns a decoded field value into the thing it means.  Without -i
// it is a pass-through that still removes the quoting.
//
// The rule the whole project turns on: every field is either translated to
// a value byte-identical to the one ausearch -i prints, or REFUSED and
// printed in its decoded raw form.  A refusal is counted under its field
// name and reported by the census.  A refusal and a wrong answer are
// different failures and are never added together, because the second is a
// defect and the first is a gap.
type Interp struct {
	on     bool
	st     *Stats
	passwd map[uint64]string
	group  map[uint64]string
}

// unsetID is (uid_t)-1, which the kernel writes when there is no login uid
// or no session.  ausearch prints "unset".
const unsetID = 4294967295

func NewInterp(on bool, st *Stats) *Interp {
	ip := &Interp{on: on, st: st}
	if on {
		ip.passwd = readIDFile("/etc/passwd")
		ip.group = readIDFile("/etc/group")
	}
	return ip
}

// readIDFile reads name:passwd:id:... from /etc/passwd or /etc/group.
//
// Files only, no NSS.  ausearch calls getpwuid, which on a machine with
// ldap or systemd-homed in nsswitch.conf would answer from those too, and
// then auditp and ausearch would disagree about a uid for a reason that
// has nothing to do with parsing an audit log.  Stated in the README as a
// limitation rather than hidden behind cgo.
func readIDFile(path string) map[uint64]string {
	m := map[uint64]string{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) < 3 {
			continue
		}
		id, err := strconv.ParseUint(p[2], 10, 64)
		if err != nil {
			continue
		}
		// First entry wins, which is what a files-backed getpwuid does.
		if _, dup := m[id]; !dup {
			m[id] = p[0]
		}
	}
	return m
}

// claim records that an interpreter took responsibility for a field.  The
// flag it returns is what lets the comparison tell a wrong translation
// from a value we never claimed to translate.
func (ip *Interp) claim(what string) string {
	ip.st.Interp[what]++
	return "i"
}

func (ip *Interp) refuse(name string) string {
	ip.st.Refused[name]++
	return "-"
}

func (ip *Interp) TypeName(r *Record) string {
	n, _ := ip.TypeNameFlag(r)
	return n
}

// TypeNameFlag resolves the UNKNOWN[nnnn] spelling auditd writes for a
// record type its table does not name.  ausearch resolves it when
// interpreting and prints the name, so a reader that leaves it as a number
// disagrees on the one field every consumer keys off.
func (ip *Interp) TypeNameFlag(r *Record) (string, string) {
	if !ip.on {
		return r.Type, "-"
	}
	if n, ok := strings.CutPrefix(r.Type, "UNKNOWN["); ok {
		if n, ok2 := strings.CutSuffix(n, "]"); ok2 {
			if num, err := strconv.Atoi(n); err == nil {
				if name := auditTypeName[num]; name != "" {
					return name, ip.claim("@type")
				}
				// A number nothing names stays as it was written.
				return r.Type, ip.claim("@type")
			}
		}
	}
	return r.Type, ip.claim("@type")
}

// Time renders the record timestamp.  ausearch -i prints it in LOCAL
// time as MM/DD/YYYY HH:MM:SS.mmm, so the comparison runs under TZ=UTC
// where there is no ambiguous hour to map back through.
func (ip *Interp) Time(r *Record) (string, string) {
	if !ip.on {
		return fmt.Sprintf("%d.%03d", r.Secs, r.Millis), "-"
	}
	t := time.Unix(r.Secs, 0)
	return fmt.Sprintf("%s.%03d", t.Format("01/02/2006 15:04:05"), r.Millis),
		ip.claim("@time")
}

func (ip *Interp) Field(r *Record, f *Field) string {
	v, _ := ip.FieldFlag(r, f)
	return v
}

// uidFields and gidFields are the names ausearch resolves through the
// password and group files.  The list is not a guess: a record was written
// for every (record type, field name) pair in the corpus with a value only
// a resolver would change, and the ones that changed are these.
var uidFields = map[string]bool{
	"uid": true, "auid": true, "euid": true, "suid": true, "fsuid": true,
	"ouid": true, "oauid": true, "sauid": true, "iuid": true,
}

var gidFields = map[string]bool{
	"gid": true, "egid": true, "sgid": true, "fsgid": true,
	"ogid": true, "igid": true,
}

// FieldFlag returns the value and "i" if an interpreter claimed the field,
// "-" if none did.
func (ip *Interp) FieldFlag(r *Record, f *Field) (string, string) {
	raw := string(f.Value())
	if !ip.on {
		return raw, "-"
	}
	switch {
	case uidFields[f.Name]:
		return ip.id(raw, ip.passwd), ip.claim("uid")
	case gidFields[f.Name]:
		return ip.id(raw, ip.group), ip.claim("gid")
	case f.Name == "ses":
		// Only ses.  oses is the session of the object process in an
		// OBJ_PID record and ausearch leaves 4294967295 alone there,
		// which is inconsistent of it and is still what it does: the
		// first version of this mapped both and was wrong once in 13923
		// fields.
		if n, ok := parseU(raw); ok && n == unsetID {
			return "unset", ip.claim("ses")
		}
		return raw, ip.claim("ses")
	case f.Name == "arch":
		return archText(raw), ip.claim("arch")
	case f.Name == "syscall":
		return ip.syscall(r, raw), ip.claim("syscall")
	case len(f.Name) == 2 && f.Name[0] == 'a' && f.Name[1] >= '0' &&
		f.Name[1] <= '3' && (r.Type == "SYSCALL" || r.Type == "SECCOMP"):
		return ip.arg(r, f, int(f.Name[1]-'0'), raw)
	case f.Name == "proctitle":
		return proctitleText(decodeEscaped(f)), ip.claim("proctitle")
	case f.Name == "mode" && r.Type != "MQ_OPEN":
		return modeText(raw), ip.claim("mode")
	case f.Name == "sig":
		return sigText(raw), ip.claim("sig")
	case f.Name == "res":
		return resText(raw), ip.claim("res")
	case f.Name == "exit":
		return exitText(raw), ip.claim("exit")
	case capFields[f.Name]:
		return capText(raw), ip.claim("cap")
	case f.Name == "code" && r.Type == "SECCOMP":
		return seccompText(raw), ip.claim("seccomp-code")
	case f.Name == "family" && r.Type == "NETFILTER_CFG":
		return familyText(raw), ip.claim("family")
	case f.Name == "list":
		return listText(raw), ip.claim("list")
	case f.Name == "oflag":
		return flagsText(raw, openFlagName, "O_RDONLY", true), ip.claim("oflag")
	case f.Name == "flags" && r.Type == "MMAP":
		return mapFlagsText(raw), ip.claim("mapflags")
	case f.Name == "saddr" && r.Type == "SOCKADDR":
		return ip.saddr(f)
	case f.Name == "data":
		// Any record type, not only TTY.  ausearch renders data= as
		// keystrokes wherever it appears, measured on BPF, PATH and
		// USER_CMD records as well as TTY ones, and the type gate
		// that used to be here was a guess.  The fuzzer found it: it
		// puts field names into record types that never carry them,
		// which is the one thing a corpus written from real shapes
		// cannot do.
		//
		// Only a hex value is rendered.  data=ls comes back as ls and
		// not as "ls", data=(null) as (null), and data="ls -l" with
		// its quotes still on, because ausearch passes anything that
		// is not hex through untouched.  An empty value is (null),
		// which is what the kernel would have written.
		if len(f.Raw) == 0 {
			return "(null)", ip.claim("tty-data")
		}
		if !f.HexShaped() {
			return string(f.Raw), ip.claim("tty-data")
		}
		return ttyText(ttyBytes(f)), ip.claim("tty-data")
	case renderRefused[f.Name]:
		return raw, ip.refuse(f.Name)
	case escapedFields[f.Name]:
		return escapeText(decodeEscaped(f)), ip.claim("escaped")
	case isEscapedField(r, f):
		return escapeText(decodeEscaped(f)), ip.claim("execve-arg")
	case f.Sub != nil:
		return ip.nested(r, f), ip.claim("nested")
	}
	return raw, ip.refuse(f.Name)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// nested renders a single-quoted msg='...' with its inner fields
// interpreted.  The separators, any prose before the first inner field and
// the quotes themselves are the bytes that were in the log; only the
// values change.  A reader that treats the value as one opaque string
// disagrees with ausearch on every USER_CMD record, because the command
// line inside it is hex.
func (ip *Interp) nested(r *Record, f *Field) string {
	var b strings.Builder
	// SubPre and SubPost carry the quotes, because Unparse has to put the
	// line back together byte for byte.  Value() strips them from every
	// other encoding, so they come off here too and the two forms agree.
	pre, post := f.SubPre, f.SubPost
	if len(pre) > 0 && pre[0] == '\'' {
		pre = pre[1:]
	}
	if n := len(post); n > 0 && post[n-1] == '\'' {
		post = post[:n-1]
	}
	b.Write(pre)
	for i := range f.Sub {
		g := &f.Sub[i]
		b.Write(g.Pre)
		b.WriteString(g.Name)
		b.WriteByte('=')
		v, _ := ip.FieldFlag(r, g)
		b.WriteString(v)
	}
	b.Write(post)
	return b.String()
}

// id renders a uid or gid the way ausearch does: the login name, "unset"
// for (uid_t)-1, and unknown(N) for a number with no entry.  Not the
// number: a reader that falls back to printing the number agrees with
// ausearch on every account that exists and differs on every one that does
// not, which is the case that matters when reading someone else's log.
func (ip *Interp) id(raw string, tab map[uint64]string) string {
	n, ok := parseU(raw)
	if !ok {
		return raw
	}
	if n == unsetID {
		return "unset"
	}
	if name, ok := tab[n]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", n)
}

// parseOctal is strtoul(s, NULL, 8): leading octal digits, zero if there
// are none, and whatever follows is ignored.
func parseOctal(s string) uint64 {
	var n uint64
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '7'; i++ {
		n = n*8 + uint64(s[i]-'0')
	}
	return n
}

// parseU reads a decimal unsigned the way ausearch's strtoul does, which
// is to say it stops at the first byte that is not a digit rather than
// rejecting the value.
func parseU(s string) (uint64, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(s[:i], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// archText renders the AUDIT_ARCH_* value.  The field is hex without an
// 0x, and libaudit has a syscall table for only eleven of the fifty-three
// values the kernel headers define; the rest print as unknown-elf-type.
func archText(raw string) string {
	n, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return raw
	}
	if name, ok := archName[int(n)]; ok {
		return name
	}
	return fmt.Sprintf("unknown-elf-type(%08x)", n)
}

// archOf finds the arch a record declares, so that its syscall number can
// be read with the right table.  Syscall 102 is socketcall on i386 and
// getuid on x86_64; one table for both is wrong for every i386 record and
// looks right because the numbers all resolve to something.
func archOf(r *Record) (int, bool) {
	for i := range r.Fields {
		if r.Fields[i].Name == "arch" {
			n, err := strconv.ParseUint(string(r.Fields[i].Value()), 16, 64)
			if err != nil {
				return 0, false
			}
			return int(n), true
		}
	}
	return 0, false
}

func (ip *Interp) syscall(r *Record, raw string) string {
	nr, err := strconv.Atoi(raw)
	if err != nil {
		return raw
	}
	a, ok := archOf(r)
	if !ok {
		return raw
	}
	var tab map[int]string
	switch archName[a] {
	case "x86_64":
		tab = syscallX8664
	case "i386":
		tab = syscallI386
	default:
		// No table for this architecture.  Refusing here would be a lie
		// about which field was refused, so the number is printed the way
		// ausearch prints an unknown one.
		return fmt.Sprintf("unknown-syscall(%d)", nr)
	}
	name, ok := tab[nr]
	if !ok {
		return fmt.Sprintf("unknown-syscall(%d)", nr)
	}
	// i386's two multiplexers.  socketcall and ipc each carry many
	// calls on one syscall number, and ausearch folds the sub-call into
	// the syscall field rather than naming it in an argument:
	// socketcall(bind), ipc(semop).  When a0 is a number neither table
	// names, the bare name is printed and nothing is appended.
	var mux map[int]string
	switch name {
	case "socketcall":
		mux = socketCallMuxName
	case "ipc":
		mux = ipcCallName
	}
	if mux != nil {
		if a0, ok := ip.argValue(r, 0); ok {
			if sub, ok := mux[int(a0)]; ok {
				return name + "(" + sub + ")"
			}
		}
	}
	return name
}

// escapedFields are the field names whose value the kernel hex-encodes
// when it contains anything outside 0x21..0x7e, and which ausearch
// therefore decodes.  The list is not a guess and not read out of
// libaudit's source: t/escaped.py writes one record per (record type,
// field name) pair with a value of 5A71, asks ausearch, and keeps the
// pairs where Zq came back.  t/run.sh re-runs that probe and diffs it
// against this table, so a name that libaudit starts or stops decoding
// turns the suite red.
//
// a0..a3 are here for EXECVE only and are handled in FieldFlag: in a
// SYSCALL record the same names are syscall arguments and a number.
var escapedFields = map[string]bool{
	"acct": true, "cmd": true, "comm": true, "cwd": true, "exe": true,
	"data": true, "key": true, "name": true, "ocomm": true, "path": true,
	"proctitle": true, "root_dir": true, "sw": true,
}

// renderRefused are escaped fields auditp decodes but will not render,
// because ausearch renders them in a format of its own.  It is empty.
// TTY data was the only entry and tty.go renders it now; the map stays
// because the next such field will want it and because the branch it
// drives is the one that keeps decoding and rendering separate
// questions.
var renderRefused = map[string]bool{}

// capFields are the capability BITMASKS.  cap_fe is a one-bit effective
// flag and cap_fver a version number, both of which share the prefix and
// neither of which ausearch translates.  A prefix test on cap_ was wrong
// for 149 fields and right for 151, which is the sort of margin a prefix
// test gets you.
var capFields = map[string]bool{
	"cap_fp": true, "cap_fi": true,
	"cap_pi": true, "cap_pp": true, "cap_pe": true, "cap_pa": true,
}

// decodeField is the structural decode, with no rendering: the bytes the
// kernel put in the field.  Hex is decoded for a field the kernel encodes,
// quotes are removed, and nothing is escaped or truncated.  It is what the
// ground-truth comparison reads.
func decodeField(r *Record, f *Field) []byte {
	if isEscapedField(r, f) {
		return decodeEscaped(f)
	}
	return f.Value()
}

// isEscapedField is the one place the decode table is consulted, so that
// the census, the renderer and the ground-truth dump cannot disagree about
// what gets decoded.
func isEscapedField(r *Record, f *Field) bool {
	if escapedFields[f.Name] {
		return true
	}
	// a0..aN in EXECVE are the argument strings.  In SYSCALL the same
	// names are register values and a number.
	return r.Type == "EXECVE" && len(f.Name) >= 2 && f.Name[0] == 'a' &&
		isAllDigits(f.Name[1:])
}

// escapeText renders a decoded value the way ausearch does.  Measured, by
// writing one record per byte value 0x00..0xff into a hex-encoded name=
// and reading back what came out:
//
//	0x00         ends the string.  Not escaped, not skipped: truncated.
//	0x01..0x1f   printed as a backslash and three octal digits.
//	0x20..0xff   printed as themselves, including 0x7f and everything
//	             above 0x7f, so a value that is not valid UTF-8 comes
//	             out as the bytes that were in the log.
//
// All 256 were checked, not a sample: the interesting boundary turned out
// to be at 0x20 and at 0x7f, and only one of those is where a C
// programmer would have guessed.
func escapeText(b []byte) string {
	// One leading NUL is skipped rather than ending the string.  The
	// rest still ends at the next one, so 00 41 42 43 is ABC, 41 00 42
	// is A, and 00 00 41 is empty.  Measured over nine placements; it
	// is not a rule anyone would guess, and auditp printed nothing at
	// all for every value starting with a NUL until the fuzzer wrote
	// one.
	if len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	var out []byte
	for _, c := range b {
		switch {
		case c == 0:
			return string(out)
		case c < 0x20:
			out = append(out, '\\', '0'+(c>>6)&7, '0'+(c>>3)&7, '0'+c&7)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// decodeEscaped is the escaped-field path: hex-decode if the value is
// hex-shaped, then render.  A value that is not hex-shaped is already the
// text, and gets the same rendering, because a quoted value holding a tab
// is escaped by ausearch too even though the kernel would never write one.
func decodeEscaped(f *Field) []byte {
	if f.HexShaped() {
		b := f.HexDecode()
		// A value that decodes to one NUL byte is printed as the hex
		// it was written as: ausearch renders path=00 as the two
		// characters 00 and not as an empty value.  Anything longer
		// goes through the decoder.
		if len(b) == 1 && b[0] == 0 {
			return f.Value()
		}
		return b
	}
	return f.Value()
}

// proctitleText is the one escaped field where a NUL does not end the
// string.  The kernel stores argv with NUL between the arguments, and
// ausearch turns each into a space, so the value is a command line.  Every
// other field truncates at the first NUL; cmd= in a USER_CMD record was
// checked specifically, because it holds a command line too and does NOT
// do this.
func proctitleText(b []byte) string {
	// The leading-NUL rule applies here too and has to be applied
	// before the NULs become spaces, or the value comes out with a
	// space in front of it where ausearch has none.
	if len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	c := make([]byte, len(b))
	copy(c, b)
	for i := range c {
		if c[i] == 0 {
			c[i] = ' '
		}
	}
	return escapeText(c)
}

// --- the small enumerated fields -------------------------------------
//
// Each of these was established by asking ausearch, not by reading
// libaudit, and each table is cross-checked bit by bit or value by value
// in t/tables.py.  Where a rendering looks odd it is because ausearch's
// is odd; the two that are not copied are in t/known-diff.txt.

// modeText renders a st_mode.  file,644 / dir,755 / file,suid,755.  The
// file-type nibble has a name for the seven types that have one and is
// printed as three octal digits otherwise, which is why a mode of 0 comes
// out as 000,000 and not as an error.
func modeText(raw string) string {
	// strtoul semantics, base 8, and a value with no leading octal digits
	// is zero rather than an error.  LANDLOCK_DOMAIN carries mode=enforcing
	// and ausearch prints 000,000 for it: the field name decides the
	// interpreter, not the value, and libaudit does not look before it
	// parses.  Returning the string unchanged there was wrong once in
	// 14043 fields.
	n := parseOctal(raw)
	var b strings.Builder
	t := (n >> 12) & 0xF
	if name, ok := fileTypeName[t]; ok {
		b.WriteString(name)
	} else {
		fmt.Fprintf(&b, "%03o", t)
	}
	if n&04000 != 0 {
		b.WriteString(",suid")
	}
	if n&02000 != 0 {
		b.WriteString(",sgid")
	}
	if n&01000 != 0 {
		b.WriteString(",sticky")
	}
	fmt.Fprintf(&b, ",%03o", n&0777)
	return b.String()
}

var fileTypeName = map[uint64]string{
	001: "fifo", 002: "character", 004: "dir", 006: "block",
	010: "file", 012: "link", 014: "socket",
}

// sigText.  Signal 0 is SIG0, which is not a name anything but libaudit
// uses, and 32 upwards are unknown-signal(N) because libaudit's table
// stops at 31 while the kernel's does not.
func sigText(raw string) string {
	n, ok := parseU(raw)
	if !ok {
		return raw
	}
	if name, ok := signalName[int(n)]; ok {
		return name
	}
	return fmt.Sprintf("unknown-signal(%d)", n)
}

// resText.  0 is no, 1 is yes, any other number is unset, and a value
// that is not a number at all is left alone, which is how res=success
// survives.
func resText(raw string) string {
	n, ok := parseU(raw)
	if !ok {
		return raw
	}
	switch n {
	case 0:
		return "no"
	case 1:
		return "yes"
	}
	return "unset"
}

// exitText.  A negative exit is an errno: EACCES(Permission denied).  The
// words in the brackets are glibc's strerror under LC_ALL=C, baked into
// the table, because Go's own Errno.Error() lower-cases the first letter
// and would disagree on every one of the 131.
func exitText(raw string) string {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n >= 0 {
		return raw
	}
	e := -n
	name := errnoName[int(e)]
	if name == "" {
		name = "(null)"
	}
	text := errnoText[int(e)]
	if text == "" {
		text = fmt.Sprintf("Unknown error %d", e)
	}
	return name + "(" + text + ")"
}

// capText renders a capability bitmask as the names of its set bits, or
// "none" for zero.  The value is hex and has no 0x.
func capText(raw string) string {
	n, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return raw
	}
	if n == 0 {
		return "none"
	}
	var parts []string
	for b := 0; b < 64; b++ {
		if n&(1<<uint(b)) == 0 {
			continue
		}
		if name, ok := capName[b]; ok {
			parts = append(parts, name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// seccompText.  The action is the top half of the return value: the low
// 16 bits are data, and SECCOMP_RET_KILL_PROCESS is 0x80000000, which
// masks to zero, which is why ausearch calls it kill-thread.
func seccompText(raw string) string {
	n, err := strconv.ParseUint(strings.TrimPrefix(raw, "0x"), 16, 64)
	if err != nil {
		return raw
	}
	a := n & 0x7FFF0000
	if name, ok := seccompCode[int(a)]; ok {
		return name
	}
	// The UNMASKED value in the unknown case.  ausearch prints
	// unknown-seccomp-code(0xac052d01) where the masked form would be
	// 0x2c050000, so a renderer that reports what it looked up rather
	// than what it was given disagrees on every code outside the
	// table.  Found by the fuzzer; the corpus only ever held codes
	// that are in it.
	return fmt.Sprintf("unknown-seccomp-code(0x%x)", n)
}

// familyText is the NETFILTER protocol family, not the socket address
// family.  family=1 is inet here and AF_UNIX in sys/socket.h, and using
// the wrong table gives an answer for every value.
func familyText(raw string) string {
	n, ok := parseU(raw)
	if !ok {
		return raw
	}
	if name, ok := nfprotoName[int(n)]; ok {
		return name
	}
	return fmt.Sprintf("unknown-netfilter-protocol(%d)", n)
}

func listText(raw string) string {
	n, ok := parseU(raw)
	if !ok {
		return raw
	}
	if name, ok := filterListName[int(n)]; ok {
		return name
	}
	return fmt.Sprintf("unknown-list(%d)", n)
}

// mapFlagsText renders mmap flags.  MAP_FILE is the name of the absence
// of MAP_SHARED and MAP_PRIVATE rather than a bit of its own, so it is
// prepended when the low two bits are clear and omitted otherwise:
// 0x30 is MAP_FILE|MAP_FIXED|MAP_ANONYMOUS and 0x12 is
// MAP_PRIVATE|MAP_FIXED.  Worked out by asking ausearch for nine values
// including the ones with no bits and with an unnamed bit, because a
// table of single bits does not tell you this.
func mapFlagsText(raw string) string {
	n, err := strconv.ParseUint(strings.TrimPrefix(raw, "0x"), 16, 64)
	if err != nil {
		return raw
	}
	var parts []string
	if n&3 == 0 {
		parts = append(parts, "MAP_FILE")
	}
	for b := 0; b < 64; b++ {
		bit := uint64(1) << uint(b)
		if n&bit == 0 {
			continue
		}
		if name, ok := mapFlagName[int(bit)]; ok {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "|")
}

// flagsText renders a bit set as base|name|name.  ausearch always starts
// the list with the zero-valued base, O_RDONLY for open flags and
// MAP_FILE for mmap, even when other bits are set, and the access mode of
// an open flag word is the low two bits rather than a bit each.
func flagsText(raw string, tab map[int]string, base string, accmode bool) string {
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(raw,
		"0x"), "0X"), 16, 64)
	if err != nil {
		return raw
	}
	var parts []string
	if !accmode || n&3 == 0 {
		// The base is the name of the zero case and is printed only
		// when the low bits are zero.  For open flags that is
		// O_RDONLY, and ausearch prints oflag=0x40 as
		// O_RDONLY|O_CREAT.
		parts = []string{base}
	}
	// O_WRONLY and O_RDWR are ordinary bits in the table and are NOT an
	// access-mode enum.  ausearch prints oflag=3 as O_WRONLY|O_RDWR and
	// not as O_ACCMODE, which is wrong about the kernel and is what it
	// does; the first version here had the enum and disagreed on every
	// value whose low two bits are both set.  Found by the fuzzer: the
	// corpus had 0, 1, 2 and a dozen values above them and nothing with
	// 3, so the one case where the two readings differ was the one case
	// nobody wrote down.
	for b := 0; b < 64; b++ {
		bit := uint64(1) << uint(b)
		if n&bit == 0 {
			continue
		}
		if name, ok := tab[int(bit)]; ok {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "|")
}

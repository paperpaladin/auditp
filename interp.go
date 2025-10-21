package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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

func (ip *Interp) Time(r *Record) (string, string) {
	return fmt.Sprintf("%d.%03d", r.Secs, r.Millis), "-"
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
	case f.Name == "proctitle":
		return proctitleText(decodeEscaped(f)), ip.claim("proctitle")
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
	if name, ok := tab[nr]; ok {
		return name
	}
	return fmt.Sprintf("unknown-syscall(%d)", nr)
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
// because ausearch renders them in a format of its own that auditp does
// not implement.  TTY data is the only one: ausearch turns the keystrokes
// into "ls",<ret>,"\000", naming the control characters.  Decoding and
// rendering are separate questions and this is the field that shows why:
// the bytes come back correctly and the presentation is refused.
var renderRefused = map[string]bool{"data": true}

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
		return f.HexDecode()
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
	c := make([]byte, len(b))
	copy(c, b)
	for i := range c {
		if c[i] == 0 {
			c[i] = ' '
		}
	}
	return escapeText(c)
}

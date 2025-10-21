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
	}
	return raw, ip.refuse(f.Name)
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

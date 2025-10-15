package main

import (
	"bytes"
	"errors"
	"fmt"
)

// Encoding is how the kernel wrote a field's value.  The audit format has
// three of them and the choice is made per value, not per field: the same
// field is bare in one record, quoted in the next and hex in a third,
// depending on what bytes the value happens to contain.
type Encoding int

const (
	EncBare   Encoding = iota // pid=1684, nametype=PARENT, name=(null)
	EncQuoted                 // comm="gnome-shell"
	EncSingle                 // msg='op=PAM:authentication ...'
	EncEmpty                  // msg= at end of line, or followed by a space
)

// HexShaped reports whether a bare value could be a hex encoding: an even
// number of upper-case hex digits, at least two.  It is a question about
// the bytes and not about the field, and the answer is not sufficient.
// exit=60 and a2=3c are hex-shaped and are not hex-encoded; cmd= and
// proctitle= are.  Which field names the kernel hex-encodes is a table, and
// it lives in the interpreter, which is the layer allowed to refuse.
func (f *Field) HexShaped() bool {
	if f.Enc != EncBare || len(f.Raw) < 2 || len(f.Raw)%2 != 0 {
		return false
	}
	for _, c := range f.Raw {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// HexDecode decodes a hex-shaped value.  Callers have already established
// that the field is one the kernel encodes.
func (f *Field) HexDecode() []byte {
	out := make([]byte, len(f.Raw)/2)
	for i := range out {
		out[i] = hexval(f.Raw[2*i])<<4 | hexval(f.Raw[2*i+1])
	}
	return out
}

func hexval(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 0
}

func (e Encoding) String() string {
	switch e {
	case EncBare:
		return "bare"
	case EncQuoted:
		return "quoted"
	case EncSingle:
		return "single"
	case EncEmpty:
		return "empty"
	}
	return "?"
}

// Field is one name=value pair.  Pre is the bytes separating it from
// whatever came before, kept so that a record can be written back out byte
// for byte; a parser that cannot reproduce its input has lost something and
// does not know what.
type Field struct {
	Pre  []byte
	Name string
	Raw  []byte // exactly the bytes after '=', quotes and all
	Enc  Encoding
	Sub  []Field // fields inside a single-quoted msg='...'
	// SubPre and SubPost are the bytes of a single-quoted value that are not
	// part of any nested field: the quote, any prose prefix, the trailing
	// quote.  Same reason as Pre.
	SubPre  []byte
	SubPost []byte
}

// Value is the field's bytes with the quoting removed.  Hex is NOT decoded
// here: whether a hex-looking value is hex depends on the field name, and
// that decision belongs to the interpreter, which can also decline to make
// it.  See interp.go.
func (f *Field) Value() []byte {
	switch f.Enc {
	case EncQuoted, EncSingle:
		if len(f.Raw) >= 2 {
			return f.Raw[1 : len(f.Raw)-1]
		}
		return nil
	case EncEmpty:
		return nil
	}
	return f.Raw
}

// Record is one line of the log.
type Record struct {
	Line    int    // 1-based line number in the input
	Node    string // the node= prefix, empty when absent
	Type    string // as written: "SYSCALL", or "UNKNOWN[1100]"
	TypeNum int    // resolved number, -1 when the type is a name we do not know
	Secs    int64
	Millis  int
	Serial  uint64
	Prefix  []byte // bytes before the first field: AVC's "avc:  denied  { x } for  "
	Fields  []Field
	Suffix  []byte // bytes after the last field
	Raw     []byte // the whole line, without the newline
}

// Key is the (node, timestamp, serial) triple the kernel uses to say that
// two records belong to one event.
func (r *Record) Key() string {
	if r.Node != "" {
		return fmt.Sprintf("%s:%d.%03d:%d", r.Node, r.Secs, r.Millis, r.Serial)
	}
	return fmt.Sprintf("%d.%03d:%d", r.Secs, r.Millis, r.Serial)
}

var errNotRecord = errors.New("not an audit record")

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_' || c == '-'
}

// fieldAt reports the length of the field name starting at body[i], or 0 if
// no field starts there.  A field starts at the beginning of the body or
// after a space, its name begins with a letter, and the name is followed by
// '='.  The leading-letter rule is what keeps "{ read write }" and the
// numbers in AVC prose from being read as field names.
func fieldAt(body []byte, i int) int {
	if i > 0 && body[i-1] != ' ' {
		return 0
	}
	c := body[i]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return 0
	}
	j := i
	for j < len(body) && isNameByte(body[j]) {
		j++
	}
	if j >= len(body) || body[j] != '=' {
		return 0
	}
	return j - i
}

// scanValue returns the raw value bytes starting at body[i] and its
// encoding.  The three encodings are distinguished by the first byte;
// whether a bare value is really hex is a question about the field name and
// is not answered here.
func scanValue(body []byte, i int) ([]byte, Encoding) {
	if i >= len(body) || body[i] == ' ' {
		return nil, EncEmpty
	}
	switch body[i] {
	case '"':
		if j := bytes.IndexByte(body[i+1:], '"'); j >= 0 {
			return body[i : i+1+j+1], EncQuoted
		}
		// No closing quote.  The kernel does not emit this; a truncated
		// line does.  Take the rest and let the round-trip check see it.
		return body[i:], EncQuoted
	case '\'':
		if j := bytes.IndexByte(body[i+1:], '\''); j >= 0 {
			return body[i : i+1+j+1], EncSingle
		}
		return body[i:], EncSingle
	}
	j := bytes.IndexByte(body[i:], ' ')
	if j < 0 {
		return body[i:], EncBare
	}
	return body[i : i+j], EncBare
}

// splitFields walks a body and returns the prose prefix, the fields and the
// trailing bytes.  Concatenating prefix, each field's Pre + Name + "=" + Raw,
// and the suffix reproduces the body exactly.
func splitFields(body []byte) (prefix []byte, fields []Field, suffix []byte) {
	i := 0
	start := -1
	for i < len(body) {
		if n := fieldAt(body, i); n > 0 {
			start = i
			break
		}
		i++
	}
	if start < 0 {
		return body, nil, nil
	}
	prefix = body[:start]
	pre := []byte(nil)
	i = start
	for i < len(body) {
		n := fieldAt(body, i)
		if n == 0 {
			i++
			continue
		}
		name := string(body[i : i+n])
		raw, enc := scanValue(body, i+n+1)
		f := Field{Pre: pre, Name: name, Raw: raw, Enc: enc}
		fields = append(fields, f)
		i = i + n + 1 + len(raw)
		// Everything from here to the next field start is separator.
		sep := i
		for i < len(body) && fieldAt(body, i) == 0 {
			i++
		}
		if i < len(body) {
			pre = body[sep:i]
		} else {
			suffix = body[sep:]
		}
	}
	return prefix, fields, suffix
}

// parseSub fills in the nested field list of a single-quoted value.  A
// USER_CMD record's msg='cwd="/home/x" cmd=... exe="/usr/bin/sudo"' holds a
// whole second field list, and ausearch interprets the fields inside it, so
// a parser that treats the value as one opaque string cannot compare.
func parseSub(f *Field) {
	if f.Enc != EncSingle {
		return
	}
	inner := f.Value()
	pre, sub, post := splitFields(inner)
	if len(sub) == 0 {
		return
	}
	f.SubPre = append([]byte{'\''}, pre...)
	f.Sub = sub
	f.SubPost = append(append([]byte{}, post...), '\'')
}

// ParseLine parses one line of an audit log.  It returns errNotRecord for a
// line that is not one, which is a counted skip and not a failure: a real
// audit log picks up stray syslog lines and half-written records.
func ParseLine(line []byte, lineno int) (*Record, error) {
	r := &Record{Line: lineno, Raw: line, TypeNum: -1}
	b := line
	if bytes.HasPrefix(b, []byte("node=")) {
		j := bytes.IndexByte(b, ' ')
		if j < 0 {
			return nil, errNotRecord
		}
		r.Node = string(b[5:j])
		b = b[j+1:]
	}
	if !bytes.HasPrefix(b, []byte("type=")) {
		return nil, errNotRecord
	}
	b = b[5:]
	j := bytes.IndexByte(b, ' ')
	if j < 0 {
		return nil, errNotRecord
	}
	r.Type = string(b[:j])
	b = b[j+1:]
	if !bytes.HasPrefix(b, []byte("msg=audit(")) {
		return nil, errNotRecord
	}
	b = b[len("msg=audit("):]
	close := bytes.Index(b, []byte("):"))
	if close < 0 {
		return nil, errNotRecord
	}
	stamp := b[:close]
	b = b[close+2:]
	if err := parseStamp(stamp, r); err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0] == ' ' {
		b = b[1:]
		r.Prefix = []byte{' '}
	}
	pre, fields, suffix := splitFields(b)
	r.Prefix = append(r.Prefix, pre...)
	r.Fields = fields
	r.Suffix = suffix
	for i := range r.Fields {
		parseSub(&r.Fields[i])
	}
	return r, nil
}

// parseStamp reads SECS.MSEC:SERIAL.  The millisecond field is exactly three
// digits in everything the kernel writes, but it is parsed as "whatever is
// between the dot and the colon" so that a hand-written record with two
// digits is read rather than rejected; the count is kept so the writer can
// put back what it found.
func parseStamp(s []byte, r *Record) error {
	dot := bytes.IndexByte(s, '.')
	colon := bytes.LastIndexByte(s, ':')
	if dot < 0 || colon < 0 || colon < dot {
		return errNotRecord
	}
	secs, ok := atoiBytes(s[:dot])
	if !ok {
		return errNotRecord
	}
	ms, ok := atoiBytes(s[dot+1 : colon])
	if !ok {
		return errNotRecord
	}
	serial, ok := atoiBytes(s[colon+1:])
	if !ok {
		return errNotRecord
	}
	r.Secs = int64(secs)
	r.Millis = int(ms)
	r.Serial = uint64(serial)
	return nil
}

func atoiBytes(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 20 {
		return 0, false
	}
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}

// Unparse writes the record back out.  Byte-for-byte equality with the input
// line is asserted over the whole corpus by the suite: it is the one check
// that notices a field the splitter silently swallowed.
func (r *Record) Unparse() []byte {
	var b bytes.Buffer
	if r.Node != "" {
		b.WriteString("node=")
		b.WriteString(r.Node)
		b.WriteByte(' ')
	}
	fmt.Fprintf(&b, "type=%s msg=audit(%d.%03d:%d):", r.Type, r.Secs, r.Millis, r.Serial)
	b.Write(r.Prefix)
	for i := range r.Fields {
		f := &r.Fields[i]
		b.Write(f.Pre)
		b.WriteString(f.Name)
		b.WriteByte('=')
		if f.Sub != nil {
			b.Write(f.SubPre)
			for j := range f.Sub {
				g := &f.Sub[j]
				b.Write(g.Pre)
				b.WriteString(g.Name)
				b.WriteByte('=')
				b.Write(g.Raw)
			}
			b.Write(f.SubPost)
		} else {
			b.Write(f.Raw)
		}
	}
	b.Write(r.Suffix)
	return b.Bytes()
}

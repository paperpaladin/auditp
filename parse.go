package main

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// HexShaped reports whether a bare value could be a hex encoding: at
// least two hex digits and nothing else.  It is a question about the
// bytes and not about the field, and the answer is not sufficient.
// exit=60 and a2=3c are hex-shaped and are not hex-encoded; cmd= and
// proctitle= are.  Which field names the kernel hex-encodes is a table,
// and it lives in the interpreter, which is the layer allowed to refuse.
//
// Three details, all measured against ausearch rather than assumed, and
// all three wrong in the first version:
//
//	lower case counts.  The kernel writes upper case, and ausearch
//	decodes name=abcdef to three bytes all the same.  A reader that
//	insists on upper case leaves a value from any other producer
//	unreadable.
//
//	an odd number of digits counts.  ausearch decodes cmd=4142434 to
//	ABC@: three whole bytes and then the leftover nibble shifted up
//	into the high half of a fourth.  Not an error and not a truncation.
//
//	one digit does not count.  name=4 is the file called 4, and
//	name=12 is the single byte 0x12.  That is the format's ambiguity
//	and not a choice available to a reader: a two-character numeric
//	filename cannot be distinguished from a byte.
func (f *Field) HexShaped() bool {
	if f.Enc != EncBare || len(f.Raw) < 2 {
		return false
	}
	for _, c := range f.Raw {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' ||
			c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// HexDecode decodes a hex-shaped value.  Callers have already established
// that the field is one the kernel encodes.  A trailing odd nibble
// becomes the high half of a last byte, which is what ausearch does.
func (f *Field) HexDecode() []byte {
	out := make([]byte, (len(f.Raw)+1)/2)
	for i := range out {
		hi := hexval(f.Raw[2*i])
		var lo byte
		if 2*i+1 < len(f.Raw) {
			lo = hexval(f.Raw[2*i+1])
		}
		out[i] = hi<<4 | lo
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
	Line     int    // 1-based line number in the input
	Node     string // the node= prefix, empty when absent
	Type     string // as written: "SYSCALL", or "UNKNOWN[1100]"
	TypeNum  int    // resolved number, -1 when the type is a name we do not know
	Secs     int64
	Millis   int
	MsDigits int // digits between the dot and the colon, -1 when there was no dot
	Serial   uint64
	Prefix   []byte // bytes before the first field: AVC's "avc:  denied  { x } for  "
	Fields   []Field
	Suffix   []byte // bytes after the last field
	Raw      []byte // the whole line, without the newline
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

// typeNumberOf is auditTypeName the other way round, built once.  It is
// what turns a type name back into the number the grouping rule and the
// JSON form both need; TypeNum was -1 on every record until now and the
// JSON said so.
var typeNumberOf = func() map[string]int {
	m := make(map[string]int, len(auditTypeName))
	for n, name := range auditTypeName {
		if _, dup := m[name]; !dup {
			m[name] = n
		}
	}
	return m
}()

// typeNumber resolves "SYSCALL" to 1300 and the UNKNOWN[1100] spelling
// auditd writes for a type its own table does not name to 1100.
func typeNumber(typ string) int {
	if n, ok := typeNumberOf[typ]; ok {
		return n
	}
	if inner, ok := strings.CutPrefix(typ, "UNKNOWN["); ok {
		if inner, ok := strings.CutSuffix(inner, "]"); ok {
			if n, err := strconv.Atoi(inner); err == nil {
				return n
			}
		}
	}
	return -1
}

// endsEvent reports whether a record of this type closes the event it
// is in, so that the next record with the same key starts a new one.
// See eventEndRange in tables.go for how the set was measured.
func endsEvent(typeNum int) bool {
	for _, r := range eventEndRange {
		if typeNum >= r[0] && typeNum <= r[1] {
			return true
		}
	}
	return false
}

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
	r.TypeNum = typeNumber(r.Type)
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

// parseStamp reads SECS[.MSEC]:SERIAL.
//
// The fraction is a count of milliseconds and not a decimal fraction:
// ausearch prints audit(1700000000.1:11) as .001, so it is read with
// atoi and not scaled.  Three things here are ausearch's behaviour
// rather than a choice, each measured by handing it one record:
//
//	The dot and the fraction are optional.  audit(1700000000:7) is a
//	record with zero milliseconds.  auditp used to refuse it, which is
//	an over-refusal: the per-line comparison against ausearch on the
//	hostile corpus is what found it, after the corpus had been sitting
//	in the tree unread.
//
//	An empty fraction, audit(1700000000.:9), is also zero.
//
//	Four digits or more is refused.  ausearch reads at most three and
//	then wants the colon, so audit(1700000000.1234:14) is not a record
//	to it, and a reader that accepted it would assemble an event under
//	a key ausearch has no record for.
//
// MsDigits is how many digits were there, so Unparse can put back what
// it found rather than normalising to three.  The old comment claimed
// that and the writer hardcoded %03d, so a two-digit fraction did not
// round trip.
func parseStamp(s []byte, r *Record) error {
	colon := bytes.LastIndexByte(s, ':')
	if colon < 0 {
		return errNotRecord
	}
	dot := bytes.IndexByte(s[:colon], '.')
	secPart := s[:colon]
	var msPart []byte
	if dot >= 0 {
		secPart = s[:dot]
		msPart = s[dot+1 : colon]
		if len(msPart) > 3 {
			return errNotRecord
		}
	}
	secs, ok := atoiBytes(secPart)
	if !ok {
		return errNotRecord
	}
	ms := uint64(0)
	if len(msPart) > 0 {
		if ms, ok = atoiBytes(msPart); !ok {
			return errNotRecord
		}
	}
	serial, ok := atoiBytes(s[colon+1:])
	if !ok {
		return errNotRecord
	}
	r.Secs = int64(secs)
	r.Millis = int(ms)
	r.MsDigits = -1
	if dot >= 0 {
		r.MsDigits = len(msPart)
	}
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
	// The fraction goes back out with the number of digits it came in
	// with, and with no dot at all when there was none.  Normalising it
	// to three would break the round trip, which is the only check that
	// sees a byte the parser quietly dropped.
	fmt.Fprintf(&b, "type=%s msg=audit(%d", r.Type, r.Secs)
	if r.MsDigits >= 0 {
		b.WriteByte('.')
		if r.MsDigits > 0 {
			fmt.Fprintf(&b, "%0*d", r.MsDigits, r.Millis)
		}
	}
	fmt.Fprintf(&b, ":%d):", r.Serial)
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

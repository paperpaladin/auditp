package main

import (
	"fmt"
	"strings"
)

// ttyText renders a TTY record's data= field, which is a hex-encoded run
// of keystrokes.  ausearch prints it as a comma-separated mixture of
// quoted text and named keys:
//
//	data="ls -l /srv",<ret>
//	data="a",<up>,"b"
//
// Three rules, all measured by putting bytes to ausearch rather than
// read anywhere, because libaudit is not installed here in source form
// and no header names a key <page-up>:
//
//	28 single bytes have a name of their own, 0x01 to 0x1b and 0x7f.
//	0x1c to 0x1f do NOT, which no terminal manual would tell you: they
//	come out as octal inside the quoted text.
//
//	143 multi-byte sequences are named keys.  Two families of them:
//	ESC and the 8-bit introducers 0x80 to 0x9f, which libaudit knows
//	thirteen of.  What it consumes is not always what it matched:
//	ESC [ 9 ~ comes back as <delete> and then the text "~".  The table
//	is keyed by the bytes consumed, introducer included, for that
//	reason.
//
//	Text runs are quoted.  A double quote becomes \" and a backslash
//	\\; every byte outside 0x20..0x7e becomes a three-digit octal
//	escape, NUL included, so "hi\000there" is one run and not three.
//
// ttyBytes decodes a hex data= value the way the keystroke renderer
// does, which is not the way every other hex field is decoded: a
// trailing odd nibble is DROPPED here and kept as the high half of a
// last byte everywhere else.  data=6C7 is one keystroke to ausearch and
// two bytes to its own general decoder.
func ttyBytes(f *Field) []byte {
	out := make([]byte, len(f.Raw)/2)
	for i := range out {
		out[i] = hexval(f.Raw[2*i])<<4 | hexval(f.Raw[2*i+1])
	}
	return out
}

func ttyText(b []byte) string {
	var parts []string
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			parts = append(parts, `"`+text.String()+`"`)
			text.Reset()
		}
	}
	for i := 0; i < len(b); {
		c := b[i]
		if seq, name := ttyEscapeAt(b[i:]); name != "" {
			flush()
			parts = append(parts, name)
			i += len(seq)
			continue
		}
		if name, ok := ttyControlName[int(c)]; ok {
			flush()
			parts = append(parts, name)
			i++
			continue
		}
		switch {
		case c == '"':
			text.WriteString(`\"`)
		case c == '\\':
			text.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			text.WriteByte(c)
		default:
			fmt.Fprintf(&text, `\%03o`, c)
		}
		i++
	}
	flush()
	if len(parts) == 0 {
		// An empty data= field is (null) to ausearch, which is what the
		// kernel wrote in the first place for an empty one.
		return "(null)"
	}
	return strings.Join(parts, ",")
}

// ttyEscapeAt finds the longest sequence in the table that b begins
// with.  Longest and not first: ESC [ 1 and ESC [ 11 ~ are both in the
// table, and matching the shorter one would leave "1~" as text.
func ttyEscapeAt(b []byte) (string, string) {
	best, bestName := "", ""
	for seq, name := range ttyEscapeName {
		if len(seq) <= len(best) || len(seq) > len(b) {
			continue
		}
		if string(b[:len(seq)]) == seq {
			best, bestName = seq, name
		}
	}
	return best, bestName
}

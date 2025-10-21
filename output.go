package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

func writeUnparse(w io.Writer, events []*Event) {
	// In input order, not event order: the point of this form is to be
	// diffed against the input file.
	var all []*Record
	for _, ev := range events {
		all = append(all, ev.Records...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Line < all[j].Line })
	for _, r := range all {
		w.Write(r.Unparse())
		fmt.Fprintln(w)
	}
}

func writeText(w io.Writer, events []*Event, ip *Interp) {
	for _, ev := range events {
		fmt.Fprintf(w, "event %s (%d record%s)\n", ev.Key, len(ev.Records),
			plural(len(ev.Records)))
		for _, r := range ev.Records {
			fmt.Fprintf(w, "  %s", ip.TypeName(r))
			if len(r.Prefix) > 0 && string(r.Prefix) != " " {
				fmt.Fprintf(w, " [%s]", trimSpace(r.Prefix))
			}
			for i := range r.Fields {
				fmt.Fprintf(w, " %s=%s", r.Fields[i].Name, ip.Field(r, &r.Fields[i]))
			}
			fmt.Fprintln(w)
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func trimSpace(b []byte) string {
	i, j := 0, len(b)
	for i < j && b[i] == ' ' {
		i++
	}
	for j > i && b[j-1] == ' ' {
		j--
	}
	return string(b[i:j])
}

type jsonRecord struct {
	Type   string            `json:"type"`
	Num    int               `json:"type_num,omitempty"`
	Line   int               `json:"line"`
	Prefix string            `json:"prefix,omitempty"`
	Fields map[string]string `json:"fields"`
	Order  []string          `json:"order"`
}

type jsonEvent struct {
	Key     string       `json:"key"`
	Node    string       `json:"node,omitempty"`
	Secs    int64        `json:"secs"`
	Millis  int          `json:"millis"`
	Serial  uint64       `json:"serial"`
	Records []jsonRecord `json:"records"`
}

func writeJSON(w io.Writer, events []*Event, ip *Interp) {
	enc := json.NewEncoder(w)
	for _, ev := range events {
		je := jsonEvent{Key: ev.Key}
		if len(ev.Records) > 0 {
			r := ev.Records[0]
			je.Node, je.Secs, je.Millis, je.Serial = r.Node, r.Secs, r.Millis, r.Serial
		}
		for _, r := range ev.Records {
			jr := jsonRecord{
				Type:   ip.TypeName(r),
				Num:    r.TypeNum,
				Line:   r.Line,
				Prefix: trimSpace(r.Prefix),
				Fields: map[string]string{},
			}
			for i := range r.Fields {
				f := &r.Fields[i]
				// A repeated name would be lost in a map.  It is counted
				// in the census and suffixed here rather than dropped.
				name := f.Name
				for k := 2; ; k++ {
					if _, dup := jr.Fields[name]; !dup {
						break
					}
					name = fmt.Sprintf("%s#%d", f.Name, k)
				}
				jr.Fields[name] = ip.Field(r, f)
				jr.Order = append(jr.Order, name)
				for j := range f.Sub {
					g := &f.Sub[j]
					sub := f.Name + "." + g.Name
					jr.Fields[sub] = ip.Field(r, g)
					jr.Order = append(jr.Order, sub)
				}
			}
			je.Records = append(je.Records, jr)
		}
		enc.Encode(&je)
	}
}

// writeFlat is the form the oracle comparison reads.  One row per field:
//
//	EVENTKEY <TAB> RECORD-INDEX <TAB> FIELD <TAB> FLAG <TAB> VALUE
//
// The record index is the position within the event in input order.  FLAG is
// "i" when an interpreter claimed the field and "-" when none did, which is
// what lets the comparison separate a wrong answer from a refusal: a
// refusal that happens to match ausearch is still a refusal, and a
// translation that does not match is the only real failure.
//
// Three pseudo-fields carry what is not a field: @type is the record type,
// @time the timestamp, @prefix the prose an AVC record puts before its first
// field.  All three are things ausearch prints and so all three are
// comparable.
//
// A nested field inside a single-quoted msg='...' is named msg.NAME and is
// emitted after the msg row that contains it, so the comparison can be made
// at either granularity.
func writeFlat(w io.Writer, events []*Event, ip *Interp) {
	for _, ev := range events {
		for idx, r := range ev.Records {
			row := func(name, flag, val string) {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", ev.Key, idx, name, flag, val)
			}
			name, flag := ip.TypeNameFlag(r)
			row("@type", flag, name)
			ts, tflag := ip.Time(r)
			row("@time", tflag, ts)
			if len(r.Prefix) > 0 && string(r.Prefix) != " " {
				row("@prefix", "-", trimSpace(r.Prefix))
			}
			for i := range r.Fields {
				f := &r.Fields[i]
				v, fl := ip.FieldFlag(r, f)
				row(f.Name, fl, v)
				for j := range f.Sub {
					g := &f.Sub[j]
					v, fl := ip.FieldFlag(r, g)
					row(f.Name+"."+g.Name, fl, v)
				}
			}
		}
	}
}

// writeDecode emits the decoded bytes of every field, escaped the way
// t/gen.py escapes its ground-truth file.  This is the one comparison in
// the project that does not involve ausearch: it asks whether the decoder
// recovers the bytes that were encoded, against a file written by the
// thing that encoded them.  Agreeing with a second decoder and agreeing
// with the original are different claims, and the hex encoding exists
// precisely for bytes that both decoders might mangle the same way.
func writeDecode(w io.Writer, events []*Event) {
	for _, ev := range events {
		for idx, r := range ev.Records {
			for i := range r.Fields {
				f := &r.Fields[i]
				emitDecoded(w, ev.Key, idx, f.Name, decodeField(r, f))
				for j := range f.Sub {
					g := &f.Sub[j]
					emitDecoded(w, ev.Key, idx, f.Name+"."+g.Name,
						decodeField(r, g))
				}
			}
		}
	}
}

func emitDecoded(w io.Writer, key string, idx int, name string, val []byte) {
	fmt.Fprintf(w, "%s\t%d\t%s\t", key, idx, name)
	for _, c := range val {
		switch {
		case c == '\\':
			io.WriteString(w, "\\\\")
		case c == '\t':
			io.WriteString(w, "\\t")
		case c == '\n':
			io.WriteString(w, "\\n")
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(w, "\\x%02x", c)
		default:
			w.Write([]byte{c})
		}
	}
	fmt.Fprintln(w)
}

func writeCensus(w io.Writer, st *Stats) {
	fmt.Fprintf(w, "lines           %d\n", st.Lines)
	fmt.Fprintf(w, "records         %d\n", st.Records)
	fmt.Fprintf(w, "unparseable     %d\n", st.Unparseable)
	fmt.Fprintf(w, "events          %d\n", st.Events)
	fmt.Fprintf(w, "fields          %d\n", st.Fields)
	fmt.Fprintf(w, "subfields       %d\n", st.SubFields)
	fmt.Fprintf(w, "prose-prefixed  %d\n", st.Prefixed)
	fmt.Fprintf(w, "trailing-bytes  %d\n", st.Trailing)
	fmt.Fprintf(w, "duplicate-names %d\n", st.DupNames)
	for _, e := range []Encoding{EncBare, EncQuoted, EncSingle, EncEmpty} {
		fmt.Fprintf(w, "enc-%-11s %d\n", e, st.Enc[e])
	}
	fmt.Fprintf(w, "hex-shaped      %d\n", st.HexShaped)
	fmt.Fprintf(w, "distinct-types  %d\n", len(st.Types))
	fmt.Fprintf(w, "distinct-names  %d\n", len(st.Names))
	for _, n := range sortedKeys(st.EscapedPairs) {
		fmt.Fprintf(w, "escaped-pair %s\n", n)
	}
	dump(w, "type", st.Types)
	dump(w, "name", st.Names)
	dump(w, "interp", st.Interp)
	dump(w, "refused", st.Refused)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dump(w io.Writer, tag string, m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		fmt.Fprintf(w, "%s %s %d\n", tag, k, m[k])
	}
}

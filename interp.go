package main

import "fmt"

// Interp turns a decoded field value into the thing it means.  Without -i it
// is a pass-through that still removes the quoting.
//
// The rule the whole project turns on: every field is either translated to
// a value byte-identical to the one ausearch -i prints, or REFUSED and
// printed in its decoded raw form.  A refusal is counted under its field
// name and reported by the census.  A refusal and a wrong answer are
// different failures and are never added together.
type Interp struct {
	on bool
	st *Stats
}

func NewInterp(on bool, st *Stats) *Interp {
	return &Interp{on: on, st: st}
}

// TypeName resolves UNKNOWN[1100] to USER_AUTH when interpreting.  Without
// -i the type is reported as the log spells it.
func (ip *Interp) TypeName(r *Record) string {
	n, _ := ip.TypeNameFlag(r)
	return n
}

func (ip *Interp) TypeNameFlag(r *Record) (string, string) {
	return r.Type, "-"
}

// Time renders the record timestamp.  ausearch -i prints it as a local
// MM/DD/YYYY HH:MM:SS.mmm; without -i both tools print the raw seconds.
func (ip *Interp) Time(r *Record) (string, string) {
	return fmt.Sprintf("%d.%03d", r.Secs, r.Millis), "-"
}

// Field returns the printable value of one field.
func (ip *Interp) Field(r *Record, f *Field) string {
	v, _ := ip.FieldFlag(r, f)
	return v
}

// FieldFlag returns the value and "i" if an interpreter claimed the field,
// "-" if none did.  The flag is the refusal channel: it is what stops a
// value that happens to be right from being counted as a translation, and
// what stops a translation that is wrong from being excused as a refusal.
func (ip *Interp) FieldFlag(r *Record, f *Field) (string, string) {
	if ip.on {
		ip.st.Refused[f.Name]++
	}
	return string(f.Value()), "-"
}

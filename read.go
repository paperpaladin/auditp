package main

import (
	"bufio"
	"io"
	"os"
)

// Stats is the census: what the input actually contained.  It exists
// because a pass count says nothing about whether the code that passed was
// reached.  If the corpus holds no hex-encoded value then the hex decoder is
// untested however many fields agree.
type Stats struct {
	Lines       int
	Records     int
	Unparseable int
	Events      int
	Fields      int
	SubFields   int
	Prefixed    int // records with prose before the first field (AVC)
	Trailing    int // records with bytes after the last field
	DupNames    int // a field name occurring twice in one record
	HexShaped   int // bare values that are an even run of hex digits
	Enc         map[Encoding]int
	Types       map[string]int
	Names       map[string]int
	Interp      map[string]int // interpreter name -> fields it translated
	Refused     map[string]int // field name -> times no interpreter claimed it
}

func NewStats() *Stats {
	return &Stats{
		Enc:     map[Encoding]int{},
		Types:   map[string]int{},
		Names:   map[string]int{},
		Interp:  map[string]int{},
		Refused: map[string]int{},
	}
}

func (s *Stats) record(r *Record) {
	s.Records++
	s.Types[r.Type]++
	if len(r.Prefix) > 0 && string(r.Prefix) != " " {
		s.Prefixed++
	}
	if len(r.Suffix) > 0 {
		s.Trailing++
	}
	seen := map[string]bool{}
	for i := range r.Fields {
		f := &r.Fields[i]
		s.Fields++
		s.Enc[f.Enc]++
		if f.HexShaped() {
			s.HexShaped++
		}
		s.Names[f.Name]++
		if seen[f.Name] {
			s.DupNames++
		}
		seen[f.Name] = true
		for j := range f.Sub {
			s.SubFields++
			s.Enc[f.Sub[j].Enc]++
			if f.Sub[j].HexShaped() {
				s.HexShaped++
			}
			s.Names[f.Name+"."+f.Sub[j].Name]++
		}
	}
}

// Event is the records that share one (node, timestamp, serial) key, in the
// order the log holds them.
type Event struct {
	Key     string
	Records []*Record
}

// Read parses a whole log.  Events come out in order of first appearance of
// their key, and a record whose key has been seen is appended to that event
// however far away it is: the kernel interleaves records of concurrent
// events and a correlator that only looks at adjacent lines splits them.
func Read(rd io.Reader, st *Stats, strict bool) ([]*Event, error) {
	sc := bufio.NewScanner(rd)
	// An audit record can be long: EXECVE with many arguments, or a hex
	// proctitle.  64 KB is the kernel's own ceiling (MAX_AUDIT_MESSAGE_LENGTH
	// is 8970, but auditd concatenates), so 1 MB is slack and still bounded.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var events []*Event
	index := map[string]*Event{}
	for sc.Scan() {
		st.Lines++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		buf := make([]byte, len(line))
		copy(buf, line)
		r, err := ParseLine(buf, st.Lines)
		if err != nil {
			st.Unparseable++
			if strict {
				return nil, &LineError{Line: st.Lines, Err: err}
			}
			continue
		}
		st.record(r)
		k := r.Key()
		ev := index[k]
		if ev == nil {
			ev = &Event{Key: k}
			index[k] = ev
			events = append(events, ev)
			st.Events++
		}
		ev.Records = append(ev.Records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// LineError names the line, because "malformed input" without a line number
// is not a diagnostic.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string {
	return "line " + itoa(e.Line) + ": " + e.Err.Error()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func ReadFile(path string, st *Stats, strict bool) ([]*Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f, st, strict)
}

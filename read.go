package main

import (
	"bufio"
	"errors"
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
	Overlong    int // lines longer than maxLine, skipped and counted
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
	// EscapedPairs is "TYPE FIELD" for every pair in the input whose
	// value auditp hex-decodes.  The probe in t/escaped.py asks ausearch
	// the same question of the same pairs and the suite diffs the two,
	// so the decode table cannot drift from libaudit's unnoticed.
	EscapedPairs map[string]int
	Interp       map[string]int // interpreter name -> fields it translated
	Refused      map[string]int // field name -> times no interpreter claimed it
}

func NewStats() *Stats {
	return &Stats{
		Enc:          map[Encoding]int{},
		Types:        map[string]int{},
		Names:        map[string]int{},
		EscapedPairs: map[string]int{},
		Interp:       map[string]int{},
		Refused:      map[string]int{},
	}
}

func (s *Stats) record(r *Record) {
	s.recordFields(r)
}

func (s *Stats) recordFields(r *Record) {
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
		if isEscapedField(r, f) {
			s.EscapedPairs[r.Type+" "+f.Name]++
		}
		if seen[f.Name] {
			s.DupNames++
		}
		seen[f.Name] = true
		for j := range f.Sub {
			if isEscapedField(r, &f.Sub[j]) {
				s.EscapedPairs[r.Type+" "+f.Sub[j].Name]++
			}
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
	br := bufio.NewReaderSize(rd, 64*1024)
	var events []*Event
	index := map[string]*Event{}
	for {
		line, over, err := readLine(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		st.Lines++
		// A line too long for the buffer is skipped and counted, not
		// a reason to abandon the file.  bufio.Scanner's answer was to
		// return ErrTooLong and stop, so one 2 MB line cost every
		// record after it; ausearch reads those records and the
		// truncation sweep is what noticed.
		if over {
			st.Overlong++
			st.Unparseable++
			if strict {
				return nil, &LineError{Line: st.Lines,
					Err: errLineTooLong}
			}
			continue
		}
		if len(line) == 0 {
			continue
		}
		r, err := ParseLine(line, st.Lines)
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
	return events, nil
}

// maxLine bounds one record.  An audit record can be long: an EXECVE
// with many arguments, or a hex proctitle.  The kernel's own ceiling is
// MAX_AUDIT_MESSAGE_LENGTH, 8970 bytes, but auditd concatenates
// continuation records, so 1 MB is slack and is still a bound.  An input
// that is one 500 MB line is a denial of service and not a log.
const maxLine = 1 << 20

var errLineTooLong = errors.New("line longer than 1 MB")

// readLine returns the next line without its newline, and whether it was
// over maxLine, in which case the bytes are discarded and the caller
// counts it.  The returned slice is freshly allocated: Record keeps it.
func readLine(br *bufio.Reader) ([]byte, bool, error) {
	var buf []byte
	over := false
	for {
		chunk, err := br.ReadSlice('\n')
		if over || len(buf)+len(chunk) > maxLine {
			over = true
		} else {
			buf = append(buf, chunk...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && (len(buf) > 0 || over) {
				return trimNewline(buf), over, nil
			}
			return nil, over, err
		}
		return trimNewline(buf), over, nil
	}
}

// trimNewline takes off the newline and nothing else.  bufio.Scanner's
// ScanLines also drops a carriage return before it; auditd does not write
// one, and if something else did, dropping it would put a byte in the
// input that the round trip cannot put back.
func trimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return b
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

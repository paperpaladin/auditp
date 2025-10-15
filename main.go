// auditp: a Linux kernel audit log parser and event correlator.
//
// The audit subsystem splits one logical event across several records that
// share a (node, timestamp, serial) key, encodes a field value in one of
// three ways depending on what bytes it contains, and leaves the syscall
// argument fields a0-a3 meaningless without knowing which syscall they
// belong to.  auditp reassembles, decodes and interprets.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

const usage = `usage: auditp [-i] [-o text|json|flat|census|unparse] [-strict] FILE

  -i         interpret field values (syscall names, uids, modes, flags)
  -o FORM    output form:
               text     one block per event, one line per record (default)
               json     one JSON object per event, one per line
               flat     one tab-separated row per field, for comparison
               census   what the input contained, per construct
               unparse  the parsed records written back out; byte for byte
                        identical to the input if nothing was lost
  -strict    exit 1 on a line that cannot be parsed, instead of counting it

exit 0 clean, 1 unreadable input or (with -strict) a malformed line,
2 usage error.
`

func main() {
	fs := flag.NewFlagSet("auditp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	interp := fs.Bool("i", false, "interpret field values")
	form := fs.String("o", "text", "output form")
	strict := fs.Bool("strict", false, "exit 1 on an unparseable line")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	switch *form {
	case "text", "json", "flat", "census", "unparse":
	default:
		fmt.Fprintf(os.Stderr, "auditp: unknown output form %q\n", *form)
		os.Exit(2)
	}

	st := NewStats()
	events, err := ReadFile(fs.Arg(0), st, *strict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auditp: %v\n", err)
		os.Exit(1)
	}

	out := bufio.NewWriterSize(os.Stdout, 256*1024)
	ip := NewInterp(*interp, st)
	switch *form {
	case "text":
		writeText(out, events, ip)
	case "json":
		writeJSON(out, events, ip)
	case "flat":
		writeFlat(out, events, ip)
	case "unparse":
		writeUnparse(out, events)
	case "census":
		if *interp {
			// Fire every interpreter so the census can report what each
			// one claimed and what it refused.  Without this the refusal
			// counts would all be zero and look like success.
			writeFlat(nopWriter{}, events, ip)
		}
		writeCensus(out, st)
	}
	out.Flush()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

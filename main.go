// auditp: a Linux kernel audit log parser and event correlator.
//
// The audit subsystem splits one logical event across several records that
// share a (node, timestamp, serial) key, encodes a field value in one of
// three ways depending on what bytes it contains, and leaves the syscall
// argument fields a0-a3 meaningless without knowing which syscall they
// belong to. auditp reassembles, decodes and interprets.
package main

import (
	"flag"
	"fmt"
	"os"
)

const usage = `usage: auditp [-i] [-o text|json|flat|census] [-strict] FILE

  -i         interpret field values (syscall names, uids, modes, flags)
  -o FORM    output form: text (default), json, flat, census
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
	_ = interp
	_ = form
	_ = strict
	fmt.Fprintln(os.Stderr, "auditp: not implemented yet")
	os.Exit(1)
}

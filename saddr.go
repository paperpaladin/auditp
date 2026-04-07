package main

import (
	"bytes"
	"fmt"
	"strings"
)

// saddr renders the packed sockaddr a SOCKADDR record carries as hex.
//
// Everything in this file is measured, by handing ausearch one record per
// case and reading what it printed; libaudit's source is not installed
// here and the uapi headers say nothing about the rendering, only about
// the structures.  t/saddr.py puts the same values to both sides every
// run, so the shapes below cannot drift from ausearch unnoticed.  The
// README says this is one source and not two.
//
// Four families are rendered and three are refused.  ax25 (3), atmpvc (8)
// and x25 (9) carry a raw byte string that ausearch octal-escapes, and
// for ax25 shorter than 9 bytes it emits "call=" and then no closing
// brace at all, which is a defect in a format this project has to parse.
// None of the three can appear in a record from this machine.  Refusing
// is the honest answer and it is counted under saddr/NAME.
func (ip *Interp) saddr(f *Field) (string, string) {
	b := f.HexDecode()
	if f.Enc != EncBare || !f.HexShaped() || len(b) < 2 {
		return string(f.Value()), ip.refuse("saddr")
	}
	fam := int(b[0]) | int(b[1])<<8
	name, named := sockFamilyName[fam]
	switch fam {
	case 1: // AF_UNIX
		switch {
		case len(b) == 2:
			return "{ saddr_fam=local unnamed socket }", ip.claim("saddr-local")
		case len(b) < 4:
			return "{ saddr_fam=local sockaddr len too short }", ip.claim("saddr-short")
		}
		p := b[2:]
		// An abstract socket's name starts after a leading NUL, and
		// ausearch steps over exactly one before printing the rest as a
		// C string.  A sockaddr_un of all zeroes therefore prints an
		// empty path rather than "unnamed socket".
		if p[0] == 0 {
			p = p[1:]
		}
		if i := bytes.IndexByte(p, 0); i >= 0 {
			p = p[:i]
		}
		return "{ saddr_fam=local path=" + string(p) + " }", ip.claim("saddr-local")
	case 2: // AF_INET
		if len(b) < 16 {
			return "{ saddr_fam=inet sockaddr len too short }", ip.claim("saddr-short")
		}
		return fmt.Sprintf("{ saddr_fam=inet laddr=%d.%d.%d.%d lport=%d }",
			b[4], b[5], b[6], b[7], int(b[2])<<8|int(b[3])), ip.claim("saddr-inet")
	case 10: // AF_INET6
		if len(b) < 28 {
			return "{ saddr_fam=inet6 sockaddr6 len too short }", ip.claim("saddr-short")
		}
		scope := uint32(b[24]) | uint32(b[25])<<8 | uint32(b[26])<<16 | uint32(b[27])<<24
		addr := inet6Text(b[8:24])
		if scope != 0 {
			addr = fmt.Sprintf("%s%%%d", addr, scope)
		}
		return fmt.Sprintf("{ saddr_fam=inet6 laddr=%s lport=%d }",
			addr, int(b[2])<<8|int(b[3])), ip.claim("saddr-inet6")
	case 16: // AF_NETLINK
		if len(b) < 12 {
			return "{ saddr_fam=netlink len too short }", ip.claim("saddr-short")
		}
		pid := uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24
		return fmt.Sprintf("{ saddr_fam=netlink nlnk-fam=%d nlnk-pid=%d }",
			fam, pid), ip.claim("saddr-netlink")
	case 3, 8, 9:
		return string(f.Value()), ip.refuse("saddr/" + name)
	}
	if !named {
		return fmt.Sprintf("unknown-family(%d)", fam), ip.claim("saddr-unknown")
	}
	return "{ saddr_fam=" + name + " (unsupported) }", ip.claim("saddr-unsupported")
}

// inet6Text is inet_ntop(AF_INET6) and not Go's net.IP.String().  Two
// implementations of "print an IPv6 address" agree on almost everything
// and the suite found both of the places they do not, by putting 89
// sockaddrs to ausearch and diffing:
//
//	Go prints an IPv4-mapped address as a bare dotted quad, 1.2.3.4,
//	where inet_ntop prints ::ffff:1.2.3.4.
//
//	inet_ntop also prints ::1.2.3.4 for the deprecated IPv4-compatible
//	form, which Go spells ::102:304.
//
// The tail is therefore printed as a dotted quad under the same three
// conditions glibc uses, which are about the zero run and not about the
// address class: the run starts at the first group, and it is six long,
// or seven long with a last group that is not 1, or five long with
// 0xffff after it.  The rest is RFC 5952: lower case, the longest run
// of two or more zero groups replaced by ::, the leftmost run on a tie.
func inet6Text(a []byte) string {
	var g [8]int
	for i := range g {
		g[i] = int(a[2*i])<<8 | int(a[2*i+1])
	}
	best, bestLen, cur, curLen := -1, 0, -1, 0
	for i := 0; i < 8; i++ {
		if g[i] == 0 {
			if cur < 0 {
				cur, curLen = i, 0
			}
			curLen++
			if curLen > bestLen {
				best, bestLen = cur, curLen
			}
		} else {
			cur, curLen = -1, 0
		}
	}
	if bestLen < 2 {
		best, bestLen = -1, 0
	}
	quad := best == 0 && (bestLen == 6 ||
		(bestLen == 7 && g[7] != 1) ||
		(bestLen == 5 && g[5] == 0xffff))
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == best {
			b.WriteString("::")
			i += bestLen - 1
			continue
		}
		if i > 0 && !(best >= 0 && i == best+bestLen) {
			b.WriteByte(':')
		}
		if quad && i == 6 {
			fmt.Fprintf(&b, "%d.%d.%d.%d", a[12], a[13], a[14], a[15])
			break
		}
		fmt.Fprintf(&b, "%x", g[i])
	}
	return b.String()
}

package main

import (
	"strconv"
	"time"
	"unicode/utf8"
)

// timeText writes a time in nanoseconds since the Unix epoch in UTC to the
// millisecond, as "2006-01-02T15:04:05.000Z". Lines come in runs within one
// second, so the text up to the second is kept and formatted again only when
// the second changes.
type timeText struct {
	sec    int64
	prefix []byte
}

func (t *timeText) append(b []byte, ns int64) []byte {
	sec, frac := ns/1e9, ns%1e9
	if frac < 0 {
		sec, frac = sec-1, frac+1e9
	}
	if len(t.prefix) == 0 || sec != t.sec {
		t.sec = sec
		t.prefix = time.Unix(sec, 0).UTC().AppendFormat(t.prefix[:0], "2006-01-02T15:04:05.")
	}
	ms := frac / 1e6
	b = append(b, t.prefix...)
	return append(b, byte('0'+ms/100), byte('0'+ms/10%10), byte('0'+ms%10), 'Z')
}

// appendRecord appends r as one line of the recording, at ns nanoseconds
// since the Unix epoch. It writes what encoding/json writes for r with "t"
// first, field for field, except that a name the step chose keeps a byte that
// is not UTF-8 (see appendString).
func appendRecord(b []byte, r *record, t *timeText, ns int64) []byte {
	b = append(b, `{"t":"`...)
	b = t.append(b, ns)
	b = append(b, `","kind":`...)
	b = appendString(b, r.Kind, false)
	b = append(b, `,"pid":`...)
	b = strconv.AppendUint(b, uint64(r.PID), 10)
	b = append(b, `,"ppid":`...)
	b = strconv.AppendUint(b, uint64(r.PPID), 10)
	b = append(b, `,"comm":`...)
	b = appendString(b, r.Comm, true)
	b = appendName(b, `,"program":`, r.Program)
	b = appendName(b, `,"path":`, r.Path)
	b = appendName(b, `,"name":`, r.Name)
	b = appendName(b, `,"to":`, r.To)
	b = appendName(b, `,"to_name":`, r.ToName)
	if r.Access != "" {
		b = appendString(append(b, `,"access":`...), r.Access, false)
	}
	if r.Flags != 0 {
		b = strconv.AppendUint(append(b, `,"flags":`...), uint64(r.Flags), 10)
	}
	if r.Mode != "" {
		b = appendString(append(b, `,"mode":`...), r.Mode, false)
	}
	if r.Owner != "" {
		b = appendString(append(b, `,"owner":`...), r.Owner, false)
	}
	if r.Err != 0 {
		b = strconv.AppendInt(append(b, `,"err":`...), int64(r.Err), 10)
	}
	b = appendTrue(b, `,"failed":`, r.Failed)
	b = appendTrue(b, `,"image":`, r.Image)
	b = appendTrue(b, `,"memfd":`, r.Memfd)
	b = appendTrue(b, `,"deleted":`, r.Deleted)
	b = appendTrue(b, `,"exchange":`, r.Exchange)
	if r.Syscall != "" {
		b = appendString(append(b, `,"syscall":`...), r.Syscall, false)
	}
	b = appendTrue(b, `,"compat":`, r.Compat)
	b = appendTrue(b, `,"killed":`, r.Killed)
	return append(b, "}\n"...)
}

// appendName appends an omitempty name field.
func appendName(b []byte, key, name string) []byte {
	if name == "" {
		return b
	}
	return appendString(append(b, key...), name, true)
}

// appendTrue appends an omitempty bool field.
func appendTrue(b []byte, key string, v bool) []byte {
	if !v {
		return b
	}
	return append(append(b, key...), "true"...)
}

const hexDigits = "0123456789abcdef"

// jsonPlain marks the ASCII bytes appendString copies as they are.
var jsonPlain = func() (t [utf8.RuneSelf]bool) {
	for c := 0x20; c < utf8.RuneSelf; c++ {
		t[c] = c != '"' && c != '\\' && c != '<' && c != '>' && c != '&'
	}
	return t
}()

// appendString appends s quoted as encoding/json quotes it, HTML characters
// and U+2028/U+2029 escaped. A byte that is not part of valid UTF-8 becomes
// U+FFFD, or for a name the step chose (raw), the escaped lone surrogate
// U+DC00 plus the byte, as Python's surrogateescape writes it, so the name can be restored
// exactly and no two names read alike.
func appendString(b []byte, s string, raw bool) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if jsonPlain[c] {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '\\', '"':
				b = append(b, '\\', c)
			case '\b':
				b = append(b, '\\', 'b')
			case '\f':
				b = append(b, '\\', 'f')
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b = append(b, s[start:i]...)
			if raw {
				b = append(b, '\\', 'u', 'd', 'c', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				b = utf8.AppendRune(b, utf8.RuneError)
			}
		case r == '\u2028' || r == '\u2029':
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
		default:
			i += size
			continue
		}
		i += size
		start = i
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

package main

import (
	"strconv"
	"time"
	"unicode/utf8"
)

// record is one line of the JSON output. Kind is the action; Path (and To,
// for the two-path operations) name the target; Access carries the open or
// mmap flags as letters; Failed and Err describe an operation that did not
// succeed. The tags name each field as appendRecord writes it, which the
// tests check against encoding/json.
type record struct {
	Kind string `json:"kind"`
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	Path string `json:"path,omitempty"`
	// Name is the name the command passed, where Path is not that name as
	// written: the file an exec resolved to, or a passed name joined to its
	// directory. ToName is the same for To.
	Name   string `json:"name,omitempty"`
	To     string `json:"to,omitempty"`
	ToName string `json:"to_name,omitempty"`
	Access string `json:"access,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`
	// Mode is a chmod's new mode in octal, and Owner a chown's new uid:gid.
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Err    int32  `json:"err,omitempty"`
	Failed bool   `json:"failed,omitempty"`
	// Image marks a mapping the kernel made while starting a program: the
	// program itself, its dynamic loader, or a script's interpreter.
	Image bool `json:"image,omitempty"`
	// Memfd marks a memfd, whose Path is "memfd:" and the name its creator
	// chose; Deleted a file unlinked while in use, or an O_TMPFILE.
	Memfd   bool `json:"memfd,omitempty"`
	Deleted bool `json:"deleted,omitempty"`
	// Exchange marks a rename that swapped Path and To (RENAME_EXCHANGE).
	Exchange bool `json:"exchange,omitempty"`
	// Syscall names a refused syscall, or gives its number where the tracer
	// has no name for it; Compat marks one of the 32-bit ABI, and Killed one
	// seccomp killed the program for.
	Syscall string `json:"syscall,omitempty"`
	Compat  bool   `json:"compat,omitempty"`
	Killed  bool   `json:"killed,omitempty"`
	// boot is the event's CLOCK_BOOTTIME stamp in nanoseconds; the line's
	// "t" is its wall-clock time.
	boot uint64
	// tid and nr are the thread and syscall an event was sent from. A
	// result has its return value in ret, RESULT_* in bits, and a failed
	// open's base directory in Path when hasBase. caller and cut mark an
	// open-name read from the caller, and cut short.
	tid     uint32
	nr      int32
	ret     int32
	bits    uint8
	hasBase bool
	caller  bool
	cut     bool
}

const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// appendRecord appends r as one line of the recording, at the wall-clock
// time at. It writes what encoding/json writes for r with "t" first, field
// for field, except that a name the step chose keeps a byte that is not UTF-8
// (see appendString).
func appendRecord(b []byte, r *record, at time.Time) []byte {
	b = append(b, `{"t":"`...)
	b = at.AppendFormat(b, timeLayout)
	b = append(b, `","kind":`...)
	b = appendString(b, r.Kind, false)
	b = append(b, `,"pid":`...)
	b = strconv.AppendUint(b, uint64(r.PID), 10)
	b = append(b, `,"ppid":`...)
	b = strconv.AppendUint(b, uint64(r.PPID), 10)
	b = append(b, `,"comm":`...)
	b = appendString(b, r.Comm, true)
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
			if c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
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

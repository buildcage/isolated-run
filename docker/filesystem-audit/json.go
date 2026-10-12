package main

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// record is one line of the JSON output. Kind is the action; Path (and To,
// for the two-path operations) name the target; Access carries the open or
// mmap flags as letters; Failed and Err describe an operation that did not
// succeed.
type record struct {
	Time string `json:"t"`
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
	// boot is the event's CLOCK_BOOTTIME stamp in nanoseconds; the reader
	// turns it into Time.
	boot uint64
}

// MarshalJSON writes record as encoding/json would, except that a name the
// step chose keeps a byte that is not UTF-8 (see rawName) rather than having
// it turned into U+FFFD.
func (r record) MarshalJSON() ([]byte, error) {
	type plain record // without this method
	if utf8.ValidString(r.Comm) && utf8.ValidString(r.Path) && utf8.ValidString(r.Name) &&
		utf8.ValidString(r.To) && utf8.ValidString(r.ToName) {
		return json.Marshal(plain(r))
	}
	return json.Marshal(struct {
		Time     string  `json:"t"`
		Kind     string  `json:"kind"`
		PID      uint32  `json:"pid"`
		PPID     uint32  `json:"ppid"`
		Comm     rawName `json:"comm"`
		Path     rawName `json:"path,omitempty"`
		Name     rawName `json:"name,omitempty"`
		To       rawName `json:"to,omitempty"`
		ToName   rawName `json:"to_name,omitempty"`
		Access   string  `json:"access,omitempty"`
		Flags    uint32  `json:"flags,omitempty"`
		Mode     string  `json:"mode,omitempty"`
		Owner    string  `json:"owner,omitempty"`
		Err      int32   `json:"err,omitempty"`
		Failed   bool    `json:"failed,omitempty"`
		Image    bool    `json:"image,omitempty"`
		Memfd    bool    `json:"memfd,omitempty"`
		Deleted  bool    `json:"deleted,omitempty"`
		Exchange bool    `json:"exchange,omitempty"`
		Syscall  string  `json:"syscall,omitempty"`
		Compat   bool    `json:"compat,omitempty"`
		Killed   bool    `json:"killed,omitempty"`
	}{r.Time, r.Kind, r.PID, r.PPID, rawName(r.Comm), rawName(r.Path), rawName(r.Name),
		rawName(r.To), rawName(r.ToName), r.Access, r.Flags, r.Mode, r.Owner, r.Err,
		r.Failed, r.Image, r.Memfd, r.Deleted, r.Exchange, r.Syscall, r.Compat, r.Killed})
}

// rawName is a file or process name as the kernel holds it: bytes, not
// necessarily UTF-8. Each byte that is not part of valid UTF-8 is written as
// the lone surrogate U+DC00 plus the byte, as Python's surrogateescape does,
// so the name can be restored exactly and no two names read alike.
type rawName string

func (n rawName) MarshalJSON() ([]byte, error) {
	s := string(n)
	out := []byte{'"'}
	for len(s) > 0 {
		valid := 0
		for valid < len(s) {
			r, size := utf8.DecodeRuneInString(s[valid:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			valid += size
		}
		if valid > 0 {
			q, err := json.Marshal(s[:valid])
			if err != nil {
				return nil, err
			}
			out = append(out, q[1:len(q)-1]...)
			s = s[valid:]
			continue
		}
		out = fmt.Appendf(out, `\udc%02x`, s[0])
		s = s[1:]
	}
	return append(out, '"'), nil
}

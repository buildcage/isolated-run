package main

import (
	"bytes"
	"strings"
)

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// components joins n NUL-terminated names stored leaf first into an absolute
// path, and returns the bytes left after them. A truncated walk is marked
// with a leading ellipsis.
func components(b []byte, n int, truncated bool) (string, []byte) {
	prefix := "/"
	if truncated {
		prefix = "…/"
	}
	// Leaf first; fewer than n if the buffer ran out. Each is located first,
	// so the path is built root first in one allocation.
	var buf [32][2]int
	spans := buf[:0]
	off, size := 0, len(prefix)
	for i := 0; i < n && off < len(b); i++ {
		j := bytes.IndexByte(b[off:], 0)
		if j < 0 {
			j = len(b) - off
		}
		spans = append(spans, [2]int{off, off + j})
		size += j + 1
		off += j
		if off < len(b) {
			off++
		}
	}
	var p strings.Builder
	p.Grow(size)
	p.WriteString(prefix)
	for i := len(spans) - 1; i >= 0; i-- {
		p.Write(b[spans[i][0]:spans[i][1]])
		if i > 0 {
			p.WriteByte('/')
		}
	}
	return p.String(), b[off:]
}

// after returns what follows a NUL-terminated name of length n, or nothing
// when the sample ends first.
func after(b []byte, n int) []byte {
	if n+1 > len(b) {
		return nil
	}
	return b[n+1:]
}

// joinBase prefixes a relative name with the base directory the BPF side
// walked for it, whose n components lead rest; has says one was walked. It
// joins them as they are: cleaning "dir/link/.." would drop a symlink the
// kernel followed, and the name's own spelling is part of what it records.
func joinBase(name string, rest []byte, has bool, n int, truncated bool) (string, []byte) {
	if !has {
		return name, rest
	}
	base, rest := components(rest, n, truncated)
	if name == "" { // futimens, fchmod: the descriptor's own path
		return base, rest
	}
	return strings.TrimSuffix(base, "/") + "/" + name, rest
}

// tidy drops the spellings that never change where a path leads: a "."
// segment or a repeated slash before the last name. A trailing "/" or "/."
// stays, since it makes the kernel follow a final symlink, and ".." stays,
// since through a symlink it leads somewhere a lexical clean would not.
func tidy(p string) string {
	if !untidy(p) {
		return p
	}
	parts := strings.Split(p, "/")
	kept := make([]string, 0, len(parts))
	for i, part := range parts {
		last := i == len(parts)-1
		if !last && i > 0 && (part == "." || part == "") {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "/")
}

// untidy reports whether p holds "//" or "/./".
func untidy(p string) bool {
	for i := 0; i+1 < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		if p[i+1] == '/' || p[i+1] == '.' && i+2 < len(p) && p[i+2] == '/' {
			return true
		}
	}
	return false
}

// filePath decodes an open, read or write's path: the d_path string, or the
// dentry components walked for one too long for it (n > 0); with neither,
// only the errno.
func filePath(data []byte, pathRet int32, n int, truncated bool) (string, int32) {
	if pathRet >= 0 {
		return cstr(data), 0
	}
	if n > 0 {
		p, _ := components(data, n, truncated)
		return p, 0
	}
	return "", pathRet
}

// passedName returns the name the command passed, for Name or ToName, when
// it differs from the path recorded for it.
func passedName(name, p string) string {
	if name == p {
		return ""
	}
	return name
}

// passed decodes a name the command passed, followed by its base directory if
// any, into its tidied path and, where that differs, the name itself.
func passed(data []byte, has bool, n int, truncated bool) (string, string) {
	name := cstr(data)
	p, _ := joinBase(name, after(data, len(name)), has, n, truncated)
	p = tidy(p)
	return p, passedName(name, p)
}

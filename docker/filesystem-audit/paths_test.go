package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestTidy(t *testing.T) {
	for in, want := range map[string]string{
		"/a/./b//c":       "/a/b/c",
		"/a/l/../b":       "/a/l/../b",
		"/work/l/":        "/work/l/",
		"/work/./l/.":     "/work/l/.",
		"/":               "/",
		".":               ".",
		"":                "",
		"x":               "x",
		"…/deep/./x":      "…/deep/x",
		"/var/tmp/b/../x": "/var/tmp/b/../x",
		"/.hidden/x":      "/.hidden/x",
		"a//":             "a/",
		"/a/.":            "/a/.",
		"/a/./":           "/a/",
		"//":              "/",
	} {
		if got := tidy(in); got != want {
			t.Errorf("tidy(%q) = %q, want %q", in, got, want)
		}
	}
}

// joinComponents is components written plainly, which it must match.
func joinComponents(b []byte, n int, truncated bool) (string, []byte) {
	var names []string
	for i := 0; i < n && len(b) > 0; i++ {
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			j = len(b)
		}
		names = append([]string{string(b[:j])}, names...)
		if j < len(b) {
			j++
		}
		b = b[j:]
	}
	prefix := "/"
	if truncated {
		prefix = "…/"
	}
	return prefix + strings.Join(names, "/"), b
}

func TestComponents(t *testing.T) {
	for _, c := range []struct {
		data      string
		n         int
		truncated bool
		want      string
		rest      string
	}{
		{"c\x00b\x00a\x00", 3, false, "/a/b/c", ""},
		{"c\x00b\x00a\x00x", 2, false, "/b/c", "a\x00x"},
		{"c\x00b", 3, false, "/b/c", ""},
		{"c\x00\x00a\x00", 3, true, "…/a//c", ""},
		{"", 2, false, "/", ""},
		{"c\x00", 0, false, "/", "c\x00"},
	} {
		got, rest := components([]byte(c.data), c.n, c.truncated)
		if got != c.want || string(rest) != c.rest {
			t.Errorf("components(%q, %d) = %q, %q; want %q, %q", c.data, c.n, got, rest, c.want, c.rest)
		}
	}
}

func FuzzComponents(f *testing.F) {
	f.Add([]byte("c\x00b\x00a"), 2, false)
	f.Add([]byte("\x00\x00x\x00"), 40, true)
	f.Fuzz(func(t *testing.T, b []byte, n int, truncated bool) {
		got, rest := components(b, n, truncated)
		want, wantRest := joinComponents(b, n, truncated)
		if got != want || !bytes.Equal(rest, wantRest) {
			t.Fatalf("components(%q, %d) = %q, %q; want %q, %q", b, n, got, rest, want, wantRest)
		}
	})
}

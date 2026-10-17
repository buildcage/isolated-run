package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAccessLetters(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{openAccess(unix.O_RDONLY, 0), "r"},
		{openAccess(unix.O_RDWR|unix.O_CREAT|unix.O_TRUNC, 0), "rwct"},
		{openAccess(unix.O_RDONLY, fmodeExec), "rx"},
		{mmapAccess(unix.PROT_WRITE, unix.MAP_SHARED), "w"},
		{mmapAccess(unix.PROT_WRITE, unix.MAP_PRIVATE), "r"},
		{mmapAccess(unix.PROT_EXEC, 0), "x"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

package main

import (
	"strings"
	"testing"
)

// x86_64 has every syscall the program watches, so each nr_ constant is set,
// as is native_arch.
func TestEverySyscallNumberIsSetOnAmd64(t *testing.T) {
	for name := range loadSpec(t).Variables {
		if _, ok := syscallNumbers[name]; (strings.HasPrefix(name, "nr_") || name == "native_arch") && !ok {
			t.Errorf("%s is not set", name)
		}
	}
}

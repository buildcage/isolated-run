package main

import (
	"strings"
	"testing"
)

// x86_64 has every syscall the program watches, so each nr_ constant is set.
func TestEverySyscallNumberIsSetOnAmd64(t *testing.T) {
	spec, err := loadFilesystemAudit()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Variables {
		if _, ok := syscallNumbers[name]; strings.HasPrefix(name, "nr_") && !ok {
			t.Errorf("%s is not set", name)
		}
	}
}

package main

import (
	"testing"

	"github.com/cilium/ebpf"
)

func loadSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := loadFilesystemAudit()
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestSetSyscallNumbersNamesOnlyTheProgramsConstants(t *testing.T) {
	if err := setSyscallNumbers(loadSpec(t)); err != nil {
		t.Fatal(err)
	}
}

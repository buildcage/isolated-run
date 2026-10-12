package main

import "testing"

func TestSetSyscallNumbersNamesOnlyTheProgramsConstants(t *testing.T) {
	spec, err := loadFilesystemAudit()
	if err != nil {
		t.Fatal(err)
	}
	if err := setSyscallNumbers(spec); err != nil {
		t.Fatal(err)
	}
}

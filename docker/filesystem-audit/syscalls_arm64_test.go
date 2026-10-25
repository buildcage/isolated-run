package main

import (
	"strings"
	"testing"
)

// The syscalls arm64 lacks, whose nr_ constants stay at -1 so no call matches.
var absentOnArm64 = map[string]bool{
	"nr_unlink": true, "nr_rmdir": true, "nr_rename": true, "nr_chmod": true, "nr_chown": true,
	"nr_lchown": true, "nr_futimesat": true, "nr_utime": true, "nr_utimes": true, "nr_mkdir": true,
	"nr_mknod": true, "nr_symlink": true, "nr_link": true, "nr_open": true, "nr_creat": true,
}

func TestEverySyscallNumberArm64HasIsSet(t *testing.T) {
	vars := loadSpec(t).Variables
	for name := range vars {
		if !strings.HasPrefix(name, "nr_") && name != "native_arch" {
			continue
		}
		if _, set := syscallNumbers[name]; set == absentOnArm64[name] {
			t.Errorf("%s: set %v, listed as absent %v", name, set, absentOnArm64[name])
		}
	}
	for name := range absentOnArm64 {
		if _, ok := vars[name]; !ok {
			t.Errorf("%s is listed as absent but the program has no such constant", name)
		}
	}
}

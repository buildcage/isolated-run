package main

import (
	"testing"
)

func TestExecFilesAttach(t *testing.T) {
	files := execFiles{}
	if !files.attach(&record{Kind: "exec-file", PID: 9, Path: "/work/A/gradlew"}) {
		t.Fatal("an exec-file record should be dropped")
	}
	other := record{Kind: "exec", PID: 7, Path: "/usr/bin/env"}
	if files.attach(&other) || other.Path != "/usr/bin/env" || other.Name != "" {
		t.Fatalf("an exec with no resolved file changed: %+v", other)
	}
	exec := record{Kind: "exec", PID: 9, Path: "./gradlew"}
	if files.attach(&exec) {
		t.Fatal("an exec record should be kept")
	}
	if exec.Path != "/work/A/gradlew" || exec.Name != "./gradlew" {
		t.Fatalf("exec = %+v, want the resolved path with the name it was run by", exec)
	}
	if _, left := files[9]; left {
		t.Fatal("the resolved file should be used once")
	}
	if files.attach(&record{Kind: "read", PID: 9, Path: "/etc/hosts"}) {
		t.Fatal("other records should be kept")
	}
	files.attach(&record{Kind: "exec-file", PID: 9, Path: "memfd:x", Memfd: true})
	memfd := record{Kind: "exec", PID: 9, Path: "/dev/fd/3"}
	files.attach(&memfd)
	if memfd.Path != "memfd:x" || !memfd.Memfd || memfd.Name != "/dev/fd/3" {
		t.Fatalf("exec = %+v, want the memfd it ran", memfd)
	}
}

func TestExecFilesDropsAFailedExecsFile(t *testing.T) {
	files := execFiles{}
	files.attach(&record{Kind: "exec-file", PID: 9, Path: "/work/noshebang"})
	files.attach(&record{Kind: "exec-file", PID: 9, Path: "/usr/bin/make"})
	retry := record{Kind: "exec", PID: 9, Path: "make"}
	files.attach(&retry)
	if retry.Path != "/usr/bin/make" {
		t.Fatalf("exec = %+v, want the file of its own attempt", retry)
	}

	files.attach(&record{Kind: "exec-file", PID: 9, Path: "/work/noshebang"})
	if files.attach(&record{Kind: "fork", PID: 9, PPID: 7}) {
		t.Fatal("a fork record should be kept")
	}
	if _, left := files[9]; left {
		t.Fatal("a reused pid should not keep the file of the exited process")
	}
	reused := record{Kind: "exec", PID: 9, Path: "./build"}
	files.attach(&reused)
	if reused.Path != "./build" || reused.Name != "" {
		t.Fatalf("exec = %+v, want it left under the name it was run by", reused)
	}
}

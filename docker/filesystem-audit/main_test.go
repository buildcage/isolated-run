package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRunRefusesAnActionAlreadyGone(t *testing.T) {
	if fd, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
		t.Skip("pidfd_open unavailable:", err)
	} else {
		unix.Close(fd)
	}
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")
	// Above the kernel's pid_max ceiling (2^22), so no process has it.
	err := run(filepath.Join(dir, "cgroup"), filepath.Join(dir, "out"), "", pidfile, 1<<30, "")
	if err == nil || err.Error() != "the action that started it has already exited" {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(pidfile); !os.IsNotExist(err) {
		t.Fatal("wrote a pidfile for a tracer that never started")
	}
}

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateRefusesALinkOrAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if _, err := create(link); err == nil {
		t.Fatal("create followed a symlink")
	}
	if _, err := create(victim); err == nil {
		t.Fatal("create opened a file already there")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("victim now holds %q", b)
	}
}

func TestWriteNewIsReadableWhateverTheUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pid")
	if err := writeNew(path, []byte("42\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644", st.Mode().Perm())
	}
}

func TestStopOnExit(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	if err := stopOnExit(child.Process.Pid, sig); err != nil {
		t.Skip("pidfd_open unavailable:", err)
	}
	select {
	case <-sig:
		t.Fatal("stopped while the process is alive")
	case <-time.After(100 * time.Millisecond):
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	select {
	case <-sig:
	case <-time.After(5 * time.Second):
		t.Fatal("not stopped after the process exited")
	}
}

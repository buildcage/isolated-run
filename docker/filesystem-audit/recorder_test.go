package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newTestRecorder records to out and logs to log, at a fixed clock offset.
func newTestRecorder() (r *recorder, out, log *bytes.Buffer) {
	out, log = &bytes.Buffer{}, &bytes.Buffer{}
	return newRecorder(bufio.NewWriter(out), log, func() (int64, error) { return 0, nil }), out, log
}

// lines decodes each line of the recording.
func lines(t *testing.T, out *bytes.Buffer) []map[string]any {
	t.Helper()
	var got []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		got = append(got, m)
	}
	return got
}

func add(t *testing.T, r *recorder, events ...event) {
	t.Helper()
	for _, e := range events {
		if err := r.add(e.bytes()); err != nil {
			t.Fatal(err)
		}
	}
}

var (
	runcOpen = event{kind: 1, pid: 5, comm: "runc", flags: unix.O_RDONLY, data: []byte("/etc/passwd\x00")}
	stepExec = event{kind: 2, pid: 9, comm: "sh", data: []byte("/bin/sh\x00")}
	stepOpen = event{kind: 1, pid: 9, comm: "sh", flags: unix.O_RDONLY, data: []byte("/etc/hosts\x00")}
)

func TestRecorderDropsWhatComesBeforeTheFirstExec(t *testing.T) {
	r, out, log := newTestRecorder()
	add(t, r, runcOpen, runcOpen, stepExec, stepOpen)
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	if len(got) != 3 || got[0]["kind"] != "exec" || got[1]["path"] != "/etc/hosts" || got[2]["kind"] != "end" {
		t.Fatalf("recording = %v, want the exec, the step's open and the end line", got)
	}
	if !strings.Contains(log.String(), "total=2 ") || !strings.Contains(log.String(), "pre-exec-skipped=2 ") {
		t.Fatalf("log = %q, want two written and two skipped", log)
	}
}

func TestRecorderGivesAnExecTheFileItResolvedTo(t *testing.T) {
	r, out, _ := newTestRecorder()
	add(t, r,
		event{kind: 23, pid: 9, comm: "sh", n1: 3, data: comps("gradlew", "A", "work")},
		event{kind: 2, pid: 9, comm: "sh", data: []byte("./gradlew\x00")},
	)
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	if len(got) != 2 || got[0]["path"] != "/work/A/gradlew" || got[0]["name"] != "./gradlew" {
		t.Fatalf("recording = %v, want the exec under its resolved path, and no exec-file line", got)
	}
}

func TestRecorderStopsAtAClockItCannotRead(t *testing.T) {
	out := &bytes.Buffer{}
	broken := errors.New("no clock")
	r := newRecorder(bufio.NewWriter(out), &bytes.Buffer{}, func() (int64, error) { return 0, broken })
	if err := r.add(runcOpen.bytes()); err != nil {
		t.Fatalf("a dropped event read the clock: %v", err)
	}
	if err := r.add(stepExec.bytes()); !errors.Is(err, broken) {
		t.Fatalf("add = %v, want the clock's error", err)
	}
}

func TestRecorderLeavesOutTheEndLineWithoutEveryCount(t *testing.T) {
	for name, l := range map[string]loss{
		"dropped":     {errDropped: errors.New("x")},
		"untracked":   {errUntracked: errors.New("x")},
		"open named":  {errNamed: errors.New("x")},
		"open unheld": {errUnheld: errors.New("x")},
		"host missed": {missed: count{err: errors.New("x")}},
	} {
		t.Run(name, func(t *testing.T) {
			r, out, log := newTestRecorder()
			add(t, r, stepExec)
			if err := r.finish(l); err != nil {
				t.Fatal(err)
			}
			if got := lines(t, out); len(got) != 1 || got[0]["kind"] != "exec" {
				t.Fatalf("recording = %v, want the exec alone", got)
			}
			if !strings.Contains(log.String(), "read loss counters") {
				t.Fatalf("log = %q, want the counter that could not be read", log)
			}
		})
	}
}

func TestRecorderCountsUnheldOpensUntrackedWhenNoOpenWasNamed(t *testing.T) {
	for _, c := range []struct {
		name      string
		l         loss
		untracked float64
	}{
		{"none named", loss{untracked: 1, unheld: 3}, 4},
		{"some named", loss{untracked: 1, named: 2, unheld: 3}, 1},
		{"named unreadable", loss{untracked: 1, unheld: 3, errNamed: errors.New("x")}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, out, log := newTestRecorder()
			if err := r.finish(c.l); err != nil {
				t.Fatal(err)
			}
			got := lines(t, out)
			if !strings.Contains(log.String(), fmt.Sprintf(" untracked=%v ", c.untracked)) {
				t.Fatalf("log = %q, want untracked %v", log, c.untracked)
			}
			// An unreadable counter leaves the end line out.
			if c.l.errNamed == nil && (len(got) != 1 || got[0]["untracked"] != c.untracked) {
				t.Fatalf("recording = %v, want untracked %v", got, c.untracked)
			}
			warned := strings.Contains(log.String(), "no open passed do_filp_open")
			if warned != (c.untracked == 4) {
				t.Fatalf("log = %q", log)
			}
		})
	}
}

func TestWallTime(t *testing.T) {
	// 1.5 s after boot, with boot at 2026-10-06T00:00:00Z.
	offset := int64(1_791_244_800) * 1_000_000_000
	if got, want := wallTime(1_500_000_000, offset), "2026-10-06T00:00:01.500Z"; got != want {
		t.Fatalf("wallTime = %s, want %s", got, want)
	}
}

func TestBootOffset(t *testing.T) {
	off, err := bootOffset()
	if err != nil {
		t.Fatal(err)
	}
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, wallTime(uint64(boot.Nano()), off))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Fatalf("boot time now converts to %s, %s from the wall clock", got, d)
	}
}

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

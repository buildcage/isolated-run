package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// newTestRecorder records to out and logs to log, at a fixed clock offset.
func newTestRecorder() (r *recorder, out, log *bytes.Buffer) {
	out, log = &bytes.Buffer{}, &bytes.Buffer{}
	return newRecorder(bufio.NewWriter(out), log, func(uint64) int64 { return 0 }), out, log
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
	runcOpen = event{kind: filesystemAuditKindK_OPEN, pid: 5, comm: "runc", flags: unix.O_RDONLY, data: []byte("/etc/passwd\x00")}
	stepExec = event{kind: filesystemAuditKindK_EXEC, pid: 9, comm: "sh", data: []byte("/bin/sh\x00")}
	stepOpen = event{kind: filesystemAuditKindK_OPEN, pid: 9, comm: "sh", flags: unix.O_RDONLY, data: []byte("/etc/hosts\x00")}
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
	if !strings.Contains(log.String(), "total=2 ") || !strings.Contains(log.String(), "pre-exec-skipped=2\n") {
		t.Fatalf("log = %q, want two written and two skipped", log)
	}
}

// Each line's "t" is its boot stamp plus the offset at that stamp.
func TestRecorderTimesALineByItsOffset(t *testing.T) {
	out := &bytes.Buffer{}
	r := newRecorder(bufio.NewWriter(out), &bytes.Buffer{}, func(boot uint64) int64 {
		if boot < 2e9 {
			return 1_791_244_800e9
		}
		return 1_791_244_900e9
	})
	exec, open := stepExec, stepOpen
	exec.boot, open.boot = 1_500_000_000, 2_250_000_000
	add(t, r, exec, open)
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	if got[0]["t"] != "2026-10-06T00:00:01.500Z" || got[1]["t"] != "2026-10-06T00:01:42.250Z" {
		t.Fatalf("times = %v, %v", got[0]["t"], got[1]["t"])
	}
}

func TestRecorderGivesAnExecTheFileItResolvedTo(t *testing.T) {
	r, out, _ := newTestRecorder()
	add(t, r,
		event{kind: filesystemAuditKindK_EXEC_FILE, pid: 9, comm: "sh", n1: 3, data: comps("gradlew", "A", "work")},
		event{kind: filesystemAuditKindK_EXEC, pid: 9, comm: "sh", data: []byte("./gradlew\x00")},
	)
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	if len(got) != 2 || got[0]["path"] != "/work/A/gradlew" || got[0]["name"] != "./gradlew" {
		t.Fatalf("recording = %v, want the exec under its resolved path, and no exec-file line", got)
	}
}

// The tracer reads each sample into the same buffer, so nothing a line keeps
// may point into it.
func TestRecorderKeepsNothingOfASample(t *testing.T) {
	r, out, _ := newTestRecorder()
	raw := event{kind: filesystemAuditKindK_EXEC_FILE, pid: 9, comm: "sh", n1: 3, data: comps("gradlew", "A", "work")}.bytes()
	add(t, r, stepExec)
	if err := r.add(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	add(t, r, event{kind: filesystemAuditKindK_EXEC, pid: 9, comm: "sh", data: []byte("./gradlew\x00")})
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	if got := lines(t, out); got[1]["path"] != "/work/A/gradlew" {
		t.Fatalf("recording = %v, want the exec under the path read before the buffer changed", got)
	}
}

// waitingOpen is an open recorded at its file whose call's result follows.
func waitingOpen(tid uint32, path string) event {
	return event{kind: filesystemAuditKindK_OPEN, pid: 9, comm: "sh", flags: unix.O_RDONLY, tid: tid, data: []byte(path + "\x00")}
}

// openName is the name an open(2) passed, as getname copied it.
func openName(tid uint32, name string) event {
	return event{kind: filesystemAuditKindK_OPEN_NAME, pid: 9, comm: "sh", tid: tid, data: []byte(name + "\x00")}
}

const (
	nrOpenat = 257
	nrUnlink = 87
	nrFchmod = 91
	nrBind   = 49
)

func openResult(tid uint32, ret int32) event {
	return result(tid, nrOpenat, resultOpen, ret)
}

func result(tid uint32, nr int32, bits uint8, ret int32) event {
	return event{kind: filesystemAuditKindK_RESULT, pid: 9, comm: "sh", tid: tid, nr: nr, n1: bits, pathRet: ret}
}

// unlink is a path change its hook sent from syscall nr.
func unlink(tid uint32, nr int32, path string) event {
	return event{kind: filesystemAuditKindK_UNLINK, pid: 9, comm: "rm", tid: tid, nr: nr, n1: 1, data: comps(path)}
}

// paths gives each line's path and err, the end line's as empty.
func paths(t *testing.T, out *bytes.Buffer) string {
	t.Helper()
	var got []string
	for _, l := range lines(t, out) {
		p, _ := l["path"].(string)
		e, _ := l["err"].(float64)
		got = append(got, fmt.Sprintf("%s:%v", p, e))
	}
	return strings.Join(got, " ")
}

// recordEvents runs events through a recorder after the step's exec and returns its
// lines' paths and its end line's untracked count.
func recordEvents(t *testing.T, events ...event) (string, any) {
	t.Helper()
	r, out, _ := newTestRecorder()
	add(t, r, stepExec)
	add(t, r, events...)
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	return paths(t, out), got[len(got)-1]["untracked"]
}

func TestRecorderSettlesAnOpenWithItsResult(t *testing.T) {
	got, untracked := recordEvents(t,
		openName(11, "/tmp/fifo"), waitingOpen(11, "/tmp/fifo"),
		openName(12, "/tmp/refused"), waitingOpen(12, "/tmp/refused"),
		openResult(12, -int32(unix.ENXIO)), openResult(11, 3),
		openName(13, "/tmp/new"), event{kind: filesystemAuditKindK_OPEN_CREATE, tid: 13}, waitingOpen(13, "/tmp/new"),
		openResult(13, -int32(unix.EACCES)),
		openResult(14, 0),                         // no open waits for it
		openName(15, "/opath"), openResult(15, 3), // O_PATH reaches no security_file_open
	)
	want := fmt.Sprintf("/bin/sh:0 /tmp/refused:%d /tmp/fifo:0 /tmp/new:0 /tmp/new:%d :0", unix.ENXIO, unix.EACCES)
	if got != want || untracked != float64(0) {
		t.Fatalf("recording = %s, untracked %v, want %s", got, untracked, want)
	}
}

// A create mark whose call sent no name ends with that call.
func TestRecorderDropsTheCreateMarkOfACallWithNoName(t *testing.T) {
	got, _ := recordEvents(t, event{kind: filesystemAuditKindK_OPEN_CREATE, tid: 11}, openResult(11, -int32(unix.EEXIST)),
		openName(11, "/f"), waitingOpen(11, "/f"), openResult(11, -int32(unix.EACCES)))
	if want := fmt.Sprintf("/bin/sh:0 /f:%d :0", unix.EACCES); got != want {
		t.Fatalf("recording = %s, want %s", got, want)
	}
}

func TestRecorderRecordsAnOpenThatFailedBeforeItsFile(t *testing.T) {
	got, _ := recordEvents(t, openName(11, "/missing"), openResult(11, -int32(unix.ENOENT)),
		openName(11, "/etc/hosts"), waitingOpen(11, "/etc/hosts"), openResult(11, 3))
	if want := fmt.Sprintf("/bin/sh:0 /missing:%d /etc/hosts:0 :0", unix.ENOENT); got != want {
		t.Fatalf("recording = %s, want %s", got, want)
	}
}

// A name the kernel copied gives way to none read from the caller.
func TestRecorderKeepsTheKernelsCopyOfAName(t *testing.T) {
	caller := openName(11, "/from-caller")
	caller.n1 = 1
	ret := -int32(unix.ENAMETOOLONG)
	got, _ := recordEvents(t, openName(11, "/kernel"), caller, openResult(11, ret), caller, openResult(11, ret))
	if want := fmt.Sprintf("/bin/sh:0 /kernel:%d /from-caller:%d :0", -ret, -ret); got != want {
		t.Fatalf("recording = %s, want %s", got, want)
	}
}

func TestRecorderDropsARestartedOpen(t *testing.T) {
	got, _ := recordEvents(t, openName(11, "/tmp/fifo"), waitingOpen(11, "/tmp/fifo"), openResult(11, -512),
		openName(11, "/tmp/missing"), openResult(11, -513),
		openName(11, "/tmp/fifo"), waitingOpen(11, "/tmp/fifo"), openResult(11, 3))
	if got != "/bin/sh:0 /tmp/fifo:0 :0" {
		t.Fatalf("recording = %s, want the rerun's open alone", got)
	}
}

// A second file before the call's result is one nested in the open, written
// as done at once.
func TestRecorderTakesTheFirstFileAsTheOpens(t *testing.T) {
	got, _ := recordEvents(t, openName(11, "/fuse/f"), waitingOpen(11, "/fuse/f"), waitingOpen(11, "/backing/f"),
		openResult(11, -int32(unix.EACCES)))
	if want := fmt.Sprintf("/bin/sh:0 /backing/f:0 /fuse/f:%d :0", unix.EACCES); got != want {
		t.Fatalf("recording = %s, want %s", got, want)
	}
}

func TestRecorderWritesAnOpenWhoseResultWasLost(t *testing.T) {
	got, untracked := recordEvents(t, openName(11, "/a"), waitingOpen(11, "/a"), openName(11, "/b"), waitingOpen(11, "/b"),
		openResult(11, -int32(unix.ENOENT)), openName(11, "/c"), openName(11, "/d"))
	if want := fmt.Sprintf("/bin/sh:0 /a:0 /b:%d :0", unix.ENOENT); got != want || untracked != float64(3) {
		t.Fatalf("recording = %s, untracked %v, want %s with /a, /c and /d untracked", got, untracked, want)
	}
}

func TestRecorderWritesOpensStillWaitingAtTheEnd(t *testing.T) {
	late, early := waitingOpen(12, "/late"), waitingOpen(11, "/early")
	late.boot, early.boot = 2, 1
	r, out, _ := newTestRecorder()
	add(t, r, stepExec, late, early, openName(13, "/named"))
	if err := r.finish(loss{untracked: 1}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	if len(got) != 4 || got[1]["path"] != "/early" || got[2]["path"] != "/late" || got[3]["untracked"] != float64(4) {
		t.Fatalf("recording = %v, want both opens in time order and four untracked", got)
	}
}

func TestRecorderDropsAnOpenWaitingBeforeTheFirstExec(t *testing.T) {
	r, out, log := newTestRecorder()
	add(t, r, openName(11, "/etc/passwd"), waitingOpen(11, "/etc/passwd"), unlink(12, nrUnlink, "x"), stepExec,
		openResult(11, 3), result(12, nrUnlink, resultWatched, 0))
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	if got := paths(t, out); got != "/bin/sh:0 :0" {
		t.Fatalf("recording = %s, want the exec alone", got)
	}
	if !strings.Contains(log.String(), "pre-exec-skipped=2\n") {
		t.Fatalf("log = %q, want the open and the unlink skipped", log)
	}
}

func TestRecorderSettlesAPathChangeWithItsResult(t *testing.T) {
	eperm := -int32(unix.EPERM)
	exitFailure := event{kind: filesystemAuditKindK_CHMOD_FAILED, pid: 9, comm: "chmod", tid: 11, pathRet: -eperm, data: []byte("/exit\x00")}
	refused := event{kind: filesystemAuditKindK_SYSCALL, pid: 9, comm: "nc", tid: 11, flags: nrBind, pathRet: -eperm}
	for _, c := range []struct {
		name      string
		events    []event
		want      string
		untracked float64
	}{
		{"done", []event{unlink(11, nrUnlink, "a"), result(11, nrUnlink, resultWatched, 0)}, "/a:0", 0},
		{
			"refused, recorded from the exit",
			[]event{unlink(11, nrFchmod, "a"), exitFailure, result(11, nrFchmod, resultWatched, eperm)},
			"/exit:1", 0,
		},
		{
			"refused through a descriptor",
			[]event{unlink(11, nrFchmod, "a"), exitFailure, result(11, nrFchmod, resultWatched|resultFD, eperm)},
			"/a:1", 0,
		},
		{
			"refused, recorded from the exit through a descriptor",
			[]event{exitFailure, result(11, nrFchmod, resultWatched|resultFD, eperm)},
			"/exit:1", 0,
		},
		{"refused in a call recorded from no exit", []event{unlink(11, nrBind, "s"), result(11, nrBind, 0, eperm)}, "/s:1", 0},
		{
			"refused, with the call refused too",
			[]event{unlink(11, nrBind, "s"), refused, result(11, nrBind, 0, eperm)},
			"/s:1", 0,
		},
		{"refused by seccomp", []event{refused, result(11, nrBind, 0, eperm)}, ":1", 0},
		{
			"refused by seccomp after a refused path change",
			[]event{unlink(11, nrBind, "s"), result(11, nrBind, 0, -int32(unix.EACCES)), refused, result(11, nrBind, 0, eperm)},
			fmt.Sprintf("/s:%d :1", unix.EACCES), 0,
		},
		{
			"refused, its result lost",
			[]event{unlink(11, nrFchmod, "a"), exitFailure, {kind: filesystemAuditKindK_EXIT, tid: 11}},
			"/exit:1", 1,
		},
		{"refused, its result not yet come at the end", []event{unlink(11, nrFchmod, "a"), exitFailure}, "/exit:1", 1},
		{
			"two refused calls after a path change whose result was lost",
			[]event{unlink(11, nrFchmod, "a"), refused, refused},
			":1 :1", 1,
		},
		{"restarted", []event{unlink(11, nrUnlink, "a"), result(11, nrUnlink, resultWatched, -514)}, "", 0},
		{
			"hook run again in its call",
			[]event{unlink(11, nrUnlink, "a"), unlink(11, nrUnlink, "b"), result(11, nrUnlink, resultWatched, 0)},
			"/b:0", 0,
		},
		{
			"from a call whose result never came",
			[]event{unlink(11, nrBind, "a"), result(11, nrUnlink, resultWatched, 0)},
			"", 1,
		},
		{
			"replaced by one from another call",
			[]event{unlink(11, nrBind, "a"), unlink(11, nrUnlink, "b"), result(11, nrUnlink, resultWatched, 0)},
			"/b:0", 1,
		},
		{"at its thread's exit", []event{unlink(11, nrUnlink, "a"), {kind: filesystemAuditKindK_EXIT, tid: 11}}, "", 1},
		{"at the end", []event{unlink(11, nrUnlink, "a")}, "", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, untracked := recordEvents(t, c.events...)
			want := strings.TrimSpace("/bin/sh:0 " + c.want + " :0")
			if c.want == "" {
				want = "/bin/sh:0 :0"
			}
			if got != want || untracked != c.untracked {
				t.Fatalf("recording = %s, untracked %v, want %s, untracked %v", got, untracked, want, c.untracked)
			}
		})
	}
}

func TestRecorderRefusesAShortSample(t *testing.T) {
	r, _, _ := newTestRecorder()
	if err := r.add([]byte{1, 2, 3}); err == nil {
		t.Fatal("added a sample shorter than its header")
	}
}

// failingWriter accepts ok writes, then fails.
type failingWriter struct{ ok int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.ok == 0 {
		return 0, errors.New("disk full")
	}
	w.ok--
	return len(p), nil
}

// A failed write reaches the caller from wherever a line is written.
func TestRecorderReturnsAFailedWrite(t *testing.T) {
	for _, c := range []struct {
		name   string
		events []event
	}{
		{"a line", []event{waitingOpen(0, "/a")}},
		{"a lost call's open", []event{waitingOpen(11, "/a"), openName(11, "b")}},
		{"a result's", []event{unlink(11, nrUnlink, "a"), result(11, nrUnlink, resultWatched, 0)}},
		{"an exited thread's open", []event{waitingOpen(11, "/a"), {kind: filesystemAuditKindK_EXIT, tid: 11}}},
		{"one still waiting at the end", []event{waitingOpen(11, "/a")}},
		{"a held failure replaced", []event{unlink(11, nrFchmod, "a"),
			{kind: filesystemAuditKindK_SYSCALL, tid: 11, flags: nrBind, pathRet: 1},
			{kind: filesystemAuditKindK_SYSCALL, tid: 11, flags: nrBind, pathRet: 1}}},
		{"the end line", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A buffer smaller than a line, so each goes straight to the
			// writer, which takes the exec's alone.
			r := newRecorder(bufio.NewWriterSize(&failingWriter{ok: 1}, 16), &bytes.Buffer{}, func(uint64) int64 { return 0 })
			add(t, r, stepExec)
			var err error
			for _, e := range c.events {
				if err = r.add(e.bytes()); err != nil {
					break
				}
			}
			if err == nil {
				err = r.finish(loss{})
			}
			if err == nil {
				t.Fatal("no error from a failed write")
			}
		})
	}
}

// A truncating open whose result never came is one call, counted once.
func TestRecorderCountsALostCallOnce(t *testing.T) {
	call := []event{openName(11, "/f"), unlink(11, nrOpenat, "f"), waitingOpen(11, "/f")}
	for name, events := range map[string][]event{
		"at its thread's exit": append(call, event{kind: filesystemAuditKindK_EXIT, tid: 11}),
		"at the end":           call,
	} {
		t.Run(name, func(t *testing.T) {
			got, untracked := recordEvents(t, events...)
			if got != "/bin/sh:0 /f:0 :0" || untracked != float64(1) {
				t.Fatalf("recording = %s, untracked %v, want /f as done and one untracked", got, untracked)
			}
		})
	}
}

func TestRecorderDropsAnExitedThreadsOpen(t *testing.T) {
	got, untracked := recordEvents(t, event{kind: filesystemAuditKindK_EXIT, tid: 11},
		openName(11, "/a"), waitingOpen(11, "/a"), event{kind: filesystemAuditKindK_EXIT, tid: 11},
		openName(11, "/b"), event{kind: filesystemAuditKindK_EXIT, tid: 11}, openResult(11, -int32(unix.ENOENT)))
	if got != "/bin/sh:0 /a:0 :0" || untracked != float64(2) {
		t.Fatalf("recording = %s, untracked %v, want /a as done and both untracked", got, untracked)
	}
}

func TestRecorderLogsALostClock(t *testing.T) {
	r, out, log := newTestRecorder()
	add(t, r, stepExec)
	if err := r.finish(loss{errClock: errors.New("x")}); err != nil {
		t.Fatal(err)
	}
	if got := lines(t, out); len(got) != 2 || got[1]["kind"] != "end" {
		t.Fatalf("recording = %v, want the exec and the end line", got)
	}
	if !strings.Contains(log.String(), "lost track of the realtime clock") {
		t.Fatalf("log = %q", log)
	}
}

func TestRecorderLeavesOutTheEndLineWithoutEveryCount(t *testing.T) {
	for name, l := range map[string]loss{
		"dropped":     {errDropped: errors.New("x")},
		"untracked":   {errUntracked: errors.New("x")},
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

func TestRecorderCountsUnnamedFailedOpensUntrackedWhenNoOpenWasNamed(t *testing.T) {
	failed := openResult(11, -int32(unix.ENOENT))
	for _, c := range []struct {
		name      string
		events    []event
		untracked float64
	}{
		{"none named", []event{failed, waitingOpen(11, "/a"), failed, {kind: filesystemAuditKindK_OPEN_CREATE, tid: 11}, failed, unlink(11, nrOpenat, "t"), failed}, 4},
		{"some named", []event{failed, openName(11, "/b"), failed, failed}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, out, log := newTestRecorder()
			add(t, r, failed, stepExec) // runc's own, before the step starts
			add(t, r, c.events...)
			if err := r.finish(loss{untracked: 1}); err != nil {
				t.Fatal(err)
			}
			got := lines(t, out)
			if got[len(got)-1]["untracked"] != c.untracked {
				t.Fatalf("recording = %v, want untracked %v", got, c.untracked)
			}
			warned := strings.Contains(log.String(), "no open passed do_filp_open")
			if warned != (c.untracked == 4) {
				t.Fatalf("log = %q", log)
			}
		})
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

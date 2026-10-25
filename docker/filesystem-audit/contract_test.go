package main

import (
	"bytes"
	"flag"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

var update = flag.Bool("update", false, "rewrite testdata/contract.jsonl")

// The report reads the recording through its own copy of the record's fields
// and kinds, and tests itself against this file.
const contractPath = "testdata/contract.jsonl"

// contractEvents is one call of each form the recorder writes, as the BPF side
// sends it, so each line carries only the fields and values the tracer gives
// its kind.
func contractEvents() []event {
	const pid, tid = 9, 11
	ev := func(e event) event {
		e.pid, e.ppid, e.comm = pid, 1, "sh"
		return e
	}
	// A call's path change, settled by its result: done when ret is 0, and
	// failed otherwise, as for a syscall whose exit the tracer does not watch.
	nr := int32(0)
	op := func(e event, ret int32) []event {
		nr++
		e.tid, e.nr = tid, nr
		bits := resultWatched
		if ret < 0 {
			bits = 0
		}
		return []event{ev(e), ev(result(tid, nr, bits, ret))}
	}
	// The exit's record of a failed call, by the name it passed relative to a
	// base directory.
	exitFailure := func(kind filesystemAuditKind, e event) event {
		e.kind, e.tid, e.pathRet, e.bases, e.mode = kind, tid, int32(unix.EROFS), 1, 1
		e.data = append([]byte("x\x00"), comps("tmp")...)
		return ev(e)
	}
	twoPathFailure := func(kind filesystemAuditKind) event {
		return ev(event{kind: kind, tid: tid, pathRet: int32(unix.EXDEV), n1: 1, bases: 3, mode: 1, flags: 1,
			data: append(append([]byte("a\x00b\x00"), comps("src")...), comps("dst")...)})
	}
	symlinkBody := []byte("target\x00")
	fails := -int32(unix.EROFS)

	events := []event{
		// The exec-file first, so the exec takes its file.
		ev(event{kind: filesystemAuditKindK_EXEC_FILE, n1: 3, data: comps("gradlew", "A", "work")}),
		ev(event{kind: filesystemAuditKindK_EXEC, nspid: 2, data: []byte("./gradlew\x00")}),
		{kind: filesystemAuditKindK_FORK, pid: pid + 1, ppid: pid, nspid: 3, comm: "sh"},
		// An open that created its file, one refused at the file, and one
		// that failed before reaching a file.
		ev(event{kind: filesystemAuditKindK_OPEN_NAME, tid: tid, data: []byte("/tmp/out\x00")}),
		ev(event{kind: filesystemAuditKindK_OPEN, tid: tid, flags: unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC, data: []byte("/tmp/out\x00")}),
		ev(openResult(tid, 3)),
		ev(event{kind: filesystemAuditKindK_OPEN_NAME, tid: tid, data: []byte("/etc/shadow\x00")}),
		ev(event{kind: filesystemAuditKindK_OPEN, tid: tid, flags: unix.O_RDONLY, mode: fmodeExec, data: []byte("/etc/shadow\x00")}),
		ev(openResult(tid, -int32(unix.EACCES))),
		ev(event{kind: filesystemAuditKindK_OPEN_NAME, tid: tid, data: []byte("/missing\x00")}),
		ev(openResult(tid, -int32(unix.ENOENT))),
		ev(event{kind: filesystemAuditKindK_READ, marks: markUnlinked, data: []byte("/tmp/old (deleted)\x00")}),
		ev(event{kind: filesystemAuditKindK_WRITE, marks: markInternal, data: []byte("/memfd:x (deleted)\x00")}),
		ev(event{kind: filesystemAuditKindK_MMAP, mode: unix.PROT_READ | unix.PROT_EXEC, pathRet: 1, n1: 3, data: comps("bash", "bin", "usr")}),
		ev(event{kind: filesystemAuditKindK_MMAP, mode: unix.PROT_READ | unix.PROT_WRITE, flags: unix.MAP_SHARED, n1: 2, data: comps("db", "tmp")}),
		ev(event{kind: filesystemAuditKindK_ATTR, bases: 1, mode: 1, data: append([]byte("f\x00"), comps("tmp")...)}),
		ev(event{kind: filesystemAuditKindK_ATTR_FAILED, pathRet: int32(unix.EROFS), data: []byte("/etc\x00")}),
		ev(event{kind: filesystemAuditKindK_SYSCALL, tid: tid, flags: uint32(syscallNumbers["nr_bpf"]), pathRet: int32(unix.EPERM)}),
		ev(event{kind: filesystemAuditKindK_SYSCALL, flags: 1, mode: 1}),
	}
	for _, ret := range []int32{0, fails} {
		for _, e := range []event{
			{kind: filesystemAuditKindK_UNLINK, n1: 2, data: comps("f", "tmp")},
			{kind: filesystemAuditKindK_RMDIR, n1: 2, data: comps("d", "tmp")},
			{kind: filesystemAuditKindK_MKDIR, n1: 2, data: comps("d", "tmp")},
			{kind: filesystemAuditKindK_MKNOD, n1: 2, data: comps("p", "tmp")},
			{kind: filesystemAuditKindK_TRUNCATE, marks: markUnlinked, n1: 2, data: comps("f", "tmp")},
			{kind: filesystemAuditKindK_CHMOD, mode: 0o4755, n1: 2, data: comps("f", "tmp")},
			{kind: filesystemAuditKindK_CHOWN, flags: 1001, mode: 121, n1: 2, data: comps("f", "tmp")},
			{kind: filesystemAuditKindK_SYMLINK, pathRet: int32(len(symlinkBody)), n1: 2,
				data: append(append([]byte{}, symlinkBody...), comps("l", "tmp")...)},
			{kind: filesystemAuditKindK_RENAME, flags: unix.RENAME_EXCHANGE, n1: 2, n2: 2,
				data: append(comps("a", "tmp"), comps("b", "tmp")...)},
			{kind: filesystemAuditKindK_LINK, marks: markUnlinked, n1: 2, n2: 2,
				data: append(comps("#12", "tmp"), comps("x", "tmp")...)},
		} {
			events = append(events, op(e, ret)...)
		}
	}
	return append(events,
		exitFailure(filesystemAuditKindK_UNLINK_FAILED, event{}),
		exitFailure(filesystemAuditKindK_RMDIR_FAILED, event{}),
		exitFailure(filesystemAuditKindK_MKDIR_FAILED, event{}),
		exitFailure(filesystemAuditKindK_MKNOD_FAILED, event{}),
		exitFailure(filesystemAuditKindK_SYMLINK_FAILED, event{}),
		exitFailure(filesystemAuditKindK_TRUNCATE_FAILED, event{}),
		exitFailure(filesystemAuditKindK_CHMOD_FAILED, event{flags: 0o755}),
		exitFailure(filesystemAuditKindK_CHOWN_FAILED, event{flags: 1001, gid: 121}),
		twoPathFailure(filesystemAuditKindK_RENAME_FAILED),
		twoPathFailure(filesystemAuditKindK_LINK_FAILED),
	)
}

func contractRecording(t *testing.T) []byte {
	t.Helper()
	r, out, _ := newTestRecorder()
	add(t, r, contractEvents()...)
	if err := r.finish(loss{dropped: 1, untracked: 2, missed: count{n: 3}}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// The contract shows the report every field and every kind a line can have.
func TestRecordingContractCoversEveryFieldAndKind(t *testing.T) {
	keys, kinds := map[string]bool{}, map[string]bool{}
	for _, l := range lines(t, bytes.NewBuffer(contractRecording(t))) {
		for k := range l {
			keys[k] = true
		}
		kinds[l["kind"].(string)] = true
	}
	var missing []string
	rt := reflect.TypeOf(record{})
	for i := 0; i < rt.NumField(); i++ {
		if tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]; tag != "" && !keys[tag] {
			missing = append(missing, tag)
		}
	}
	for _, n := range kindNames {
		// An exec-file only lends its file to the exec that follows.
		if n != "" && n != "exec-file" && !kinds[n] {
			missing = append(missing, "kind "+n)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("the contract has no line with %v", missing)
	}
}

func TestRecordingContractIsUpToDate(t *testing.T) {
	got := contractRecording(t)
	if *update {
		if err := os.WriteFile(contractPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date; rerun go test with -update\ngot:\n%s", contractPath, got)
	}
}

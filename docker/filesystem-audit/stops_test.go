package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	stopFailed = 1
	nrRename   = 82
)

// stopAt is a K_STOP: the lookup of the call's name number which stopped
// with name[at:] left, in the directory whose components dir lists leaf first.
func stopAt(tid uint32, which uint32, typ uint8, name string, at int32, dir ...string) event {
	return event{kind: filesystemAuditKindK_STOP, pid: 9, comm: "sh", tid: tid, mode: which, n2: typ,
		pathRet: at, flags: uint32(len(name) + 1), n1: uint8(len(dir)), data: append([]byte(name+"\x00"), comps(dir...)...)}
}

// missing is the exit's record of a call that failed with ENOENT, its K_STOP
// marked as saying where.
func missing(tid uint32, kind filesystemAuditKind, names ...string) event {
	e := event{kind: kind, pid: 9, comm: "sh", tid: tid, pathRet: int32(unix.ENOENT), n2: 1}
	for _, n := range names {
		e.data = append(e.data, n+"\x00"...)
	}
	if len(names) == 2 {
		e.n1 = 1
	}
	return e
}

func stopResult(tid uint32, ret int32) event {
	return result(tid, nrOpenat, resultOpen|resultStop, ret)
}

// recordLines runs events through a recorder after the step's exec and returns
// the lines between the exec and the end line.
func recordLines(t *testing.T, events ...event) []map[string]any {
	t.Helper()
	r, out, _ := newTestRecorder()
	add(t, r, stepExec)
	add(t, r, events...)
	if err := r.finish(loss{}); err != nil {
		t.Fatal(err)
	}
	got := lines(t, out)
	return got[1 : len(got)-1]
}

// field gives each line's value of key, or nil.
func field(got []map[string]any, key string) []any {
	var vs []any
	for _, l := range got {
		vs = append(vs, l[key])
	}
	return vs
}

func TestRecorderMovesAFailedOpenToWhereItsNameWasMissing(t *testing.T) {
	got := recordLines(t,
		openName(1, "/ws/a/b"),
		stopAt(1, 1, stopFailed, "/ws/a/b", 4, "ws", "real"),
		stopResult(1, -int32(unix.ENOENT)))
	if len(got) != 1 || got[0]["path"] != "/real/ws/a/b" || got[0]["name"] != "/ws/a/b" || got[0]["resolved"] != true {
		t.Fatalf("lines = %v, want /real/ws/a/b resolved, by the name /ws/a/b", got)
	}
}

// A relative name joined to its working directory keeps the name as passed.
func TestRecorderMovesARelativeName(t *testing.T) {
	got := recordLines(t,
		openName(1, "x//y"),
		stopAt(1, 1, stopFailed, "x//y", 0, "ws", "real"),
		stopResult(1, -int32(unix.ENOENT)))
	if got[0]["path"] != "/real/ws/x/y" || got[0]["name"] != "x//y" {
		t.Fatalf("lines = %v, want /real/ws/x/y by the name x//y", got)
	}
}

// Moved to a directory under a path too long to walk, a name starts with "…".
func TestRecorderMovesANameUnderACutDirectory(t *testing.T) {
	stop := stopAt(1, 1, stopFailed, "/ws/x", 4, "ws")
	stop.truncated = 1
	got := recordLines(t, openName(1, "/ws/x"), stop, stopResult(1, -int32(unix.ENOENT)))
	if got[0]["path"] != "…/ws/x" {
		t.Fatalf("lines = %v, want …/ws/x", got)
	}
}

func TestRecorderKeepsTheNameWithoutAStop(t *testing.T) {
	for name, events := range map[string][]event{
		// The open's latest lookup sent none, or failed for another reason.
		"no stop bit": {openName(1, "/ws/x"), stopAt(1, 1, stopFailed, "/ws/x", 4, "real"),
			openResult(1, -int32(unix.ENOENT))},
		"no stop": {openName(1, "/ws/x"), stopResult(1, -int32(unix.ENOENT))},
		// A K_STOP of another name, as of an earlier call whose result was lost.
		"other name": {openName(1, "/ws/x"), stopAt(1, 1, stopFailed, "/ws/y", 4, "real"),
			stopResult(1, -int32(unix.ENOENT))},
		// A name cut short is not the name the kernel copied.
		"cut name": {{kind: filesystemAuditKindK_OPEN_NAME, pid: 9, comm: "sh", tid: 1, n2: 1, data: []byte("/ws/x\x00")},
			stopAt(1, 1, stopFailed, "/ws/x", 4, "real"), stopResult(1, -int32(unix.ENOENT))},
		"missing part out of range": {openName(1, "/ws/x"), stopAt(1, 1, stopFailed, "/ws/x", 5, "real"),
			stopResult(1, -int32(unix.ENOENT))},
		"name longer than the sample": {openName(1, "/ws/x"),
			event{kind: filesystemAuditKindK_STOP, tid: 1, mode: 1, n2: stopFailed, flags: 100, data: []byte("/ws/x\x00")},
			stopResult(1, -int32(unix.ENOENT))},
		// Forgotten with the result of the call that sent it.
		"earlier call's": {stopAt(1, 1, stopFailed, "/ws/x", 4, "real"), openResult(1, 3),
			openName(1, "/ws/x"), stopResult(1, -int32(unix.ENOENT))},
	} {
		t.Run(name, func(t *testing.T) {
			got := recordLines(t, events...)
			if !strings.HasPrefix(got[0]["path"].(string), "/ws/x") || got[0]["resolved"] != nil {
				t.Fatalf("lines = %v, want /ws/x as passed", got)
			}
		})
	}
}

// An unlink or rmdir that found the parent but not the name.
func TestRecorderMovesARemovalToItsParent(t *testing.T) {
	got := recordLines(t,
		stopAt(1, 1, stopParent, "/ws/gone", 4, "ws", "real"),
		missing(1, filesystemAuditKindK_UNLINK_FAILED, "/ws/gone"),
		result(1, nrUnlink, resultWatched, -int32(unix.ENOENT)))
	if len(got) != 1 || got[0]["path"] != "/real/ws/gone" || got[0]["name"] != "/ws/gone" || got[0]["resolved"] != true {
		t.Fatalf("lines = %v, want /real/ws/gone resolved", got)
	}
}

func TestRecorderPlacesEachNameOfARename(t *testing.T) {
	for name, tc := range map[string]struct {
		stops    []event
		path, to string
	}{
		// Both parents found: each name is where its parent led.
		"both parents": {[]event{stopAt(1, 1, stopParent, "/ws/a", 4, "ws", "real"),
			stopAt(1, 2, stopParent, "/ws/b/c", 6, "b", "ws", "real")}, "/real/ws/a", "/real/ws/b/c"},
		"new parent missing": {[]event{stopAt(1, 1, stopParent, "/ws/a", 4, "ws", "real"),
			stopAt(1, 2, stopFailed, "/ws/b/c", 4, "ws", "real")}, "/real/ws/a", "/real/ws/b/c"},
		"old parent missing": {[]event{stopAt(1, 1, stopFailed, "/ws/a", 4, "real")}, "/real/a", "/ws/b/c"},
		// The new name's parent found after a first lookup that sent none of its own.
		"no first parent": {[]event{stopAt(1, 1, stopFailed, "/ws/a", 4, "real"),
			stopAt(1, 2, stopParent, "/ws/b/c", 6, "b", "ws", "real")}, "/ws/a", "/real/ws/b/c"},
	} {
		t.Run(name, func(t *testing.T) {
			events := append(tc.stops, missing(1, filesystemAuditKindK_RENAME_FAILED, "/ws/a", "/ws/b/c"),
				result(1, nrRename, resultWatched, -int32(unix.ENOENT)))
			got := recordLines(t, events...)
			if got[0]["path"] != tc.path || got[0]["to"] != tc.to {
				t.Fatalf("lines = %v, want %s to %s", got, tc.path, tc.to)
			}
			if (got[0]["resolved"] == true) != (tc.path != "/ws/a") || (got[0]["to_resolved"] == true) != (tc.to != "/ws/b/c") {
				t.Fatalf("lines = %v, want resolved only where moved", got)
			}
		})
	}
}

// A removal refused once its parent was found acts on the name there, a
// symlink itself included.
func TestRecorderPlacesARefusedRemovalInItsParent(t *testing.T) {
	refused := missing(1, filesystemAuditKindK_RMDIR_FAILED, "/ws")
	refused.pathRet, refused.n2 = int32(unix.ENOTDIR), stopParent
	got := recordLines(t,
		stopAt(1, 1, stopParent, "/ws", 1),
		refused,
		result(1, nrUnlink, resultWatched, -int32(unix.ENOTDIR)))
	if got[0]["path"] != "/ws" || got[0]["resolved"] != true {
		t.Fatalf("lines = %v, want /ws resolved", got)
	}
}

// A failure the kernel refused at the file it reached is where it landed.
func TestRecorderMarksAFailureAtItsFileResolved(t *testing.T) {
	got := recordLines(t,
		openName(1, "/ws/f"), waitingOpen(1, "/real/ws/f"), openResult(1, -int32(unix.EACCES)),
		unlink(2, nrUnlink, "/real/ws/f"), result(2, nrUnlink, 0, -int32(unix.EPERM)))
	if v := field(got, "resolved"); len(v) != 2 || v[0] != true || v[1] != true {
		t.Fatalf("lines = %v, want both resolved", got)
	}
}

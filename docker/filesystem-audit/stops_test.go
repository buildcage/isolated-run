package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	stopFailed = 1
	stopParent = 2
	nrRename   = 82
	nrChmod    = 90
)

// stopAt is a K_STOP: name number which, from offset at on, was not looked up
// in the directory whose components dir lists leaf first.
func stopAt(tid uint32, which uint32, typ uint8, at int32, dir ...string) event {
	return event{kind: filesystemAuditKindK_STOP, pid: 9, comm: "sh", tid: tid, mode: which, n2: typ,
		pathRet: at, n1: uint8(len(dir)), data: comps(dir...)}
}

// failure is the exit's record of a call that failed with err, sent marking
// the names its exit sent K_STOP for.
func failure(tid uint32, kind filesystemAuditKind, err unix.Errno, sent uint8, names ...string) event {
	e := event{kind: kind, pid: 9, comm: "sh", tid: tid, pathRet: int32(err), n2: sent}
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
		stopAt(1, 1, stopFailed, 4, "ws", "real"),
		stopResult(1, -int32(unix.ENOENT)))
	if len(got) != 1 || got[0]["path"] != "/real/ws/a/b" || got[0]["name"] != "/ws/a/b" || got[0]["resolved"] != true {
		t.Fatalf("lines = %v, want /real/ws/a/b resolved, by the name /ws/a/b", got)
	}
}

// A relative name joined to its working directory keeps the name as passed.
func TestRecorderMovesARelativeName(t *testing.T) {
	got := recordLines(t,
		openName(1, "x//y"),
		stopAt(1, 1, stopFailed, 0, "ws", "real"),
		stopResult(1, -int32(unix.ENOENT)))
	if got[0]["path"] != "/real/ws/x/y" || got[0]["name"] != "x//y" {
		t.Fatalf("lines = %v, want /real/ws/x/y by the name x//y", got)
	}
}

// Moved to a directory under a path too long to walk, a name starts with "…".
func TestRecorderMovesANameUnderACutDirectory(t *testing.T) {
	stop := stopAt(1, 1, stopFailed, 4, "ws")
	stop.truncated = 1
	got := recordLines(t, openName(1, "/ws/x"), stop, stopResult(1, -int32(unix.ENOENT)))
	if got[0]["path"] != "…/ws/x" {
		t.Fatalf("lines = %v, want …/ws/x", got)
	}
}

func TestRecorderKeepsTheNameWithoutAStop(t *testing.T) {
	for name, events := range map[string][]event{
		// The exit sent none for the open's name.
		"no stop bit": {openName(1, "/ws/x"), stopAt(1, 1, stopFailed, 4, "real"),
			openResult(1, -int32(unix.ENOENT))},
		"no stop": {openName(1, "/ws/x"), stopResult(1, -int32(unix.ENOENT))},
		// A name cut short has lost the part the offset counts into.
		"cut name": {{kind: filesystemAuditKindK_OPEN_NAME, pid: 9, comm: "sh", tid: 1, n2: 1, data: []byte("/ws/x\x00")},
			stopAt(1, 1, stopFailed, 4, "real"), stopResult(1, -int32(unix.ENOENT))},
		// Past the end of the name, as when another thread rewrote it.
		"offset out of range": {openName(1, "/ws/x"), stopAt(1, 1, stopFailed, 6, "real"),
			stopResult(1, -int32(unix.ENOENT))},
		"negative offset": {openName(1, "/ws/x"), stopAt(1, 1, stopFailed, -1, "real"),
			stopResult(1, -int32(unix.ENOENT))},
		// Forgotten with the result of the call that sent it.
		"earlier call's": {stopAt(1, 1, stopFailed, 4, "real"), openResult(1, -int32(unix.EACCES)),
			openName(1, "/ws/x"), stopResult(1, -int32(unix.ENOENT))},
	} {
		t.Run(name, func(t *testing.T) {
			got := recordLines(t, events...)
			last := got[len(got)-1]
			if !strings.HasPrefix(last["path"].(string), "/ws/x") || last["resolved"] != nil {
				t.Fatalf("lines = %v, want /ws/x as passed", got)
			}
		})
	}
}

// An unlink or rmdir that found the parent: the name it acts on is there,
// whatever the error, a symlink itself included.
func TestRecorderPlacesARemovalInItsParent(t *testing.T) {
	for _, err := range []unix.Errno{unix.ENOENT, unix.ENOTDIR} {
		got := recordLines(t,
			stopAt(1, 1, stopParent, 4, "ws", "real"),
			failure(1, filesystemAuditKindK_RMDIR_FAILED, err, 1, "/ws/gone"),
			result(1, nrUnlink, resultWatched, -int32(err)))
		if len(got) != 1 || got[0]["path"] != "/real/ws/gone" || got[0]["name"] != "/ws/gone" || got[0]["resolved"] != true {
			t.Fatalf("%v: lines = %v, want /real/ws/gone resolved", err, got)
		}
	}
}

func TestRecorderPlacesEachNameOfARenameItsExitSentAStopFor(t *testing.T) {
	stops := []event{stopAt(1, 1, stopParent, 4, "ws", "real"), stopAt(1, 2, stopFailed, 4, "ws", "real")}
	for _, tc := range []struct {
		sent     uint8
		path, to string
	}{
		{3, "/real/ws/a", "/real/ws/b/c"},
		{1, "/real/ws/a", "/ws/b/c"},
		{2, "/ws/a", "/real/ws/b/c"},
		{0, "/ws/a", "/ws/b/c"},
	} {
		events := append(append([]event{}, stops...),
			failure(1, filesystemAuditKindK_RENAME_FAILED, unix.ENOENT, tc.sent, "/ws/a", "/ws/b/c"),
			result(1, nrRename, resultWatched, -int32(unix.ENOENT)))
		got := recordLines(t, events...)
		if got[0]["path"] != tc.path || got[0]["to"] != tc.to {
			t.Fatalf("sent %d: lines = %v, want %s to %s", tc.sent, got, tc.path, tc.to)
		}
		if (got[0]["resolved"] == true) != (tc.sent&1 != 0) || (got[0]["to_resolved"] == true) != (tc.sent&2 != 0) {
			t.Fatalf("sent %d: lines = %v, want resolved only where moved", tc.sent, got)
		}
	}
}

// A lookup that reached its file places the call's failure there, a name cut
// short included, since nothing of the name follows the file.
func TestRecorderPlacesAFailureAtTheFileItReached(t *testing.T) {
	cut := event{kind: filesystemAuditKindK_OPEN_NAME, pid: 9, comm: "sh", tid: 1, n2: 1, data: []byte("/ws/f\x00")}
	for name, open := range map[string]event{"whole": openName(1, "/ws/f"), "cut": cut} {
		got := recordLines(t, open, stopAt(1, 1, stopReached, 0, "f", "ws", "real"),
			stopResult(1, -int32(unix.EACCES)))
		if len(got) != 1 || got[0]["path"] != "/real/ws/f" || got[0]["resolved"] != true {
			t.Fatalf("%s: lines = %v, want /real/ws/f resolved", name, got)
		}
	}
}

// A time or xattr change has no result: its record takes the K_STOP its exit
// sent, success or failure, and its call ends with it.
func TestRecorderPlacesATimeChange(t *testing.T) {
	for _, err := range []unix.Errno{0, unix.EPERM} {
		kind := filesystemAuditKindK_ATTR
		if err != 0 {
			kind = filesystemAuditKindK_ATTR_FAILED
		}
		got := recordLines(t,
			stopAt(1, 1, stopReached, 0, "f", "ws", "real"),
			failure(1, kind, err, 1, "/ws/f"),
			// A later call whose exit sent none.
			failure(1, filesystemAuditKindK_CHMOD_FAILED, unix.EPERM, 1, "/ws/g"),
			result(1, nrChmod, resultWatched, -int32(unix.EPERM)))
		if len(got) != 2 || got[0]["path"] != "/real/ws/f" || got[0]["name"] != "/ws/f" || got[0]["resolved"] != true {
			t.Fatalf("%v: lines = %v, want /real/ws/f resolved", err, got)
		}
		if got[1]["path"] != "/ws/g" || got[1]["resolved"] != nil {
			t.Fatalf("%v: lines = %v, want /ws/g as passed", err, got)
		}
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

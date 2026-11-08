package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// call is what one thread sent while in a syscall. It stays with its thread,
// for the next call, until the thread exits.
type call struct {
	// op is a path change its hook sent, whose result says whether it
	// happened, and failure the call's failure recorded from its exit.
	op, failure       record
	hasOp, hasFailure bool
	// open is the file an open reached, and name the name it passed, cut
	// short when cut; created says it reached its create step.
	open             record
	name             []byte
	hasOpen, hasName bool
	cut, created     bool
	// stop is the call's latest K_STOP, and parent its first name's from a
	// parent lookup; their buffers are kept from call to call.
	stop, parent       []byte
	hasStop, hasParent bool
}

// pending says whether c holds anything of a call.
func (c *call) pending() bool {
	return c.hasOp || c.hasName || c.hasOpen
}

// leftovers appends what c holds that stands without its call's result: a
// failure recorded from its exit and the file an open reached.
func (c *call) leftovers(recs []record) []record {
	if c.hasFailure {
		recs = append(recs, c.failure)
	}
	if c.hasOpen {
		recs = append(recs, c.open)
	}
	return recs
}

// callOf is thread tid's call, created if absent.
func (r *recorder) callOf(tid uint32) *call {
	c := r.calls[tid]
	if c == nil {
		c = &call{}
		r.calls[tid] = c
	}
	return c
}

// openName takes the name of the open(2) a thread starts. A name read from
// the caller comes at the call's return, when getname refused it, and gives
// way to the kernel's copy if the call had one.
func (r *recorder) openName(h hdr, raw []byte) error {
	c := r.callOf(h.tid)
	name := cbytes(raw[hdrLen:])
	if h.n1 != 0 && c.hasName {
		// The caller's copy of a name the kernel copied matches it, unless
		// the copy held is an earlier call's whose result was lost, or
		// another thread rewrote the name during the call. The two cannot be
		// told apart, and either may leave the open under the wrong name.
		if !bytes.Equal(name, c.name) {
			r.renamed++
		}
		return nil
	}
	if h.n1 == 0 {
		r.named = true
	}
	// An open still waiting is the last call's, whose result never came.
	if err := r.lose(c); err != nil {
		return err
	}
	c.name, c.hasName, c.cut = append(c.name[:0], name...), true, h.n2 != 0
	return nil
}

// lose writes what c holds as if its call's result never came: an open as
// done and a failure as recorded, counting the call once.
func (r *recorder) lose(c *call) error {
	if !c.pending() {
		c.created = false
		return nil
	}
	var buf [2]record
	recs := c.leftovers(buf[:0])
	c.clear()
	r.unsettled++
	for _, rec := range recs {
		if err := r.write(rec); err != nil {
			return err
		}
	}
	return nil
}

// clear empties c, keeping its buffers.
func (c *call) clear() {
	*c = call{name: c.name[:0], stop: c.stop[:0], parent: c.parent[:0]}
}

// settle writes what the thread sent during the call the result h ends. A
// path change is done, or refused unless the exit's record stands for the
// failure. An open is done, refused, or both if it created its file first;
// one that failed before reaching a file is written under its name. A
// restarted call drops them, as its rerun sends them again.
func (r *recorder) settle(h hdr, raw []byte) error {
	c := r.calls[h.tid]
	if c == nil {
		c = &r.none
	}
	if !c.pending() {
		c.created = false // a mark left by a call that sent neither name nor file
	}
	defer c.forgetStops()
	if err := r.settleOp(c, h); err != nil {
		return err
	}
	if h.n1&resultOpen == 0 {
		return nil
	}
	return r.settleOpen(c, h, raw)
}

// settleOp writes the path change c holds by the result h. On a failure the
// record from the call's exit stands instead, unless there is none to stand
// (the syscall is not watched) or the hook saw the file of a descriptor,
// which the thread could have swapped before the exit.
func (r *recorder) settleOp(c *call, h hdr) error {
	op, failure, hasOp, hasFailure := &c.op, c.failure, c.hasOp, c.hasFailure
	c.hasOp, c.hasFailure = false, false
	switch {
	case !hasOp:
		return nil
	case op.nr != h.nr:
		// Sent from a call whose own result never came.
		r.unsettled++
	case isRestart(h.ret):
	case h.ret >= 0:
		return r.write(*op)
	case h.n1&resultWatched == 0 || h.n1&resultFD != 0:
		op.Err, op.Failed, op.Resolved = -h.ret, true, true
		op.ToResolved = op.To != "" && op.Kind != "symlink"
		return r.write(*op)
	}
	if !hasFailure {
		return nil
	}
	return r.write(failure)
}

// settleOpen writes the open c holds by the result h: the file it reached,
// done or refused, or both if the call created the file before failing; or,
// failed before reaching a file, the name it passed. A failure with neither
// counts as unnamed; runc's own opens before the first exec are not counted.
func (r *recorder) settleOpen(c *call, h hdr, raw []byte) error {
	open, hasOpen, hasName, created := &c.open, c.hasOpen, c.hasName, c.created
	c.hasOpen, c.hasName, c.created = false, false, false
	switch {
	case isRestart(h.ret):
		return nil
	case hasOpen:
		if h.ret >= 0 || created {
			if err := r.write(*open); err != nil || h.ret >= 0 {
				return err
			}
		}
		open.Err, open.Failed, open.Resolved = -h.ret, true, true
		return r.write(*open)
	case h.ret >= 0:
		return nil
	case hasName:
		rec := failedOpen(string(c.name), c.cut, raw)
		if h.n1&resultStop != 0 && !c.cut {
			c.place(&rec)
		}
		r.setProgram(&rec)
		return r.write(rec)
	}
	if r.started {
		r.unnamed++
	}
	return nil
}

// exited drops what thread tid still had waiting, so a reused thread id does
// not take it up.
func (r *recorder) exited(tid uint32) error {
	c := r.calls[tid]
	delete(r.calls, tid)
	if c == nil {
		return nil
	}
	return r.lose(c)
}

// isRestart is is_restart() in bpf/syscalls.h: whether ret is one of
// ERESTARTSYS to ERESTART_RESTARTBLOCK, which the kernel runs the call again
// for.
func isRestart(ret int32) bool {
	return ret <= -512 && ret >= -516
}

// keepStop holds the K_STOP raw of the thread's call, and its first name's
// from a parent lookup.
func (c *call) keepStop(raw []byte) {
	c.stop, c.hasStop = append(c.stop[:0], raw...), true
	if binary.LittleEndian.Uint32(raw[offMode:]) == 1 {
		c.hasParent = raw[offN2] == stopParent
		if c.hasParent {
			c.parent = append(c.parent[:0], raw...)
		}
	}
}

// forgetStops drops the K_STOPs of a call that ended.
func (c *call) forgetStops() {
	c.hasStop, c.hasParent = false, false
}

// place moves rec, a failure of c's call that its latest K_STOP speaks for,
// to where the kernel took its names: the directory the lookup stopped in
// followed by the rest of the name, for a name found missing or one the call
// acts on in a parent it found. When a rename's or link's new name was looked
// up last, the first name's parent lookup, if any, places that name too.
func (c *call) place(rec *record) {
	if !c.hasStop {
		return
	}
	if placeName(rec, c.stop) == 2 && c.hasParent {
		placeName(rec, c.parent)
	}
}

// placeName moves the name of rec that the K_STOP raw is of, if it is the name
// rec holds, and returns which name that is.
func placeName(rec *record, raw []byte) uint32 {
	le := binary.LittleEndian
	which := le.Uint32(raw[offMode:])
	data := raw[hdrLen:]
	n := int(le.Uint32(raw[offFlags:]))
	at := int(int32(le.Uint32(raw[offPathLen:])))
	if n < 1 || n > len(data) || at < 0 || at >= n-1 {
		return which
	}
	name := string(data[:n-1])
	dir, _ := components(data[n:], int(raw[offN1]), raw[offTruncated] != 0)
	p := tidy(strings.TrimSuffix(dir, "/") + "/" + name[at:])
	switch which {
	case 1:
		if passed := orPath(rec.Name, rec.Path); passed == name {
			rec.Path, rec.Name, rec.Resolved = p, passedName(passed, p), true
		}
	case 2:
		if passed := orPath(rec.ToName, rec.To); passed == name {
			rec.To, rec.ToName, rec.ToResolved = p, passedName(passed, p), true
		}
	}
	return which
}

// orPath is the name a command passed, from a record's name field or, where
// that is empty, the path it equals.
func orPath(name, path string) string {
	if name == "" {
		return path
	}
	return name
}

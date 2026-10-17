package main

import "bytes"

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

// clear empties c, keeping its name's buffer.
func (c *call) clear() {
	*c = call{name: c.name[:0]}
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
		op.Err, op.Failed = -h.ret, true
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
		open.Err, open.Failed = -h.ret, true
		return r.write(*open)
	case h.ret >= 0:
		return nil
	case hasName:
		return r.write(failedOpen(string(c.name), c.cut, raw))
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

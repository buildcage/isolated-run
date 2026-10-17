package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// recorder writes the ring buffer's samples as the recording's lines, and
// tallies them for the step log.
type recorder struct {
	w   *bufio.Writer
	log io.Writer
	// offset is the realtime clock's offset over the boot clock at a boot
	// timestamp (see bootClock).
	offset func(boot uint64) int64
	files  execFiles
	// calls holds, per thread, what it sent while in a syscall, until the
	// call's result arrives.
	calls map[uint32]*call
	// line is reused for each line written, and stamp keeps the second's
	// text from line to line.
	line    []byte
	stamp   timeText
	counts  map[tally]int
	preExec int
	// unsettled counts calls whose result never arrived.
	unsettled int
	// named says an open(2) passed do_filp_open its name, and unnamed counts
	// the failures that came with none.
	named   bool
	unnamed int
	total   int
	started bool
	// none stands in for the call of a thread that sent nothing yet; settling
	// it never sets anything, so it stays empty.
	none call
}

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

// tally is what the step log counts lines by.
type tally struct {
	kind   string
	failed bool
}

func newRecorder(w *bufio.Writer, log io.Writer, offset func(boot uint64) int64) *recorder {
	return &recorder{
		w:      w,
		log:    log,
		offset: offset,
		files:  execFiles{},
		calls:  map[uint32]*call{},
		counts: map[tally]int{},
	}
}

// add writes one sample out, or holds it until its syscall's result. Events
// before the sandboxed command's first exec belong to runc's own setup and are
// dropped; the cgroup holds nothing else before then.
func (r *recorder) add(raw []byte) error {
	// The events that only settle others are read from their header alone.
	if len(raw) >= hdrLen {
		h := header(raw)
		switch h.kind {
		case filesystemAuditKindK_RESULT:
			return r.settle(h, raw)
		case filesystemAuditKindK_EXIT:
			return r.exited(h.tid)
		case filesystemAuditKindK_OPEN_NAME:
			if r.started {
				return r.openName(h, raw)
			}
			return nil
		case filesystemAuditKindK_OPEN_CREATE:
			if r.started {
				r.callOf(h.tid).created = true
			}
			return nil
		}
	}
	rec, err := decode(raw)
	if err != nil {
		return err
	}
	if r.files.attach(&rec) {
		return nil
	}
	if !r.started {
		if rec.Kind != "exec" {
			r.preExec++
			return nil
		}
		r.started = true
	}
	if rec.tid == 0 {
		return r.write(rec)
	}
	if rec.Failed {
		// Recorded from its call's exit, just before the call's result,
		// which can keep the path change its hook sent instead.
		if c := r.calls[rec.tid]; c != nil && c.hasOp {
			// One already held is from a call whose result never came.
			if c.hasFailure {
				if err := r.write(c.failure); err != nil {
					return err
				}
			}
			c.failure, c.hasFailure = rec, true
			return nil
		}
		return r.write(rec)
	}
	c := r.callOf(rec.tid)
	if rec.Kind == "open" {
		// The call's own file is the first it reaches; a later one, as a
		// FUSE passthrough's backing file, is written as done.
		if c.hasOpen {
			return r.write(rec)
		}
		c.open, c.hasOpen = rec, true
		return nil
	}
	// A path change from another call means that call's result never came;
	// one from the same call is its hook run again, as after breaking a
	// delegation. Calls are told apart by syscall number alone, so two of the
	// same syscall in a row are confused only once a result was dropped.
	if c.hasOp && c.op.nr != rec.nr {
		r.unsettled++
	}
	// A failure comes after its call's hooks, so one held is from an earlier
	// call; it stands, as the failure of a call with no result does.
	if c.hasFailure {
		c.hasFailure = false
		if err := r.write(c.failure); err != nil {
			return err
		}
	}
	c.op, c.hasOp = rec, true
	return nil
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
	if h.n1 != 0 && c.hasName {
		return nil
	}
	if h.n1 == 0 {
		r.named = true
	}
	// An open still waiting is the last call's, whose result never came.
	if err := r.lose(c); err != nil {
		return err
	}
	name := raw[hdrLen:]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
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

// write writes rec as the recording's next line.
func (r *recorder) write(rec record) error {
	// Taken at the event, so a wall-clock step mid-run shifts later times as
	// it shifts the proxy's.
	at := int64(rec.boot) + r.offset(rec.boot)
	r.counts[tally{rec.Kind, rec.Failed}]++
	r.total++
	r.line = appendRecord(r.line[:0], &rec, &r.stamp, at)
	_, err := r.w.Write(r.line)
	return err
}

// loss is what the BPF side counted, read once the ring buffer is drained,
// each counter with its own read error.
type loss struct {
	dropped, untracked, internal uint64
	errDropped, errUntracked     error
	missed                       count
	// errClock is why the realtime clock's sets stopped being followed.
	errClock error
}

// finish reports a one-line tally to the log and writes the end line, then
// flushes the recording.
func (r *recorder) finish(l loss) error {
	// Times are off only if the clock was set after it was lost.
	if l.errClock != nil {
		fmt.Fprintln(r.log, "filesystem-audit: lost track of the realtime clock:", l.errClock)
	}
	// An open whose call never returned while the tracer ran reached its
	// file, but whether it succeeded is unknown.
	waiting := make([]record, 0, len(r.calls))
	for _, c := range r.calls {
		if c.pending() {
			r.unsettled++
		}
		waiting = c.leftovers(waiting)
	}
	sort.SliceStable(waiting, func(i, j int) bool { return waiting[i].boot < waiting[j].boot })
	for _, rec := range waiting {
		if err := r.write(rec); err != nil {
			return err
		}
	}
	untracked := l.untracked + uint64(r.unsettled)
	// attachAll refuses to start without do_filp_open or do_file_open, so
	// this is a kernel whose open(2) no longer passes the one attached.
	if !r.named && r.unnamed > 0 {
		fmt.Fprintln(r.log, "filesystem-audit: no open passed do_filp_open; failed opens went unrecorded")
		untracked += uint64(r.unnamed)
	}
	lines := make([]string, 0, len(r.counts))
	for k, n := range r.counts {
		name := k.kind
		if k.failed {
			name += " failed"
		}
		lines = append(lines, fmt.Sprintf("filesystem-audit: %-13s %d", name, n))
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Fprintln(r.log, l)
	}
	fmt.Fprintf(r.log, "filesystem-audit: total=%d dropped=%d untracked=%d host-missed=%d internal-skipped=%d pre-exec-skipped=%d\n",
		r.total, l.dropped, untracked, l.missed.n, l.internal, r.preExec)
	// Without every count the recording cannot claim to be complete, so it is
	// left without its end line.
	if err := errors.Join(l.errDropped, l.errUntracked, l.missed.err); err != nil {
		fmt.Fprintln(r.log, "filesystem-audit: read loss counters:", err)
		return r.w.Flush()
	}
	if err := json.NewEncoder(r.w).Encode(end{Kind: "end", Dropped: l.dropped, Untracked: untracked, HostMissed: l.missed.n}); err != nil {
		return err
	}
	return r.w.Flush()
}

// end is the recording's last line, written only once every queued event is
// out, so a recording without it was cut short. Dropped events found the ring
// buffer full, and Untracked calls found a tracking map full or had a return
// the tracer never saw, or, when no open passed its name, failed opens that
// came without one. HostMissed runs the kernel skipped between attaching
// and the stop signal; the summary does not count them as lost, since any of
// them may have been another process's.
type end struct {
	Kind       string `json:"kind"`
	Dropped    uint64 `json:"dropped"`
	Untracked  uint64 `json:"untracked"`
	HostMissed uint64 `json:"host_missed"`
}

// execFiles holds each process's resolved exec target until its exec record
// arrives. An exec that fails after resolving its file sends no exec record, so
// its entry stays until the process's next exec-file replaces it or a fork
// reuses its pid.
type execFiles map[uint32]record

// attach takes in an exec-file record, keeping its path for the exec that
// follows, and reports true so the caller drops it. An exec record gets that
// path, with the name it was run by moved to Name. A fork record drops the
// entry for its pid.
func (f execFiles) attach(r *record) bool {
	switch r.Kind {
	case "exec-file":
		f[r.PID] = *r
		return true
	case "fork":
		delete(f, r.PID)
	case "exec":
		if t, ok := f[r.PID]; ok {
			delete(f, r.PID)
			r.Name, r.Path, r.Memfd, r.Deleted = r.Path, t.Path, t.Memfd, t.Deleted
		}
	}
	return false
}

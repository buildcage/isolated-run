package main

import (
	"bufio"
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
	// none stands in for the call of a thread that sent nothing yet.
	none call
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
		// Its failure stands, as the failure of a call with no result does.
		if c.hasFailure {
			c.hasFailure = false
			if err := r.write(c.failure); err != nil {
				return err
			}
		}
	}
	c.op, c.hasOp = rec, true
	return nil
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

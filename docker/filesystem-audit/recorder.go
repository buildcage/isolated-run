package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// recorder writes the ring buffer's samples as the recording's lines, and
// tallies them for the step log.
type recorder struct {
	w   *bufio.Writer
	log io.Writer
	// offset is bootOffset, read once per line written.
	offset func() (int64, error)
	files  execFiles
	// calls holds, per thread, what it sent while in a syscall, until the
	// call's result arrives.
	calls map[uint32]*call
	// line is reused for each line written.
	line    []byte
	counts  map[tally]int
	preExec int
	// unsettled counts calls whose result never arrived.
	unsettled int
	// named counts the names open(2) calls passed do_filp_open with, and
	// unnamed their failures that came with none.
	named, unnamed int
	total          int
	started        bool
}

// call is what one thread sent while in a syscall.
type call struct {
	// op is a path change its hook sent, whose result says whether it
	// happened, and failure the call's failure recorded from its exit.
	op, failure *record
	// name is an open's name, open the file it reached, and created says it
	// reached its create step.
	name, open *record
	created    bool
}

// tally is what the step log counts lines by.
type tally struct {
	kind   string
	failed bool
}

func newRecorder(w *bufio.Writer, log io.Writer, offset func() (int64, error)) *recorder {
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
	rec, err := decode(raw)
	if err != nil {
		return err
	}
	if r.files.attach(&rec) {
		return nil
	}
	switch rec.Kind {
	case "result":
		return r.settle(rec)
	case "exit":
		return r.exited(rec.tid)
	}
	if !r.started {
		if rec.Kind != "exec" {
			if rec.Kind != "open-name" && rec.Kind != "open-create" {
				r.preExec++
			}
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
		if c := r.calls[rec.tid]; c != nil && c.op != nil {
			c.failure = &rec
			return nil
		}
		return r.write(rec)
	}
	c := r.call(rec.tid)
	switch {
	case rec.Kind == "open-name":
		return r.openName(c, rec)
	case rec.Kind == "open-create":
		c.created = true
	case rec.Kind == "open":
		// The call's own file is the first it reaches; a later one, as a
		// FUSE passthrough's backing file, is written as done.
		if c.open != nil {
			return r.write(rec)
		}
		c.open = &rec
	default:
		// A path change from another call means that call's result never
		// came; one from the same call is its hook run again, as after
		// breaking a delegation.
		if c.op != nil && c.op.nr != rec.nr {
			r.unsettled++
		}
		c.op = &rec
	}
	return nil
}

// call is thread tid's call, created if absent.
func (r *recorder) call(tid uint32) *call {
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
func (r *recorder) openName(c *call, name record) error {
	if name.caller && c.name != nil {
		return nil
	}
	if !name.caller {
		r.named++
	}
	// An open still waiting is the last call's, whose result never came.
	if err := r.lose(c); err != nil {
		return err
	}
	c.name = &name
	return nil
}

// lose writes what c holds as if its call's result never came: an open as
// done and a failure as recorded, counting the call once.
func (r *recorder) lose(c *call) error {
	open, failure := c.open, c.failure
	if c.op == nil && c.name == nil && open == nil {
		return nil
	}
	*c = call{}
	r.unsettled++
	if failure != nil {
		if err := r.write(*failure); err != nil {
			return err
		}
	}
	if open == nil {
		return nil
	}
	return r.write(*open)
}

// settle writes what the thread sent during the call res ends. A path change
// is done, or refused unless the exit's record stands for the failure. An
// open is done, refused, or both if it created its file first; one that
// failed before reaching a file is written under its name. A restarted call
// drops them, as its rerun sends them again.
func (r *recorder) settle(res record) error {
	c := r.calls[res.tid]
	if c == nil {
		// runc's own opens before the first exec send no name the reader keeps.
		if r.started && res.bits&resultOpen != 0 && res.ret < 0 && !isRestart(res.ret) {
			r.unnamed++
		}
		return nil
	}
	if err := r.settleOp(c, res); err != nil {
		return err
	}
	if res.bits&resultOpen != 0 {
		if err := r.settleOpen(c, res); err != nil {
			return err
		}
	}
	if c.op == nil && c.name == nil && c.open == nil {
		delete(r.calls, res.tid)
	}
	return nil
}

func (r *recorder) settleOp(c *call, res record) error {
	op, failure := c.op, c.failure
	c.op, c.failure = nil, nil
	switch {
	case op == nil:
		return nil
	case op.nr != res.nr:
		// Sent from a call whose own result never came.
		r.unsettled++
	case isRestart(res.ret):
	case res.ret >= 0:
		return r.write(*op)
	case res.bits&resultWatched == 0 || res.bits&resultFD != 0:
		op.Err, op.Failed = -res.ret, true
		return r.write(*op)
	}
	if failure == nil {
		return nil
	}
	return r.write(*failure)
}

func (r *recorder) settleOpen(c *call, res record) error {
	open, name, created := c.open, c.name, c.created
	c.open, c.name, c.created = nil, nil, false
	switch {
	case isRestart(res.ret):
		return nil
	case open != nil:
		if res.ret >= 0 || created {
			if err := r.write(*open); err != nil || res.ret >= 0 {
				return err
			}
		}
		open.Err, open.Failed = -res.ret, true
		return r.write(*open)
	case res.ret >= 0:
		return nil
	case name != nil:
		return r.write(failedOpen(*name, res))
	}
	r.unnamed++
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
	// Read per event, so a wall-clock step mid-run shifts later times as it
	// shifts the proxy's.
	offset, err := r.offset()
	if err != nil {
		return err
	}
	r.counts[tally{rec.Kind, rec.Failed}]++
	r.total++
	r.line = appendRecord(r.line[:0], &rec, wallClock(rec.boot, offset))
	_, err = r.w.Write(r.line)
	return err
}

// loss is what the BPF side counted, read once the ring buffer is drained,
// each counter with its own read error.
type loss struct {
	dropped, untracked, internal uint64
	errDropped, errUntracked     error
	missed                       count
}

// finish reports a one-line tally to the log and writes the end line, then
// flushes the recording.
func (r *recorder) finish(l loss) error {
	// An open whose call never returned while the tracer ran reached its
	// file, but whether it succeeded is unknown.
	waiting := make([]record, 0, len(r.calls))
	for _, c := range r.calls {
		if c.op != nil || c.name != nil || c.open != nil {
			r.unsettled++
		}
		for _, rec := range []*record{c.open, c.failure} {
			if rec != nil {
				waiting = append(waiting, *rec)
			}
		}
	}
	sort.Slice(waiting, func(i, j int) bool { return waiting[i].boot < waiting[j].boot })
	for _, rec := range waiting {
		if err := r.write(rec); err != nil {
			return err
		}
	}
	untracked := l.untracked + uint64(r.unsettled)
	if r.named == 0 && r.unnamed > 0 {
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
// the tracer never saw. HostMissed runs the kernel skipped between attaching
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

// bootOffset is CLOCK_REALTIME minus CLOCK_BOOTTIME, read back to back, so
// adding it to an event's boot timestamp gives the wall-clock time of the
// access.
func bootOffset() (int64, error) {
	var boot, real unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return 0, fmt.Errorf("read CLOCK_BOOTTIME: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &real); err != nil {
		return 0, fmt.Errorf("read CLOCK_REALTIME: %w", err)
	}
	return real.Nano() - boot.Nano(), nil
}

// wallClock is an event's boot timestamp as UTC wall-clock time.
func wallClock(boot uint64, offset int64) time.Time {
	return time.Unix(0, int64(boot)+offset).UTC()
}

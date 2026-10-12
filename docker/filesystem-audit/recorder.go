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
	enc *json.Encoder
	log io.Writer
	// offset is bootOffset, read once per line written.
	offset  func() (int64, error)
	files   execFiles
	counts  map[string]int
	preExec int
	total   int
	started bool
}

func newRecorder(w *bufio.Writer, log io.Writer, offset func() (int64, error)) *recorder {
	return &recorder{
		w:      w,
		enc:    json.NewEncoder(w),
		log:    log,
		offset: offset,
		files:  execFiles{},
		counts: map[string]int{},
	}
}

// add writes one sample out. Events before the sandboxed command's first exec
// belong to runc's own setup and are dropped; the cgroup holds nothing else
// before then.
func (r *recorder) add(raw []byte) error {
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
	// Read per event, so a wall-clock step mid-run shifts later times as it
	// shifts the proxy's.
	offset, err := r.offset()
	if err != nil {
		return err
	}
	rec.Time = wallTime(rec.boot, offset)
	if rec.Failed {
		r.counts[rec.Kind+" failed"]++
	} else {
		r.counts[rec.Kind]++
	}
	r.total++
	return r.enc.Encode(rec)
}

// loss is what the BPF side counted, read once the ring buffer is drained,
// each counter with its own read error.
type loss struct {
	dropped, untracked, internal, named, unheld   uint64
	errDropped, errUntracked, errNamed, errUnheld error
	missed                                        count
	tailsPeak                                     string
	tailsMax                                      uint32
}

// finish reports a one-line tally to the log and writes the end line, then
// flushes the recording.
func (r *recorder) finish(l loss) error {
	untracked := l.untracked
	if l.errNamed == nil && l.errUnheld == nil && l.named == 0 && l.unheld > 0 {
		fmt.Fprintln(r.log, "filesystem-audit: no open passed do_filp_open; failed opens went unrecorded")
		untracked += l.unheld
	}
	kinds := make([]string, 0, len(r.counts))
	for k := range r.counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(r.log, "filesystem-audit: %-13s %d\n", k, r.counts[k])
	}
	fmt.Fprintf(r.log, "filesystem-audit: total=%d dropped=%d untracked=%d host-missed=%d internal-skipped=%d pre-exec-skipped=%d tails-peak=%s/%d\n",
		r.total, l.dropped, untracked, l.missed.n, l.internal, r.preExec, l.tailsPeak, l.tailsMax)
	// Without every count the recording cannot claim to be complete, so it is
	// left without its end line.
	if err := errors.Join(l.errDropped, l.errUntracked, l.errNamed, l.errUnheld, l.missed.err); err != nil {
		fmt.Fprintln(r.log, "filesystem-audit: read loss counters:", err)
		return r.w.Flush()
	}
	if err := r.enc.Encode(end{Kind: "end", Dropped: l.dropped, Untracked: untracked, HostMissed: l.missed.n}); err != nil {
		return err
	}
	return r.w.Flush()
}

// end is the recording's last line, written only once every queued event is
// out, so a recording without it was cut short. Dropped events found the ring
// buffer full, and Untracked calls found a tracking map full. HostMissed runs the
// kernel skipped between attaching and the stop signal; the summary does not
// count them as lost, since any of them may have been another process's.
type end struct {
	Kind       string `json:"kind"`
	Dropped    uint64 `json:"dropped"`
	Untracked  uint64 `json:"untracked"`
	HostMissed uint64 `json:"host_missed"`
}

// execFiles holds each process's resolved exec target until its exec record
// arrives.
type execFiles map[uint32]record

// attach takes in an exec-file record, keeping its path for the exec that
// follows, and reports true so the caller drops it. An exec record gets that
// path, with the name it was run by moved to Name.
func (f execFiles) attach(r *record) bool {
	switch r.Kind {
	case "exec-file":
		f[r.PID] = *r
		return true
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

// wallTime formats an event's boot timestamp as UTC to the millisecond.
func wallTime(boot uint64, offset int64) string {
	return time.Unix(0, int64(boot)+offset).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

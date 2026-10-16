// Command filesystem-audit records the file accesses of every task in one
// cgroup v2 subtree and writes them as JSON lines until it is signalled to
// stop. It attaches eBPF programs to the kernel's VFS and syscall layers,
// so it observes the accesses as the kernel sees them, below any library
// the sandboxed command links against.
//
// It is compiled into buildcage's proxy image and, like runc, extracted
// onto the runner host and run there natively (it needs root, BTF and a
// cgroup v2 host). It creates the sandbox's cgroup before runc joins it, so
// nothing the sandboxed command does is missed. It records only; it never
// blocks an access. See docs/development.md and the isolated-run action.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run ./cmd/gensyscallnames

// -mcpu=v3 for its 32-bit jumps; every kernel the tracer runs on has them.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags -mcpu=v3 -type event -type kind -type result_bit filesystemAudit bpf/filesystem_audit.bpf.c

func main() {
	cgPath := flag.String("cgroup", "", "cgroup v2 directory to watch, created if missing")
	out := flag.String("out", "", "JSON lines output file")
	ready := flag.String("ready", "", "file to create once the programs are attached")
	pidfile := flag.String("pidfile", "", "file to write this process's pid to, for the caller to stop it")
	watchPid := flag.Int("watch-pid", 0, "process whose exit stops the tracer, as a signal would")
	allowed := flag.String("allowed-syscalls", "", "comma-separated syscalls the sandbox's seccomp profile allows outright; any other failing EPERM is recorded as refused")
	flag.Parse()
	if *cgPath == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	// stderr is a pipe the action reads; once the action is gone, a write to
	// it must fail rather than kill the tracer before it flushes the record.
	signal.Ignore(syscall.SIGPIPE)
	if err := run(*cgPath, *out, *ready, *pidfile, *watchPid, *allowed); err != nil {
		// The action reports the "fatal:" line as the reason the step failed.
		fmt.Fprintln(os.Stderr, "filesystem-audit: fatal:", err)
		os.Exit(1)
	}
}

func run(cgPath, outPath, readyPath, pidPath string, watchPid int, allowedSyscalls string) error {
	// Set up before loading, which takes a while, so an action that dies or
	// stops the tracer meanwhile does not leave it recording.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	if watchPid > 0 {
		err := stopOnExit(watchPid, sig)
		if errors.Is(err, unix.ESRCH) {
			return errors.New("the action that started it has already exited")
		}
		// Otherwise only a backstop for the action's own stop, so not worth failing over.
		if err != nil {
			fmt.Fprintf(os.Stderr, "filesystem-audit: cannot watch pid %d: %v\n", watchPid, err)
		}
	}
	// Written before loading so the post step can stop a tracer still loading.
	if pidPath != "" {
		if err := writeNew(pidPath, []byte(fmt.Sprintln(os.Getpid()))); err != nil {
			return err
		}
	}

	cg, created, err := prepareCgroup(cgPath)
	if err != nil {
		return err
	}
	defer cg.Close()
	if created {
		// For a start that never ran the sandbox; runc's delete removes it
		// otherwise. rmdir fails on a cgroup still in use.
		defer os.Remove(cg.Name())
	}
	if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		fmt.Fprintf(os.Stderr, "filesystem-audit: active LSMs: %s\n", strings.TrimSpace(string(lsm)))
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	spec, err := loadFilesystemAudit()
	if err != nil {
		return err
	}
	kspec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("read kernel BTF: %w", err)
	}
	if err := requireLinux61(kspec); err != nil {
		return err
	}
	dropAbsentPrograms(spec, kspec)
	if err := setSyscallNumbers(spec); err != nil {
		return err
	}
	if stopRequested(sig) {
		return errStoppedEarly
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load: %+v", ve)
		}
		return fmt.Errorf("load: %w", err)
	}
	defer coll.Close()
	// Before attaching: an empty slot matches no task.
	if err := coll.Maps["target"].Put(uint32(0), uint32(cg.Fd())); err != nil {
		return fmt.Errorf("set watched cgroup: %w", err)
	}
	if err := markRefusable(coll.Maps["refusable"], allowedSyscalls); err != nil {
		return err
	}

	if stopRequested(sig) {
		return errStoppedEarly
	}
	links, err := attachAll(coll)
	for _, l := range links {
		defer l.Close()
	}
	if err != nil {
		return err
	}
	if stopRequested(sig) {
		return errStoppedEarly
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	f, err := create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	defer bw.Flush()

	// Before the ready file, which lets the step start.
	clock, err := newBootClock()
	if err != nil {
		return err
	}
	base, errBase := missedRuns(coll)
	if readyPath != "" {
		if err := writeNew(readyPath, nil); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "filesystem-audit: attached")

	// Read before the flush that ends readLoop, so it has the count by then.
	missed := make(chan count, 1)
	go func() {
		<-sig
		n, err := missedRuns(coll)
		if err = errors.Join(errBase, err); err != nil {
			n, base = 0, 0
		}
		missed <- count{n - base, err}
		rd.Flush() // Read drains what is queued, then returns ErrFlushed.
	}()

	return readLoop(rd, bw, coll, clock, missed)
}

var errStoppedEarly = errors.New("stopped before it attached")

// stopRequested reports a stop that came while starting up. Checked between
// the slow steps, so a stopped tracer exits, and removes its cgroup, before
// the action's stop grace runs out and it is killed.
func stopRequested(sig <-chan os.Signal) bool {
	select {
	case <-sig:
		return true
	default:
		return false
	}
}

// readLoop drains the ring buffer into the recording until the reader is
// flushed.
func readLoop(rd *ringbuf.Reader, w *bufio.Writer, coll *ebpf.Collection, clock *bootClock, missedRun <-chan count) error {
	rec := newRecorder(w, os.Stderr, clock.offset)
	// Reused for each sample: what decode keeps of it is copied.
	var sample ringbuf.Record
	for {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		if err := rd.ReadInto(&sample); err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				break
			}
			// Idle: write out what is buffered, so a tracer killed later loses
			// at most what came since.
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if err := w.Flush(); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if err := rec.add(sample.RawSample); err != nil {
			return err
		}
	}
	l := readLoss(coll, <-missedRun)
	l.errClock = clock.err()
	return rec.finish(l)
}

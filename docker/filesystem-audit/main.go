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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event filesystemAudit bpf/filesystem_audit.bpf.c

const cgroupRoot = "/sys/fs/cgroup"

// optionalProgs are programs whose attach target some supported kernels do
// not expose; each is dropped before load when its function is absent from
// kernel BTF. getname has two spellings (one inlined into the other) and
// names a failed open; backing_file_open (added in 6.7) de-duplicates
// overlayfs layer opens, so on older kernels those opens go unmerged.
var optionalProgs = map[string]string{
	"on_getname":       "getname_flags",
	"on_getname_outer": "getname",
	"on_backing_enter": "backing_file_open",
	"on_backing_exit":  "backing_file_open",
	"on_exec_file":     "security_bprm_creds_for_exec",
}

// getnameProgs is the subset of optionalProgs that records a failed open's
// name; at least one must attach.
var getnameProgs = map[string]bool{"on_getname": true, "on_getname_outer": true}

func main() {
	cgPath := flag.String("cgroup", "", "cgroup v2 directory to watch, created if missing")
	out := flag.String("out", "", "JSON lines output file")
	ready := flag.String("ready", "", "file to create once the programs are attached")
	pidfile := flag.String("pidfile", "", "file to write this process's pid to, for the caller to stop it")
	flag.Parse()
	if *cgPath == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*cgPath, *out, *ready, *pidfile); err != nil {
		fmt.Fprintln(os.Stderr, "filesystem-audit:", err)
		os.Exit(1)
	}
}

func run(cgPath, outPath, readyPath, pidPath string) error {
	cgid, level, err := prepareCgroup(cgPath)
	if err != nil {
		return err
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
	if err := spec.Variables["target_cgid"].Set(cgid); err != nil {
		return err
	}
	if err := spec.Variables["target_level"].Set(level); err != nil {
		return err
	}
	dropAbsentPrograms(spec)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load: %+v", ve)
		}
		return fmt.Errorf("load: %w", err)
	}
	defer coll.Close()

	links, err := attachAll(coll, spec)
	for _, l := range links {
		defer l.Close()
	}
	if err != nil {
		return err
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	// The tracer runs as root; 0644 regardless of root's umask so the action,
	// running as the runner, can read the recording back.
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	defer bw.Flush()

	if pidPath != "" {
		if err := os.WriteFile(pidPath, []byte(fmt.Sprintln(os.Getpid())), 0o644); err != nil {
			return err
		}
	}
	if readyPath != "" {
		if err := os.WriteFile(readyPath, nil, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "filesystem-audit: attached")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Flush() // Read drains what is queued, then returns ErrFlushed.
	}()

	return readLoop(rd, bw, coll)
}

// prepareCgroup verifies the host is cgroup v2, creates the watched cgroup
// if missing, and returns its id and its depth below the cgroup root (the
// ancestor level the programs compare against).
func prepareCgroup(cgPath string) (cgid uint64, level uint32, err error) {
	var sfs unix.Statfs_t
	if err = unix.Statfs(cgroupRoot, &sfs); err != nil {
		return 0, 0, err
	}
	if sfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0, 0, fmt.Errorf("%s is not cgroup v2 (magic %#x)", cgroupRoot, sfs.Type)
	}
	abs := filepath.Clean(cgPath)
	rel, err := filepath.Rel(cgroupRoot, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return 0, 0, fmt.Errorf("cgroup path must be below %s: %s", cgroupRoot, cgPath)
	}
	if err = os.MkdirAll(abs, 0o755); err != nil {
		return 0, 0, err
	}
	var st unix.Stat_t
	if err = unix.Stat(abs, &st); err != nil {
		return 0, 0, err
	}
	level = uint32(len(strings.Split(rel, "/")))
	fmt.Fprintf(os.Stderr, "filesystem-audit: cgroup %s id=%d level=%d\n", abs, st.Ino, level)
	return st.Ino, level, nil
}

// dropAbsentPrograms removes optional programs whose attach target the
// running kernel does not expose, so loading does not fail on a missing one.
func dropAbsentPrograms(spec *ebpf.CollectionSpec) {
	kspec, err := btf.LoadKernelSpec()
	if err != nil {
		return
	}
	for prog, fn := range optionalProgs {
		var f *btf.Func
		if err := kspec.TypeByName(fn, &f); err != nil {
			fmt.Fprintf(os.Stderr, "filesystem-audit: %s absent from kernel BTF, skipped\n", fn)
			delete(spec.Programs, prog)
		}
	}
}

// attachAll attaches every loaded program. A classic syscall tracepoint
// needs tracefs; where it is missing the failed path operations go
// unrecorded, which is a reduced result, not a failure, so those attach
// errors only warn. At least one getname spelling must attach, or a failed
// open would have no name.
func attachAll(coll *ebpf.Collection, spec *ebpf.CollectionSpec) ([]link.Link, error) {
	var links []link.Link
	getnames := 0
	for name, p := range coll.Programs {
		var l link.Link
		var err error
		if p.Type() == ebpf.TracePoint {
			group, tp, _ := strings.Cut(strings.TrimPrefix(spec.Programs[name].SectionName, "tracepoint/"), "/")
			l, err = link.Tracepoint(group, tp, p, nil)
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: p})
		}
		_, optional := optionalProgs[name]
		if err != nil {
			if optional || p.Type() == ebpf.TracePoint {
				fmt.Fprintf(os.Stderr, "filesystem-audit: %s not attached: %v\n", name, err)
				continue
			}
			return links, fmt.Errorf("attach %s: %w", name, err)
		}
		links = append(links, l)
		if getnameProgs[name] {
			getnames++
		}
	}
	if getnames == 0 {
		return links, errors.New("neither getname nor getname_flags can be traced")
	}
	return links, nil
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

// readLoop drains the ring buffer into the writer until the reader is
// flushed, then reports a one-line tally to stderr. Events before the
// sandboxed command's first exec belong to runc's own setup and are
// dropped; the cgroup holds nothing else before then.
func readLoop(rd *ringbuf.Reader, w *bufio.Writer, coll *ebpf.Collection) error {
	enc := json.NewEncoder(w)
	counts := map[string]int{}
	files := execFiles{}
	preExec, total := 0, 0
	started := false
	for {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		rec, err := rd.Read()
		if err != nil {
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
		r, err := decode(rec.RawSample)
		if err != nil {
			return err
		}
		if files.attach(&r) {
			continue
		}
		if !started {
			if r.Kind != "exec" {
				preExec++
				continue
			}
			started = true
		}
		// Read per event, so a wall-clock step mid-run shifts later times as it
		// shifts the proxy's.
		offset, err := bootOffset()
		if err != nil {
			return err
		}
		r.Time = wallTime(r.boot, offset)
		counts[r.Kind]++
		total++
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	dropped, errDropped := sumPerCPU(coll.Maps["drops"])
	untracked, errUntracked := sumPerCPU(coll.Maps["untracked"])
	internal, _ := sumPerCPU(coll.Maps["skipped_internal"])
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(os.Stderr, "filesystem-audit: %-11s %d\n", k, counts[k])
	}
	fmt.Fprintf(os.Stderr, "filesystem-audit: total=%d dropped=%d untracked=%d internal-skipped=%d pre-exec-skipped=%d\n",
		total, dropped, untracked, internal, preExec)
	// Without both counts the recording cannot claim to be complete, so it is
	// left without its end line.
	if err := errors.Join(errDropped, errUntracked); err != nil {
		fmt.Fprintln(os.Stderr, "filesystem-audit: read loss counters:", err)
		return w.Flush()
	}
	if err := enc.Encode(end{Kind: "end", Dropped: dropped, Untracked: untracked}); err != nil {
		return err
	}
	return w.Flush()
}

// end is the recording's last line, written only once every queued event is
// out, so a recording without it was cut short. Dropped events found the ring
// buffer full, and Untracked calls found a tracking map full.
type end struct {
	Kind      string `json:"kind"`
	Dropped   uint64 `json:"dropped"`
	Untracked uint64 `json:"untracked"`
}

func sumPerCPU(m *ebpf.Map) (uint64, error) {
	var per []uint64
	if err := m.Lookup(uint32(0), &per); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range per {
		sum += v
	}
	return sum, nil
}

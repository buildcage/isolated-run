// file-audit (PoC): attaches eBPF programs that record file opens, execs,
// unlinks and renames made inside one cgroup v2 subtree, and writes them as
// JSON lines until SIGINT/SIGTERM. The cgroup is created if missing so the
// tracer can be attached before runc puts the sandbox into it.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event fileAudit bpf/file_audit.bpf.c

const cgroupRoot = "/sys/fs/cgroup"

type record struct {
	TimeNs int64  `json:"t"`
	Kind   string `json:"kind"`
	PID    uint32 `json:"pid"`
	PPID   uint32 `json:"ppid"`
	Comm   string `json:"comm"`
	Path   string `json:"path,omitempty"`
	To     string `json:"to,omitempty"`
	Access string `json:"access,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`
	Args   string `json:"args,omitempty"`
	Err    int32  `json:"err,omitempty"`
}

var benchMode string

func main() {
	cgPath := flag.String("cgroup", "", "cgroup v2 directory to watch (created if missing)")
	out := flag.String("out", "", "JSON lines output file")
	ready := flag.String("ready", "", "file created once programs are attached")
	flag.StringVar(&benchMode, "bench", "", "PoC overhead breakdown: 'nomatch' filters out everything in-kernel, 'discard' skips writing records")
	flag.Parse()
	if *cgPath == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*cgPath, *out, *ready); err != nil {
		fmt.Fprintln(os.Stderr, "file-audit:", err)
		os.Exit(1)
	}
}

func run(cgPath, outPath, readyPath string) error {
	var sfs unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &sfs); err != nil {
		return err
	}
	if sfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not cgroup v2 (magic %#x)", cgroupRoot, sfs.Type)
	}
	abs := filepath.Clean(cgPath)
	rel, err := filepath.Rel(cgroupRoot, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("cgroup path must be below %s: %s", cgroupRoot, cgPath)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Stat(abs, &st); err != nil {
		return err
	}
	level := uint32(len(strings.Split(rel, "/")))
	fmt.Fprintf(os.Stderr, "file-audit: cgroup %s id=%d level=%d\n", abs, st.Ino, level)
	if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		fmt.Fprintf(os.Stderr, "file-audit: active LSMs: %s\n", strings.TrimSpace(string(lsm)))
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	spec, err := loadFileAudit()
	if err != nil {
		return err
	}
	cgid := st.Ino
	if benchMode == "nomatch" {
		cgid = 0
	}
	if err := spec.Variables["target_cgid"].Set(cgid); err != nil {
		return err
	}
	if err := spec.Variables["target_level"].Set(level); err != nil {
		return err
	}
	var objs fileAuditObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load: %+v", ve)
		}
		return fmt.Errorf("load: %w", err)
	}
	defer objs.Close()

	for name, p := range map[string]*ebpf.Program{
		"open": objs.OnOpen, "exec": objs.OnExec, "unlink": objs.OnSecurityPathUnlink,
		"rmdir": objs.OnSecurityPathRmdir, "mkdir": objs.OnSecurityPathMkdir,
		"rename": objs.OnRename, "chmod": objs.OnChmod, "symlink": objs.OnSymlink,
		"backing-enter": objs.OnBackingEnter, "backing-exit": objs.OnBackingExit,
		"link": objs.OnLink, "truncate": objs.OnTruncate, "chown": objs.OnChown,
		"openat2-enter": objs.OnOpenat2Enter, "getname": objs.OnGetname,
		"openat2-exit": objs.OnOpenat2Exit, "open-enter": objs.OnOpenEnter, "open-exit": objs.OnOpenExit,
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		defer l.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	defer bw.Flush()
	enc := json.NewEncoder(bw)

	if readyPath != "" {
		if err := os.WriteFile(readyPath, nil, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "file-audit: attached")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		// Read returns what is already queued, then ErrFlushed.
		rd.Flush()
	}()

	counts := map[string]int{}
	preExec := 0
	started := false
	unique := map[string]struct{}{}
	for {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				break
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return err
		}
		r, err := decode(rec.RawSample)
		if err != nil {
			return err
		}
		// Until its first exec the cgroup holds only runc's own init.
		// Cut by event order, not comm, which the sandbox can set.
		if !started {
			if r.Kind != "exec" {
				preExec++
				continue
			}
			started = true
		}
		counts[r.Kind]++
		unique[r.Kind+" "+r.Access+" "+r.Path] = struct{}{}
		if benchMode == "discard" {
			continue
		}
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	rd.Close()

	dropped, internal := sumPerCPU(objs.Drops), sumPerCPU(objs.SkippedInternal)
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	total := 0
	for _, k := range kinds {
		total += counts[k]
		fmt.Fprintf(os.Stderr, "file-audit: %-7s %d\n", k, counts[k])
	}
	fmt.Fprintf(os.Stderr, "file-audit: total=%d unique=%d dropped=%d internal-skipped=%d pre-exec-skipped=%d\n", total, len(unique), dropped, internal, preExec)
	return nil
}

var kindNames = map[uint32]string{1: "open", 2: "exec", 3: "unlink", 4: "rmdir", 5: "rename", 6: "mkdir", 7: "chmod", 8: "symlink", 9: "link", 10: "truncate", 11: "chown", 12: "open-failed"}

// Mirrors struct event's fixed header in bpf/file_audit.bpf.c.
const (
	hdrLen  = 8*4 + 4 + 16
	pathLen = 4096
)

func sumPerCPU(m *ebpf.Map) uint64 {
	var per []uint64
	var sum uint64
	if err := m.Lookup(uint32(0), &per); err == nil {
		for _, v := range per {
			sum += v
		}
	}
	return sum
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// components splits n NUL-terminated names off the front of b and returns
// them joined as an absolute path (they are stored leaf first).
func components(b []byte, n int, truncated bool) (string, []byte) {
	parts := make([]string, n)
	for i := 0; i < n && len(b) > 0; i++ {
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			j = len(b)
		}
		parts[n-1-i] = string(b[:j])
		if j < len(b) {
			j++
		}
		b = b[j:]
	}
	prefix := "/"
	if truncated {
		prefix = "…/"
	}
	return prefix + strings.Join(parts, "/"), b
}

func decode(raw []byte) (record, error) {
	if len(raw) < hdrLen {
		return record{}, fmt.Errorf("short event: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	kind := le.Uint32(raw[0:])
	flags := le.Uint32(raw[12:])
	mode := le.Uint32(raw[16:])
	pathRet := int32(le.Uint32(raw[20:]))
	argsLen := le.Uint32(raw[24:])
	n1, n2, truncated := int(raw[32]), int(raw[33]), raw[34] != 0
	data := raw[hdrLen:]
	r := record{
		TimeNs: time.Now().UnixNano(),
		Kind:   kindNames[kind],
		PID:    le.Uint32(raw[4:]),
		PPID:   le.Uint32(raw[8:]),
		Comm:   cstr(raw[36:52]),
	}
	switch kind {
	case 1:
		if pathRet < 0 {
			r.Err = pathRet
		} else {
			r.Path = cstr(data)
		}
		r.Flags = flags
		r.Access = access(flags, mode)
	case 12:
		r.Path = cstr(data)
		r.Err = pathRet
	case 2:
		r.Path = cstr(data)
		if int(pathLen+argsLen) <= len(data) {
			a := data[pathLen : pathLen+argsLen]
			r.Args = strings.TrimRight(strings.ReplaceAll(string(a), "\x00", " "), " ")
		}
	case 3, 4, 6, 10:
		r.Path, _ = components(data, n1, truncated)
	case 11:
		r.Path, _ = components(data, n1, truncated)
		r.Flags = flags
		r.Args = fmt.Sprintf("%d:%d", flags, mode)
	case 7:
		r.Path, _ = components(data, n1, truncated)
		r.Flags = mode
	case 8:
		r.To = cstr(data)
		r.Path, _ = components(data[pathRet:], n1, truncated)
	case 5, 9:
		var rest []byte
		r.Path, rest = components(data, n1, truncated)
		r.To, _ = components(rest, n2, truncated)
	}
	return r, nil
}

const fmodeExec = 0x20

func access(flags, mode uint32) string {
	var s string
	switch flags & unix.O_ACCMODE {
	case unix.O_RDONLY:
		s = "r"
	case unix.O_WRONLY:
		s = "w"
	default:
		s = "rw"
	}
	if flags&unix.O_CREAT != 0 {
		s += "c"
	}
	if flags&unix.O_TRUNC != 0 {
		s += "t"
	}
	if mode&fmodeExec != 0 {
		s += "x"
	}
	return s
}

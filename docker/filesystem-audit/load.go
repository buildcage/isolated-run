package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// optionalProgs are programs whose attach target some supported kernels do
// not expose; each is dropped before load when its function is absent from
// kernel BTF. do_filp_open, renamed in 7.0, sends an open's name as getname
// copied it.
var optionalProgs = map[string]string{
	"on_filp_open":     "do_filp_open",
	"on_do_file_open":  "do_file_open",
	"on_exec_file":     "security_bprm_creds_for_exec",
	"on_file_truncate": "security_file_truncate",
}

// openNameProgs is the subset of optionalProgs that sends an open's name; at
// least one must attach.
var openNameProgs = map[string]bool{"on_filp_open": true, "on_do_file_open": true}

// requireLinux61 refuses a kernel older than 6.1, the oldest the tracer
// supports, told by the BPF memory allocator that release added.
func requireLinux61(kspec *btf.Spec) error {
	var s *btf.Struct
	err := kspec.TypeByName("bpf_mem_alloc", &s)
	if errors.Is(err, btf.ErrNotFound) {
		return errors.New("the kernel is older than Linux 6.1")
	}
	if err != nil {
		return fmt.Errorf("read kernel BTF: %w", err)
	}
	return nil
}

// dropAbsentPrograms removes optional programs whose attach target the
// running kernel does not expose, so loading does not fail on a missing one.
func dropAbsentPrograms(spec *ebpf.CollectionSpec, kspec *btf.Spec, log io.Writer) {
	for prog, fn := range optionalProgs {
		var f *btf.Func
		if err := kspec.TypeByName(fn, &f); err != nil {
			fmt.Fprintf(log, "filesystem-audit: %s absent from kernel BTF, skipped\n", fn)
			delete(spec.Programs, prog)
		}
	}
}

// setSyscallNumbers gives the BPF program the architecture's syscall numbers;
// those it leaves unset are syscalls the architecture lacks.
func setSyscallNumbers(spec *ebpf.CollectionSpec) error {
	for name, nr := range syscallNumbers {
		v, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("no variable %s in the BPF program", name)
		}
		if err := v.Set(nr); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	return nil
}

// markRefusable marks each native syscall the sandbox's seccomp profile does
// not allow outright, given the comma-separated names it does; with none
// given, no refusal is recorded.
func markRefusable(m *ebpf.Map, allowed string) error {
	if allowed == "" {
		return nil
	}
	ok := map[string]bool{}
	for _, name := range strings.Split(allowed, ",") {
		ok[name] = true
	}
	for nr, name := range syscallNames {
		if ok[name] || nr < 0 || nr >= int64(m.MaxEntries()) {
			continue
		}
		if err := m.Put(uint32(nr), uint8(1)); err != nil {
			return fmt.Errorf("mark %s refusable: %w", name, err)
		}
	}
	return nil
}

// attachAll attaches every loaded program, and any that fails is fatal; those
// the kernel does not offer were dropped before load. The exception is one of
// the two spellings of do_filp_open, of which at least one must attach or no
// failed open would have a name.
func attachAll(coll *ebpf.Collection, log io.Writer) ([]link.Link, error) {
	var links []link.Link
	openNames := 0
	for name, p := range coll.Programs {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			if openNameProgs[name] {
				fmt.Fprintf(log, "filesystem-audit: %s not attached: %v\n", name, err)
				continue
			}
			return links, fmt.Errorf("attach %s: %w", name, err)
		}
		links = append(links, l)
		if openNameProgs[name] {
			openNames++
		}
	}
	if openNames == 0 {
		return links, errors.New("neither do_filp_open nor do_file_open can be traced")
	}
	return links, nil
}

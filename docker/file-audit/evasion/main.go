// evasion (PoC): tries ways a sandboxed step could touch files without the
// tracer seeing it. Each case prints its marker so the output can be lined
// up with the tracer's records.
package main

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func report(name string, err error) {
	if err != nil {
		fmt.Printf("CASE %-16s err=%v\n", name, err)
	} else {
		fmt.Printf("CASE %-16s ok\n", name)
	}
}

func main() {
	os.WriteFile("/tmp/secret", []byte("s3cret\n"), 0o600)

	// io_uring bypasses the syscall layer; seccomp should refuse it.
	var params [120]byte
	_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 8, uintptr(unsafe.Pointer(&params[0])), 0)
	if errno != 0 {
		report("io_uring", errno)
	} else {
		report("io_uring", nil)
	}

	fd, err := unix.Openat2(unix.AT_FDCWD, "/etc/hostname", &unix.OpenHow{Flags: unix.O_RDONLY, Resolve: unix.RESOLVE_NO_SYMLINKS})
	report("openat2", err)
	unix.Close(fd)

	// A path longer than a small d_path buffer.
	dir, _ := unix.Open("/tmp", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	seg := strings.Repeat("d", 200)
	for i := 0; i < 8; i++ {
		unix.Mkdirat(dir, seg, 0o755)
		nd, err := unix.Openat(dir, seg, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			report("deep-mkdir", err)
			break
		}
		unix.Close(dir)
		dir = nd
	}
	fd, err = unix.Openat(dir, "deep-file", unix.O_CREAT|unix.O_WRONLY, 0o644)
	report("deep-open", err)
	unix.Close(fd)

	report("hardlink", unix.Link("/tmp/secret", "/tmp/hl"))
	b, err := os.ReadFile("/tmp/hl")
	report("hardlink-read", err)
	_ = b

	// Fileless exec from a memfd.
	mfd, err := unix.MemfdCreate("payload", 0)
	if err == nil {
		bin, _ := os.ReadFile("/bin/true")
		unix.Write(mfd, bin)
		pid, _, _ := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
		if pid == 0 {
			argv0 := []byte("true\x00")
			argv := []uintptr{uintptr(unsafe.Pointer(&argv0[0])), 0}
			empty := []byte("\x00")
			envp := []uintptr{0}
			unix.RawSyscall6(unix.SYS_EXECVEAT, uintptr(mfd), uintptr(unsafe.Pointer(&empty[0])),
				uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])), unix.AT_EMPTY_PATH, 0)
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 99, 0, 0)
		}
		var ws unix.WaitStatus
		unix.Wait4(int(pid), &ws, 0, nil)
		report("memfd-exec", fmt.Errorf("child exit %d", ws.ExitStatus()))
	} else {
		report("memfd-exec", err)
	}

	// O_PATH skips the open hook; reopening through /proc must not.
	pfd, err := unix.Open("/tmp/secret", unix.O_PATH, 0)
	report("o_path", err)
	fd, err = unix.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), unix.O_RDONLY, 0)
	report("o_path-reopen", err)
	unix.Close(fd)

	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, "/tmp/secret", 0)
	if err == nil {
		_, err = unix.OpenByHandleAt(pfd, h, unix.O_RDONLY)
	}
	report("open_by_handle", err)

	report("cgroup-escape", os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(fmt.Sprint(os.Getpid())), 0))

	report("truncate", unix.Truncate("/tmp/secret", 0))
	os.WriteFile("/tmp/other", nil, 0o600)
	report("rename-exchange", unix.Renameat2(unix.AT_FDCWD, "/tmp/secret", unix.AT_FDCWD, "/tmp/other", unix.RENAME_EXCHANGE))
	report("chown", unix.Chown("/tmp/other", os.Getuid(), os.Getgid()))
	fd, _ = unix.Open("/tmp/other", unix.O_RDONLY, 0)
	report("fchmod", unix.Fchmod(fd, 0o640))
	unix.Close(fd)

	// Flood the ring buffer, then do the "real" access.
	for i := 0; i < 500000; i++ {
		fd, _ := unix.Open("/tmp/other", unix.O_RDONLY, 0)
		unix.Close(fd)
	}
	_, err = unix.Open("/etc/shadow", unix.O_RDONLY, 0)
	report("shadow", err)
	fd, err = unix.Open("/etc/shadow-after-flood", unix.O_RDONLY, 0)
	report("after-flood", err)
	fd, err = unix.Open("/etc/passwd", unix.O_RDONLY, 0)
	report("after-flood-ok", err)
	unix.Close(fd)
}

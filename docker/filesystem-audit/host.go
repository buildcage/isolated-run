package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

// create makes a new file, never one already there and never through a
// symlink at the path itself, as the tracer runs as root in a directory the
// runner owns; the action has checked that directory is its own. It is 0644
// whatever root's umask, so the action can read it back.
func create(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func writeNew(path string, data []byte) error {
	f, err := create(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// stopOnExit stops the tracer when pid exits, so it does not outlive an
// action killed before it could stop it. A pidfd, opened while pid is known
// to be alive, cannot follow a later process that reuses the number.
func stopOnExit(pid int, sig chan<- os.Signal) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	go func() {
		defer unix.Close(fd)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(fds, -1)
			if err == nil {
				break
			}
			if err != unix.EINTR {
				fmt.Fprintln(os.Stderr, "filesystem-audit: stopped watching the action:", err)
				return
			}
		}
		select {
		case sig <- syscall.SIGTERM:
		default: // a stop is already pending
		}
	}()
	return nil
}

// prepareCgroup verifies the host is cgroup v2, creates the watched cgroup
// if missing, and opens it for the programs' cgroup array. created says
// whether it made the cgroup itself.
func prepareCgroup(cgPath string) (f *os.File, created bool, err error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &sfs); err != nil {
		return nil, false, err
	}
	if sfs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, false, fmt.Errorf("%s is not cgroup v2 (magic %#x)", cgroupRoot, sfs.Type)
	}
	abs := filepath.Clean(cgPath)
	rel, err := filepath.Rel(cgroupRoot, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, false, fmt.Errorf("cgroup path must be below %s: %s", cgroupRoot, cgPath)
	}
	// Under the runner's own cgroup, which is there already.
	err = os.Mkdir(abs, 0o755)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, false, err
	}
	created = err == nil
	var st unix.Stat_t
	if err = unix.Stat(abs, &st); err == nil {
		f, err = os.Open(abs)
	}
	if err != nil {
		if created {
			os.Remove(abs)
		}
		return nil, false, err
	}
	fmt.Fprintf(os.Stderr, "filesystem-audit: cgroup %s id=%d\n", abs, st.Ino)
	return f, created, nil
}

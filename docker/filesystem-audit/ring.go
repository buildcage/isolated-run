package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// ring reads the BPF ring buffer where it is mapped. One goroutine reads it,
// so unlike cilium/ebpf's reader it takes no lock per record, and it reads
// the producer position and hands space back once per batch rather than per
// record. On arm that lock and those atomics took a third of the reader's
// time.
type ring struct {
	consPage, dataPages []byte
	// consPos and prodPos are the positions the kernel shares; data maps the
	// ring twice over, so no record wraps.
	consPos, prodPos *uintptr
	data             []byte
	mask             uintptr
	epfd, flushFd    int
}

// releaseBytes is how much is read before it is handed back mid-batch, so a
// long batch does not hold the producers' space.
const releaseBytes = 1 << 20

func newRing(m *ebpf.Map) (*ring, error) {
	size := int(m.MaxEntries())
	if size == 0 || size&(size-1) != 0 {
		return nil, fmt.Errorf("ring buffer size %d is not a power of two", size)
	}
	page := os.Getpagesize()
	cons, err := unix.Mmap(m.FD(), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map the ring buffer's consumer page: %w", err)
	}
	data, err := unix.Mmap(m.FD(), int64(page), page+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(cons)
		return nil, fmt.Errorf("map the ring buffer: %w", err)
	}
	r := &ring{
		consPage:  cons,
		dataPages: data,
		consPos:   (*uintptr)(unsafe.Pointer(&cons[0])),
		prodPos:   (*uintptr)(unsafe.Pointer(&data[0])),
		data:      data[page:],
		mask:      uintptr(size - 1),
	}
	if err := r.openWait(m.FD()); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// openWait sets up the epoll that waits for the ring buffer or a flush.
func (r *ring) openWait(fd int) error {
	r.epfd, r.flushFd = -1, -1
	var err error
	if r.epfd, err = unix.EpollCreate1(unix.EPOLL_CLOEXEC); err != nil {
		return fmt.Errorf("epoll: %w", err)
	}
	if r.flushFd, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK); err != nil {
		return fmt.Errorf("eventfd: %w", err)
	}
	for _, f := range []int{fd, r.flushFd} {
		ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(f)}
		if err := unix.EpollCtl(r.epfd, unix.EPOLL_CTL_ADD, f, &ev); err != nil {
			return fmt.Errorf("epoll: %w", err)
		}
	}
	return nil
}

// Flush makes read return once it has read what is queued.
func (r *ring) Flush() error {
	_, err := unix.Write(r.flushFd, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	return err
}

func (r *ring) Close() error {
	var errs []error
	for _, fd := range []int{r.epfd, r.flushFd} {
		if fd >= 0 {
			errs = append(errs, unix.Close(fd))
		}
	}
	if r.dataPages != nil {
		errs = append(errs, unix.Munmap(r.dataPages))
	}
	if r.consPage != nil {
		errs = append(errs, unix.Munmap(r.consPage))
	}
	return errors.Join(errs...)
}

// read passes each record to f until Flush, and calls idle each time the ring
// stays empty for wait. A record is valid only until f returns.
func (r *ring) read(f func([]byte) error, wait time.Duration, idle func() error) error {
	flushing := false
	for {
		n, busy, err := r.drain(f)
		if err != nil {
			return err
		}
		// A record still being written is done within microseconds.
		if busy {
			runtime.Gosched()
			continue
		}
		if n > 0 {
			continue
		}
		if flushing {
			return nil
		}
		ready, err := r.wait(wait)
		if err != nil {
			return err
		}
		switch ready {
		case waitTimeout:
			if err := idle(); err != nil {
				return err
			}
		case waitFlush:
			flushing = true
		}
	}
}

// drain reads the records committed so far and returns how many it read,
// and whether it stopped at one reserved but not yet committed.
func (r *ring) drain(f func([]byte) error) (n int, busy bool, err error) {
	prod := atomic.LoadUintptr(r.prodPos)
	cons := atomic.LoadUintptr(r.consPos)
	released := cons
	defer func() {
		if cons != released {
			atomic.StoreUintptr(r.consPos, cons)
		}
	}()
	for cons < prod {
		start := cons & r.mask
		// Loaded atomically: the kernel clears the busy bit after writing the
		// record, so the record is complete once the bit reads clear.
		hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.data[start])))
		if hdr&unix.BPF_RINGBUF_BUSY_BIT != 0 {
			return n, true, nil
		}
		size := uintptr(hdr &^ (unix.BPF_RINGBUF_BUSY_BIT | unix.BPF_RINGBUF_DISCARD_BIT))
		begin := start + unix.BPF_RINGBUF_HDR_SZ
		if begin+size > uintptr(len(r.data)) {
			return n, false, fmt.Errorf("ring buffer record of %d bytes at %d runs past the ring", size, start)
		}
		if hdr&unix.BPF_RINGBUF_DISCARD_BIT == 0 {
			if err := f(r.data[begin : begin+size]); err != nil {
				return n, false, err
			}
			n++
		}
		cons += unix.BPF_RINGBUF_HDR_SZ + (size+7)&^7
		if cons-released >= releaseBytes {
			atomic.StoreUintptr(r.consPos, cons)
			released = cons
		}
	}
	return n, false, nil
}

type waitResult int

const (
	waitData waitResult = iota
	waitTimeout
	waitFlush
)

// wait blocks until the kernel wakes the reader, Flush is called, or timeout
// passes.
func (r *ring) wait(timeout time.Duration) (waitResult, error) {
	var events [2]unix.EpollEvent
	for {
		n, err := unix.EpollWait(r.epfd, events[:], int(timeout.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("epoll wait: %w", err)
		}
		if n == 0 {
			return waitTimeout, nil
		}
		for _, ev := range events[:n] {
			if int(ev.Fd) == r.flushFd {
				return waitFlush, nil
			}
		}
		return waitData, nil
	}
}

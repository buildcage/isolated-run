package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// ring reads the BPF ring buffer where it is mapped. One goroutine reads it,
// so unlike cilium/ebpf's reader it takes no lock per record, and it reads
// the producer position and hands space back once per batch rather than per
// record.
type ring struct {
	consPage, dataPages, waitingPage []byte
	// consPos and prodPos are the positions the kernel shares; data maps the
	// ring twice over, so no record wraps.
	consPos, prodPos *uintptr
	data             []byte
	mask             uintptr
	// waiting is the BPF side's reader_waiting flag.
	waiting *uint32
	// release is how much is read before it is handed back mid-batch. The
	// BPF side counts what is not handed back as queued when it decides to
	// wake the reader, so this stays well below WAKEUP_BYTES.
	release uintptr
	epfd    int
	// flushFd is closed under mu, so a late Flush does not write to a
	// reused descriptor. flushed is checked on every batch, since the ring
	// may never empty for read to see flushFd while producers keep up.
	mu      sync.Mutex
	flushFd int
	flushed atomic.Bool
}

func newRing(m, waiting *ebpf.Map) (*ring, error) {
	size := int(m.MaxEntries())
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
	flag, err := unix.Mmap(waiting.FD(), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(data)
		unix.Munmap(cons)
		return nil, fmt.Errorf("map the reader's waiting flag: %w", err)
	}
	r := &ring{
		consPage:    cons,
		dataPages:   data,
		waitingPage: flag,
		waiting:     (*uint32)(unsafe.Pointer(&flag[0])),
		consPos:     (*uintptr)(unsafe.Pointer(&cons[0])),
		prodPos:     (*uintptr)(unsafe.Pointer(&data[0])),
		data:        data[page:],
		mask:        uintptr(size - 1),
		release:     64 << 10,
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.flushFd < 0 {
		return os.ErrClosed
	}
	r.flushed.Store(true)
	_, err := unix.Write(r.flushFd, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	return err
}

func (r *ring) Close() error {
	var errs []error
	r.mu.Lock()
	for _, fd := range []*int{&r.epfd, &r.flushFd} {
		if *fd >= 0 {
			errs = append(errs, unix.Close(*fd))
			*fd = -1
		}
	}
	r.mu.Unlock()
	if r.dataPages != nil {
		errs = append(errs, unix.Munmap(r.dataPages))
	}
	if r.consPage != nil {
		errs = append(errs, unix.Munmap(r.consPage))
	}
	if r.waitingPage != nil {
		errs = append(errs, unix.Munmap(r.waitingPage))
	}
	return errors.Join(errs...)
}

// busySpins is how often read yields for a record still being written
// before it sleeps instead, should its writer be preempted.
const busySpins = 64

// read passes each record to f until Flush, then returns once it has read
// what was queued when Flush was called. It calls tick when the ring stays
// empty for every, and at least that often while records keep coming. A
// record is valid only until f returns.
func (r *ring) read(f func([]byte) error, every time.Duration, tick func() error) error {
	flushing, until, spins := false, ^uintptr(0), 0
	last := time.Now()
	for {
		if !flushing && r.flushed.Load() {
			flushing, until = true, atomic.LoadUintptr(r.prodPos)
		}
		moved, busy, err := r.drain(f, until)
		if err != nil {
			return err
		}
		if moved {
			spins = 0
		}
		// Also while waiting out a record still being written.
		if (moved || busy) && time.Since(last) >= every {
			if err := tick(); err != nil {
				return err
			}
			last = time.Now()
		}
		switch {
		case busy && spins < busySpins:
			spins++
			runtime.Gosched()
			continue
		case busy:
			// Not an epoll wait: the ring reads as ready while a record is
			// reserved, so that wait could return at once.
			spins = 0
			time.Sleep(time.Millisecond)
			continue
		case moved:
			continue
		case flushing:
			return nil
		}
		// Set before the last look at the ring, so a record committed
		// after it finds the flag set and wakes the reader.
		atomic.StoreUint32(r.waiting, 1)
		if atomic.LoadUintptr(r.prodPos) != atomic.LoadUintptr(r.consPos) {
			atomic.StoreUint32(r.waiting, 0)
			continue
		}
		timedOut, err := r.wait(every)
		atomic.StoreUint32(r.waiting, 0)
		if err != nil {
			return err
		}
		if timedOut {
			if err := tick(); err != nil {
				return err
			}
			last = time.Now()
		}
	}
}

// drain reads the records committed so far, up to until. It reports whether
// it moved past any, and whether it stopped at one reserved but not yet
// committed.
func (r *ring) drain(f func([]byte) error, until uintptr) (moved, busy bool, err error) {
	prod := min(atomic.LoadUintptr(r.prodPos), until)
	start := atomic.LoadUintptr(r.consPos)
	cons, released := start, start
	defer func() {
		if cons != released {
			atomic.StoreUintptr(r.consPos, cons)
		}
	}()
	for cons < prod {
		at := cons & r.mask
		// Loaded atomically: the kernel clears the busy bit after writing the
		// record, so the record is complete once the bit reads clear.
		hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.data[at])))
		if hdr&unix.BPF_RINGBUF_BUSY_BIT != 0 {
			return cons != start, true, nil
		}
		size := uintptr(hdr &^ (unix.BPF_RINGBUF_BUSY_BIT | unix.BPF_RINGBUF_DISCARD_BIT))
		begin := at + unix.BPF_RINGBUF_HDR_SZ
		if begin+size > uintptr(len(r.data)) {
			return cons != start, false, fmt.Errorf("ring buffer record of %d bytes at %d runs past the ring", size, at)
		}
		if hdr&unix.BPF_RINGBUF_DISCARD_BIT == 0 {
			if err := f(r.data[begin : begin+size]); err != nil {
				return cons != start, false, err
			}
		}
		cons += unix.BPF_RINGBUF_HDR_SZ + (size+7)&^7
		if cons-released >= r.release {
			atomic.StoreUintptr(r.consPos, cons)
			released = cons
		}
	}
	return cons != start, false, nil
}

// wait blocks until the kernel wakes the reader, Flush is called, or timeout
// passes.
func (r *ring) wait(timeout time.Duration) (timedOut bool, err error) {
	var events [2]unix.EpollEvent
	for {
		n, err := unix.EpollWait(r.epfd, events[:], int(timeout.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("epoll wait: %w", err)
		}
		return n == 0, nil
	}
}

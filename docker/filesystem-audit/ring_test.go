package main

import (
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeRing is a ring over Go memory, mapped twice over as the kernel maps it,
// with an eventfd standing in for the ring buffer's wakeup.
type fakeRing struct {
	*ring
	cons, prod uintptr
	size       int
}

func newFakeRing(t *testing.T, size int) *fakeRing {
	t.Helper()
	f := &fakeRing{size: size}
	f.ring = &ring{data: make([]byte, 2*size), mask: uintptr(size - 1), release: uintptr(size)}
	f.consPos, f.prodPos = &f.cons, &f.prod
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.openWait(wake); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.Close()
		unix.Close(wake)
	})
	return f
}

// put writes a record at the producer position with the header bits given.
func (f *fakeRing) put(payload string, bits uint32) {
	rec := make([]byte, unix.BPF_RINGBUF_HDR_SZ+(len(payload)+7)&^7)
	binary.LittleEndian.PutUint32(rec, uint32(len(payload))|bits)
	copy(rec[unix.BPF_RINGBUF_HDR_SZ:], payload)
	for i, c := range rec {
		at := (int(f.prod) + i) & (f.size - 1)
		f.data[at], f.data[at+f.size] = c, c
	}
	f.prod += uintptr(len(rec))
}

func (f *fakeRing) collect() (got []string, busy bool, err error) {
	_, busy, err = f.drain(func(b []byte) error {
		got = append(got, string(b))
		return nil
	})
	return got, busy, err
}

func TestRingReadsRecordsAndSkipsDiscarded(t *testing.T) {
	f := newFakeRing(t, 64)
	f.put("one", 0)
	f.put("skipped", unix.BPF_RINGBUF_DISCARD_BIT)
	f.put("three", 0)
	got, busy, err := f.collect()
	if err != nil || busy || !slices.Equal(got, []string{"one", "three"}) {
		t.Fatalf("got %q busy=%v err=%v", got, busy, err)
	}
	if f.cons != f.prod {
		t.Fatalf("consumer at %d, want %d", f.cons, f.prod)
	}
}

// Space is handed back every release bytes, not only at the batch's end.
func TestRingHandsSpaceBackMidBatch(t *testing.T) {
	f := newFakeRing(t, 64)
	f.release = 16
	f.put("one", 0)
	f.put("two", 0)
	var seen []uintptr
	if _, _, err := f.drain(func([]byte) error {
		seen = append(seen, f.cons)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seen, []uintptr{0, 16}) || f.cons != 32 {
		t.Fatalf("consumer at %v while reading, %d after; want [0 16], 32", seen, f.cons)
	}
}

// A batch of discarded records still counts as moving, so read drains again.
func TestRingMovesPastDiscardedRecords(t *testing.T) {
	f := newFakeRing(t, 64)
	f.put("gone", unix.BPF_RINGBUF_DISCARD_BIT)
	moved, _, err := f.drain(func([]byte) error { return nil })
	if err != nil || !moved || f.cons != f.prod {
		t.Fatalf("moved=%v err=%v consumer at %d, want %d", moved, err, f.cons, f.prod)
	}
}

// A record across the ring's end reads whole, through the second mapping.
func TestRingReadsARecordAcrossTheEnd(t *testing.T) {
	f := newFakeRing(t, 64)
	f.cons, f.prod = 48, 48
	f.put("across the end", 0)
	if got, _, err := f.collect(); err != nil || !slices.Equal(got, []string{"across the end"}) {
		t.Fatalf("got %q err=%v", got, err)
	}
}

// A record still being written stops the batch there, with what came before
// it handed back.
func TestRingStopsAtABusyRecord(t *testing.T) {
	f := newFakeRing(t, 64)
	f.put("done", 0)
	busyAt := f.prod
	f.put("writing", unix.BPF_RINGBUF_BUSY_BIT)
	got, busy, err := f.collect()
	if err != nil || !busy || !slices.Equal(got, []string{"done"}) || f.cons != busyAt {
		t.Fatalf("got %q busy=%v err=%v consumer at %d, want %d", got, busy, err, f.cons, busyAt)
	}
}

func TestRingRefusesARecordPastTheRing(t *testing.T) {
	f := newFakeRing(t, 64)
	binary.LittleEndian.PutUint32(f.data, 200)
	f.prod = 208
	if _, _, err := f.collect(); err == nil {
		t.Fatal("read a record longer than the ring")
	}
}

func TestRingReadCallsIdleAndEndsAfterFlush(t *testing.T) {
	f := newFakeRing(t, 64)
	f.put("first", 0)
	var got []string
	idle := 0
	err := f.read(func(b []byte) error {
		got = append(got, string(b))
		return nil
	}, time.Millisecond, func() error {
		if idle++; idle == 2 {
			f.put("queued at the flush", 0)
			return f.Flush()
		}
		return nil
	})
	if err != nil || idle != 2 || !slices.Equal(got, []string{"first", "queued at the flush"}) {
		t.Fatalf("got %q idle=%d err=%v", got, idle, err)
	}
}

// While records keep coming, tick still runs every interval.
func TestRingReadTicksWhileRecordsKeepComing(t *testing.T) {
	f := newFakeRing(t, 64)
	f.put("x", 0)
	err := f.read(func([]byte) error {
		time.Sleep(time.Millisecond)
		f.put("x", 0)
		return nil
	}, 5*time.Millisecond, func() error {
		f.prod = f.cons // stop feeding, then end
		return f.Flush()
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRingFlushAfterCloseFails(t *testing.T) {
	f := newFakeRing(t, 64)
	f.Close()
	if err := f.Flush(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Flush after Close = %v, want %v", err, os.ErrClosed)
	}
}

func TestRingReadStopsOnTheCallbacksError(t *testing.T) {
	f := newFakeRing(t, 64)
	f.put("x", 0)
	stop := errors.New("stop")
	if err := f.read(func([]byte) error { return stop }, time.Millisecond, func() error { return nil }); !errors.Is(err, stop) {
		t.Fatalf("err = %v, want %v", err, stop)
	}
}

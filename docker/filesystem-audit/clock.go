package main

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// bootClock converts an event's CLOCK_BOOTTIME stamp to wall-clock time with
// the offset CLOCK_REALTIME had over it at that moment. The offset changes
// only when the realtime clock is set, as an NTP step does; slewing moves both
// clocks alike. A timerfd reports each set, so the clocks are read at the
// start and after each set rather than for every line.
type bootClock struct {
	steps atomic.Pointer[[]clockStep]
	// unfollowed is set once sets can no longer be told, after which the
	// clocks are read for every line, as without a timerfd.
	unfollowed atomic.Bool
}

// clockStep is the offset from boot on.
type clockStep struct {
	boot   uint64
	offset int64
}

// farFuture is when the timerfd that watches for sets expires, just short of
// the latest time a timer can hold.
var farFuture = unix.Timespec{Sec: 9_200_000_000}

// newBootClock reads the offset and follows the realtime clock's sets from
// then on.
func newBootClock(log io.Writer) (*bootClock, error) {
	c := &bootClock{}
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_CLOEXEC)
	if err == nil {
		// Armed before the first read, so a set in between is not missed.
		if err = armClockSet(fd); err != nil {
			unix.Close(fd)
		}
	}
	following := err == nil
	if !following {
		c.unfollow(log, err)
	}
	if err := c.step(); err != nil {
		if following {
			unix.Close(fd)
		}
		return nil, err
	}
	if following {
		go c.follow(fd, log)
	}
	return c, nil
}

// armClockSet arms fd to be cancelled by the next set. Arming refuses with
// ECANCELED while a set it has not reported is pending, which arming again
// clears.
func armClockSet(fd int) error {
	for {
		err := unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME|unix.TFD_TIMER_CANCEL_ON_SET,
			&unix.ItimerSpec{Value: farFuture}, nil)
		if !errors.Is(err, unix.ECANCELED) {
			return err
		}
	}
}

// follow takes a new offset each time the realtime clock is set. An event
// between a set and its new offset still takes the old one.
func (c *bootClock) follow(fd int, log io.Writer) {
	defer unix.Close(fd)
	var buf [8]byte
	for {
		_, err := unix.Read(fd, buf[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		// A set cancels the timer; one past farFuture makes it expire.
		if err != nil && !errors.Is(err, unix.ECANCELED) {
			c.unfollow(log, err)
			return
		}
		// Rearmed first, so a set while the offset is read fires again.
		err = armClockSet(fd)
		if err == nil {
			err = c.step()
		}
		if err != nil {
			c.unfollow(log, err)
			return
		}
	}
}

func (c *bootClock) unfollow(log io.Writer, err error) {
	fmt.Fprintln(log, "filesystem-audit: reading the clocks for every line, as their sets cannot be followed:", err)
	c.unfollowed.Store(true)
}

// step reads the offset and records it from now on.
func (c *bootClock) step() error {
	boot, offset, err := readOffset()
	if err != nil {
		return err
	}
	c.add(clockStep{boot, offset})
	return nil
}

// readOffset reads CLOCK_BOOTTIME and CLOCK_REALTIME back to back.
func readOffset() (boot uint64, offset int64, err error) {
	var b, r unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &b); err != nil {
		return 0, 0, fmt.Errorf("read CLOCK_BOOTTIME: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &r); err != nil {
		return 0, 0, fmt.Errorf("read CLOCK_REALTIME: %w", err)
	}
	return uint64(b.Nano()), r.Nano() - b.Nano(), nil
}

func (c *bootClock) add(s clockStep) {
	var steps []clockStep
	if old := c.steps.Load(); old != nil {
		steps = append(steps, *old...)
	}
	steps = append(steps, s)
	c.steps.Store(&steps)
}

// offset is the offset at boot: the latest step at or before it, or the
// first for an event from before the tracer started.
func (c *bootClock) offset(boot uint64) int64 {
	if c.unfollowed.Load() {
		if _, offset, err := readOffset(); err == nil {
			return offset
		}
	}
	steps := *c.steps.Load()
	for i := len(steps) - 1; i > 0; i-- {
		if steps[i].boot <= boot {
			return steps[i].offset
		}
	}
	return steps[0].offset
}

// wallClock is an event's boot timestamp as UTC wall-clock time.
func wallClock(boot uint64, offset int64) time.Time {
	return time.Unix(0, int64(boot)+offset).UTC()
}

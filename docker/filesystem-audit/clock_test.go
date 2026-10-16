package main

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBootClockConvertsNow(t *testing.T) {
	c, err := newBootClock()
	if err != nil {
		t.Fatal(err)
	}
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		t.Fatal(err)
	}
	got := time.Unix(0, boot.Nano()+c.offset(uint64(boot.Nano())))
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Fatalf("boot time now converts to %s, %s from the wall clock", got, d)
	}
}

// Each event takes the offset of the last set at or before it.
func TestBootClockTakesTheOffsetAtEachEvent(t *testing.T) {
	c := &bootClock{}
	c.add(clockStep{boot: 100, offset: 1000})
	c.add(clockStep{boot: 200, offset: 5000})
	c.add(clockStep{boot: 300, offset: 3000})
	for boot, want := range map[uint64]int64{50: 1000, 100: 1000, 199: 1000, 200: 5000, 299: 5000, 300: 3000, 1 << 40: 3000} {
		if got := c.offset(boot); got != want {
			t.Errorf("offset(%d) = %d, want %d", boot, got, want)
		}
	}
}

func TestBootClockTakesANewOffsetAtEachStep(t *testing.T) {
	c := &bootClock{}
	c.add(clockStep{boot: 0, offset: 1})
	if err := c.step(); err != nil {
		t.Fatal(err)
	}
	if steps := *c.steps.Load(); len(steps) != 2 || steps[1].boot == 0 {
		t.Fatalf("steps = %v, want the new offset after the first", steps)
	}
}

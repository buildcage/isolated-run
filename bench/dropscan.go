package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

// A timeline of the ring's backlog and the BPF drop count every millisecond,
// and of each wait the reader makes, to see what came before a drop.
type benchEv struct {
	t       time.Duration
	kind    byte // s: sample, w: wait begins, T: timed out, D: woken, F: flushed
	backlog uintptr
	drops   uint64
}

var (
	benchMu  sync.Mutex
	benchEvs = make([]benchEv, 0, 1<<20)
	benchT0  time.Time
	benchR   *ring
)

func benchAdd(kind byte, backlog uintptr, drops uint64) {
	benchMu.Lock()
	if len(benchEvs) < cap(benchEvs) {
		benchEvs = append(benchEvs, benchEv{time.Since(benchT0), kind, backlog, drops})
	}
	benchMu.Unlock()
}

func scanBacklog() uintptr {
	return atomic.LoadUintptr(benchR.prodPos) - atomic.LoadUintptr(benchR.consPos)
}

func benchStart(r *ring, coll *ebpf.Collection) {
	benchT0, benchR = time.Now(), r
	m := coll.Maps["drops"]
	go func() {
		for {
			time.Sleep(time.Millisecond)
			d, _ := sumPerCPU(m)
			benchAdd('s', scanBacklog(), d)
		}
	}()
}

func benchWait(kind byte) { benchAdd(kind, scanBacklog(), 0) }

func benchDropDump() {
	benchMu.Lock()
	defer benchMu.Unlock()
	var maxB uintptr
	var longest, waitAt time.Duration
	var longestWake byte
	var longestB uintptr
	first := -1
	for i, e := range benchEvs {
		if e.kind == 's' {
			maxB = max(maxB, e.backlog)
			if first < 0 && e.drops > 0 {
				first = i
			}
		}
		if e.kind == 'w' {
			waitAt = e.t
		}
		if e.kind == 'T' || e.kind == 'D' || e.kind == 'F' {
			if d := e.t - waitAt; d > longest {
				longest, longestWake, longestB = d, e.kind, e.backlog
			}
		}
	}
	fmt.Fprintf(os.Stderr, "dropscan: events=%d max_backlog_kb=%d longest_wait_ms=%.1f ended=%c backlog_at_end_kb=%d\n",
		len(benchEvs), maxB>>10, float64(longest.Microseconds())/1000, longestWake, longestB>>10)
	if first < 0 {
		return
	}
	from := benchEvs[first].t - 300*time.Millisecond
	to := benchEvs[first].t + 50*time.Millisecond
	for _, e := range benchEvs {
		if e.t >= from && e.t <= to {
			fmt.Fprintf(os.Stderr, "dropscan: %8.1fms %c backlog_kb=%d drops=%d\n",
				float64(e.t.Microseconds())/1000, e.kind, e.backlog>>10, e.drops)
		}
	}
}

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// benchBacklog samples the ring buffer's queued bytes every 256 samples:
// how many samples, how many past 512 KiB, 1 MiB and 32 MiB, and the most.
var benchBacklog struct {
	n, over512k, over1m, over32m, max int
}

// benchProfile is the CPU profile being written, from the first sample on.
var benchProfile *os.File

// benchKinds counts the ring buffer's samples and bytes per kind.
var benchKinds = map[string]*[2]uint64{}

var benchProfilePath = os.Getenv("BENCH_PROFILE")

var benchCountN int

func benchCount(rd *ringbuf.Reader, raw []byte) {
	if path := benchProfilePath; path != "" && benchProfile == nil {
		f, err := os.Create(path)
		if err == nil && pprof.StartCPUProfile(f) == nil {
			benchProfile = f
		}
	}
	if benchCountN++; benchCountN%256 == 0 {
		a := rd.AvailableBytes()
		b := &benchBacklog
		b.n++
		if a > 512<<10 {
			b.over512k++
		}
		if a > 1<<20 {
			b.over1m++
		}
		if a > 32<<20 {
			b.over32m++
		}
		b.max = max(b.max, a)
	}
	if len(raw) < 4 {
		return
	}
	k := kindName(filesystemAuditKind(binary.LittleEndian.Uint32(raw)))
	c := benchKinds[k]
	if c == nil {
		c = new([2]uint64)
		benchKinds[k] = c
	}
	c[0]++
	c[1] += uint64((len(raw) + 8 + 7) &^ 7) // with the ring buffer's record header
}

func benchReport(coll *ebpf.Collection) {
	if benchProfile != nil {
		pprof.StopCPUProfile()
		benchProfile.Close()
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b := benchBacklog
	fmt.Fprintf(os.Stderr, "bench: backlog samples=%d over512k=%d over1m=%d over32m=%d max_kb=%d\n", b.n, b.over512k, b.over1m, b.over32m, b.max>>10)
	fmt.Fprintf(os.Stderr, "bench: gc=%d gc_pause_ms=%d alloc_mb=%d\n", ms.NumGC, ms.PauseTotalNs/1e6, ms.TotalAlloc>>20)
	var events, bytes uint64
	for k, c := range benchKinds {
		fmt.Fprintf(os.Stderr, "bench: kind=%s events=%d bytes=%d\n", k, c[0], c[1])
		events += c[0]
		bytes += c[1]
	}
	fmt.Fprintf(os.Stderr, "bench: events=%d bytes=%d\n", events, bytes)
	for name, p := range coll.Programs {
		s, err := p.Stats()
		if err == nil && s.RunCount > 0 {
			fmt.Fprintf(os.Stderr, "bench: prog=%s runs=%d ns=%d\n", name, s.RunCount, s.Runtime.Nanoseconds())
		}
	}
}

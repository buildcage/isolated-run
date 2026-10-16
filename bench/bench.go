package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/cilium/ebpf"
)

// benchProfile is the CPU profile being written, from the first sample on.
var benchProfile *os.File

// benchKinds counts the ring buffer's samples and bytes per kind.
var benchKinds = map[string]*[2]uint64{}

func benchCount(raw []byte) {
	if path := os.Getenv("BENCH_PROFILE"); path != "" && benchProfile == nil {
		f, err := os.Create(path)
		if err == nil && pprof.StartCPUProfile(f) == nil {
			benchProfile = f
		}
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

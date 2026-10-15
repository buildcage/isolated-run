package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

// benchKinds counts the ring buffer's samples and bytes per kind.
var benchKinds = map[string]*[2]uint64{}

func benchCount(raw []byte) {
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

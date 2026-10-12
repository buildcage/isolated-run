package main

import (
	"bufio"
	"io"
	"testing"

	"golang.org/x/sys/unix"
)

// BenchmarkRecorderAdd decodes and writes one event at a time, the work the
// tracer does per sample once the step's command runs.
func BenchmarkRecorderAdd(b *testing.B) {
	samples := [][]byte{
		event{kind: filesystemAuditKindK_OPEN, pid: 9, ppid: 1, comm: "node", flags: unix.O_RDONLY, data: []byte("/home/runner/work/app/node_modules/x/index.js\x00")}.bytes(),
		event{kind: filesystemAuditKindK_READ, pid: 9, ppid: 1, comm: "node", n1: 4, data: comps("index.js", "x", "node_modules", "app")}.bytes(),
		event{kind: filesystemAuditKindK_WRITE, pid: 9, ppid: 1, comm: "node", n1: 2, data: comps("out.log", "tmp")}.bytes(),
	}
	r := newRecorder(bufio.NewWriter(io.Discard), io.Discard, func() (int64, error) { return 0, nil })
	if err := r.add(event{kind: filesystemAuditKindK_EXEC, pid: 9, comm: "node", data: []byte("/usr/bin/node\x00")}.bytes()); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		if err := r.add(samples[i%len(samples)]); err != nil {
			b.Fatal(err)
		}
	}
}

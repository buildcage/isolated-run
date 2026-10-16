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
	r := newRecorder(bufio.NewWriter(io.Discard), io.Discard, func(uint64) int64 { return 0 })
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

// BenchmarkRecorderOpen settles an open(2) that reached its file: its name,
// the file and the call's result.
func BenchmarkRecorderOpen(b *testing.B) {
	benchCall(b,
		event{kind: filesystemAuditKindK_OPEN_NAME, pid: 9, ppid: 1, comm: "node", tid: 9, data: []byte("/home/runner/work/app/node_modules/x/index.js\x00")},
		event{kind: filesystemAuditKindK_OPEN, pid: 9, ppid: 1, comm: "node", tid: 9, flags: unix.O_RDONLY, data: []byte("/home/runner/work/app/node_modules/x/index.js\x00")},
		event{kind: filesystemAuditKindK_RESULT, pid: 9, ppid: 1, comm: "node", tid: 9, nr: 257, n1: resultOpen, pathRet: 3},
	)
}

// BenchmarkRecorderFailedOpen settles an open(2) of a missing file by an
// absolute name, its result carrying the working directory.
func BenchmarkRecorderFailedOpen(b *testing.B) {
	benchCall(b,
		event{kind: filesystemAuditKindK_OPEN_NAME, pid: 9, ppid: 1, comm: "node", tid: 9, data: []byte("/usr/lib/x86_64-linux-gnu/libmissing.so\x00")},
		event{kind: filesystemAuditKindK_RESULT, pid: 9, ppid: 1, comm: "node", tid: 9, nr: 257, n1: resultOpen, pathRet: -2,
			bases: 1, mode: 5, data: comps("x", "node_modules", "app", "work", "runner")},
	)
}

func benchCall(b *testing.B, events ...event) {
	samples := make([][]byte, len(events))
	for i, e := range events {
		samples[i] = e.bytes()
	}
	r := newRecorder(bufio.NewWriter(io.Discard), io.Discard, func(uint64) int64 { return 0 })
	if err := r.add(event{kind: filesystemAuditKindK_EXEC, pid: 9, comm: "node", data: []byte("/usr/bin/node\x00")}.bytes()); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, s := range samples {
			if err := r.add(s); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkTimeText writes the time of lines 1 µs apart.
func BenchmarkTimeText(b *testing.B) {
	var text timeText
	var buf []byte
	for i := int64(0); b.Loop(); i++ {
		buf = text.append(buf[:0], testTime+i*1000)
	}
}

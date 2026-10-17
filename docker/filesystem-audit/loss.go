package main

import "github.com/cilium/ebpf"

// loss is what the BPF side counted, read once the ring buffer is drained,
// each counter with its own read error.
type loss struct {
	dropped, untracked, internal uint64
	errDropped, errUntracked     error
	missed                       count
	// errClock is why the realtime clock's sets stopped being followed.
	errClock error
}

type count struct {
	n   uint64
	err error
}

// missedRuns sums the runs of the programs the kernel skipped, anywhere on
// the host, as it cannot say whose access a skip was.
func missedRuns(coll *ebpf.Collection) (uint64, error) {
	var sum uint64
	for _, p := range coll.Programs {
		s, err := p.Stats()
		if err != nil {
			return 0, err
		}
		sum += s.RecursionMisses
	}
	return sum, nil
}

// readLoss reads the counters the recording's end and the step log report,
// given the host-missed count read at the stop.
func readLoss(coll *ebpf.Collection, missed count) loss {
	var l loss
	l.dropped, l.errDropped = sumPerCPU(coll.Maps["drops"])
	l.untracked, l.errUntracked = sumPerCPU(coll.Maps["untracked"])
	l.internal, _ = sumPerCPU(coll.Maps["skipped_internal"])
	l.missed = missed
	return l
}

func sumPerCPU(m *ebpf.Map) (uint64, error) {
	var per []uint64
	if err := m.Lookup(uint32(0), &per); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range per {
		sum += v
	}
	return sum, nil
}

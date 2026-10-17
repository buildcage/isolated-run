package main

import ()

// execFiles holds each process's resolved exec target until its exec record
// arrives. An exec that fails after resolving its file sends no exec record, so
// its entry stays until the process's next exec-file replaces it or a fork
// reuses its pid.
type execFiles map[uint32]record

// attach takes in an exec-file record, keeping its path for the exec that
// follows, and reports true so the caller drops it. An exec record gets that
// path, with the name it was run by moved to Name. A fork record drops the
// entry for its pid.
func (f execFiles) attach(r *record) bool {
	switch r.Kind {
	case "exec-file":
		f[r.PID] = *r
		return true
	case "fork":
		delete(f, r.PID)
	case "exec":
		if t, ok := f[r.PID]; ok {
			delete(f, r.PID)
			r.Name, r.Path, r.Memfd, r.Deleted = r.Path, t.Path, t.Memfd, t.Deleted
		}
	}
	return false
}

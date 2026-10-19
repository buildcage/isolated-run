package main

// record is one line of the JSON output. Kind is the action; Path (and To,
// for the two-path operations) name the target; Access carries the open or
// mmap flags as letters; Failed and Err describe an operation that did not
// succeed. The tags name each field as appendRecord writes it, which the
// tests check against encoding/json.
type record struct {
	Kind string `json:"kind"`
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	// Program is the file the process last ran, which a fork hands its child;
	// empty for one that ran nothing since the recording started.
	Program string `json:"program,omitempty"`
	Path    string `json:"path,omitempty"`
	// Name is the name the command passed, where Path is not that name as
	// written: the file an exec resolved to, or a passed name joined to its
	// directory. ToName is the same for To.
	Name   string `json:"name,omitempty"`
	To     string `json:"to,omitempty"`
	ToName string `json:"to_name,omitempty"`
	Access string `json:"access,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`
	// Mode is a chmod's new mode in octal, and Owner a chown's new uid:gid.
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Err    int32  `json:"err,omitempty"`
	Failed bool   `json:"failed,omitempty"`
	// Image marks a mapping the kernel made while starting a program: the
	// program itself, its dynamic loader, or a script's interpreter.
	Image bool `json:"image,omitempty"`
	// Memfd marks a memfd, whose Path is "memfd:" and the name its creator
	// chose; Deleted a file unlinked while in use, or an O_TMPFILE.
	Memfd   bool `json:"memfd,omitempty"`
	Deleted bool `json:"deleted,omitempty"`
	// Exchange marks a rename that swapped Path and To (RENAME_EXCHANGE).
	Exchange bool `json:"exchange,omitempty"`
	// Syscall names a refused syscall, or gives its number where the tracer
	// has no name for it; Compat marks one of the 32-bit ABI, and Killed one
	// seccomp killed the program for.
	Syscall string `json:"syscall,omitempty"`
	Compat  bool   `json:"compat,omitempty"`
	Killed  bool   `json:"killed,omitempty"`
	// boot is the event's CLOCK_BOOTTIME stamp in nanoseconds; the line's
	// "t" is its wall-clock time.
	boot uint64
	// tid and nr are the thread and syscall an event was sent from.
	tid uint32
	nr  int32
}

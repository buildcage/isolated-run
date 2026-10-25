// gen-seccomp-profile resolves moby/profiles' Docker default seccomp
// profile into the OCI Runtime Spec form runc's config.json expects,
// against a synthetic spec with an empty capability set (matching the
// sandboxed process, which always runs with its capability bounding set
// fully cleared). Writes the result to stdout as JSON.
//
// Compiled at image build time but run on the runner host, before the
// sandbox is set up: its output depends on the architecture and the running
// kernel (a few of the profile's syscalls carry a minKernel condition), so
// it is only right for the machine that runs it. See docs/development.md.
// A mismatched kernel can only add a syscall that fails with ENOSYS or leave
// out one a tool needed; it never widens the filter.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/moby/profiles/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func main() {
	rs := &specs.Spec{
		Process: &specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding: []string{},
			},
		},
	}

	linuxSeccomp, err := seccomp.GetDefaultProfile(rs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-seccomp-profile:", err)
		os.Exit(1)
	}

	// Machine-readable only (sandbox/runc-bootstrap.ts's extractRuncBootstrap
	// JSON.parses this straight off stdout), no pretty-printing needed.
	if err := json.NewEncoder(os.Stdout).Encode(linuxSeccomp); err != nil {
		fmt.Fprintln(os.Stderr, "gen-seccomp-profile:", err)
		os.Exit(1)
	}
}

import { describe, it, expect, beforeEach } from "vitest";

import { parseNofileLimit, type HostProbes } from "./host-probes.ts";
import type { BuildOciConfigOptions } from "./oci-config.ts";
import type { OciSpec } from "./types.ts";
import { buildOciConfig } from "./oci-config.ts";
import { RESOLV_CONF_DESTINATION } from "./oci-mounts.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import { WritablePathConflictError } from "./paths.ts";
import { OWN_CA_DESTINATION } from "./ca-trust.ts";

/** Not the first candidate: the mount lands where the runner keeps its store. */
const SYSTEM_STORE = "/etc/pki/tls/certs/ca-bundle.crt";

const SHM_BYTES = 4 * 1024 * 1024 * 1024;
const PROC_LIMITS = [
  "Limit                     Soft Limit           Hard Limit           Units",
  "Max open files            65536                65536                files",
].join("\n");

/**
 * A GitHub-hosted Linux runner's answers, supplied rather than read, since
 * otherwise the suite silently covers something different on a macOS dev
 * machine than in CI. `absent` drops one, which is what a non-Linux host
 * looks like.
 */
function pinnedProbes({ absent = [] }: { absent?: ("setpriv" | "nofile")[] } = {}): HostProbes {
  return {
    setprivPath: () => (absent.includes("setpriv") ? "setpriv" : "/usr/bin/setpriv"),
    nofileRlimit: () =>
      absent.includes("nofile") ? undefined : parseNofileLimit(PROC_LIMITS, 1073741816),
    shmSizeBytes: () => SHM_BYTES,
    hostname: () => HOSTNAME,
  };
}

const HOSTNAME = "runner-abcdef";

// Every buildOciConfig case runs against the same pinned host, so a case only
// has to say so when it wants a different one, which it does by reassigning
// `probes` before calling build().
let probes: HostProbes;
beforeEach(() => {
  probes = pinnedProbes();
});

/** buildOciConfig against whatever host the current case pinned. */
function build(baseSpec: OciSpec, options: BuildOciConfigOptions) {
  return buildOciConfig(baseSpec, options, probes);
}

// A minimal stand-in for what `runc spec` actually produces (see
// runc-bootstrap.ts's generateBaseOciSpec): only the fields buildOciConfig
// reads/overrides are included.
function fakeBaseSpec() {
  return {
    ociVersion: "1.0.2",
    hostname: "runc",
    root: { path: "rootfs", readonly: true },
    mounts: [
      { destination: "/proc", type: "proc", source: "proc" },
      { destination: "/sys", type: "none", source: "/sys", options: ["rbind", "ro"] },
      {
        destination: "/dev/shm",
        type: "tmpfs",
        source: "shm",
        options: ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
      },
    ],
    process: {
      terminal: true,
      user: { uid: 0, gid: 0 },
      args: ["sh"],
      env: ["PATH=/usr/local/sbin:/usr/local/bin", "TERM=xterm"],
      cwd: "/",
      capabilities: {
        bounding: ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
        effective: ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
        permitted: ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
        inheritable: [],
        ambient: [],
      },
      rlimits: [{ type: "RLIMIT_NOFILE", hard: 1024, soft: 1024 }],
    },
    linux: {
      namespaces: [
        { type: "pid" },
        { type: "network" },
        { type: "ipc" },
        { type: "uts" },
        { type: "mount" },
        { type: "cgroup" },
      ],
      maskedPaths: ["/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/timer_list"],
      readonlyPaths: ["/proc/bus", "/proc/sysrq-trigger"],
    },
  };
}

describe("buildOciConfig", () => {
  const baseArgs = {
    identity: { uid: 1000, gid: 1000 },
    writable: {
      workdir: "/home/runner/work/repo/repo",
      home: "/home/runner",
      writablePaths: [] as string[],
    },
    runtime: {
      netnsPath: "/var/run/netns/buildcage-sandbox-abcd1234",
      rootfsBindDir: "/tmp/buildcage-sandbox-xyz/rootfs",
      resolvConfPath: "/tmp/buildcage-sandbox-xyz/resolv.conf",
      seccompProfile: { defaultAction: "SCMP_ACT_ERRNO" },
      execDir: "/tmp/buildcage-sandbox-xyz/exec",
      envLoaderPath: "/tmp/buildcage-sandbox-xyz/exec/env-loader.sh",
      scriptPath: "/tmp/buildcage-sandbox-xyz/exec/run-script.sh",
    },
    env: { FOO: "bar", UNSET: undefined },
  };

  describe("the process runc starts", () => {
    it("clears all five capability sets and sets noNewPrivileges", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.process.capabilities).toStrictEqual({
        bounding: [],
        effective: [],
        permitted: [],
        inheritable: [],
        ambient: [],
      });
      expect(config.process.noNewPrivileges).toBe(true);
    });

    it("sets uid/gid and cwd from the given options", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.process.user).toStrictEqual({ uid: 1000, gid: 1000 });
      expect(config.process.cwd).toBe(baseArgs.writable.workdir);
    });

    it("falls back to / when the step has no workdir to run in", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, workdir: "" },
      });
      expect(config.process.cwd).toBe("/");
    });

    it("wraps the script in `setpriv --pdeathsig=KILL` at the path the host reported", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.process.args).toStrictEqual([
        "/usr/bin/setpriv",
        "--pdeathsig=KILL",
        "--",
        baseArgs.runtime.envLoaderPath,
        baseArgs.runtime.scriptPath,
      ]);
    });

    it("passes a bare PATH lookup through when the host has no candidate", () => {
      probes = pinnedProbes({ absent: ["setpriv"] });
      expect(build(fakeBaseSpec(), baseArgs).process.args[0]).toBe("setpriv");
    });

    it("leaves process.env empty (the step environment travels over stdin)", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.process.env).toStrictEqual([]);
    });

    it("embeds the seccomp profile as-is", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.seccomp).toStrictEqual(baseArgs.runtime.seccompProfile);
    });
  });

  describe("matched to the runner, not runc's container defaults", () => {
    it("replaces runc's 1024-file default with the host's own RLIMIT_NOFILE", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.process.rlimits).toStrictEqual([
        { type: "RLIMIT_NOFILE", soft: 65536, hard: 65536 },
      ]);
    });

    // runc reads config.json, so the key has to be gone from the serialised form,
    // not merely undefined on the object.
    it("drops rlimits entirely when the host exposes no limits to read", () => {
      probes = pinnedProbes({ absent: ["nofile"] });
      const config = build(fakeBaseSpec(), baseArgs);
      expect(JSON.parse(JSON.stringify(config)).process).not.toHaveProperty("rlimits");
    });

    it('names the sandbox after the runner instead of runc\'s default "runc"', () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.hostname).toBe(HOSTNAME);
    });

    // What withHostShmSize does with a size is its own (see oci-mounts.test.ts);
    // what this says is that the size reaching it is the one the host reported.
    it("resizes /dev/shm to the host's own, away from runc's 64MB container default", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      const shm = config.mounts.find((m) => m.destination === "/dev/shm");
      expect(shm?.options).not.toContain("size=65536k");
      expect(shm?.options).toContain(`size=${SHM_BYTES}`);
    });
  });

  describe("the network namespace", () => {
    it("adds `path` to the network namespace entry, leaving other namespace types untouched", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      const netNs = config.linux.namespaces.find((ns) => ns.type === "network");
      expect(netNs!.path).toBe(baseArgs.runtime.netnsPath);
      expect(config.linux.namespaces.length).toBe(6);
    });
  });

  describe("paths masked from the step", () => {
    it("extends maskedPaths with kallsyms/kmsg/sysrq-trigger and moves sysrq-trigger out of readonlyPaths", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      for (const p of [
        "/proc/kallsyms",
        "/proc/kmsg",
        "/proc/sysrq-trigger",
        "/proc/kcore",
        "/proc/keys",
        "/proc/timer_list",
      ]) {
        expect(
          config.linux.maskedPaths.includes(p),
          `expected maskedPaths to include ${p}`,
        ).toBeTruthy();
      }
      expect(!config.linux.readonlyPaths.includes("/proc/sysrq-trigger")).toBeTruthy();
      expect(config.linux.readonlyPaths.includes("/proc/bus")).toBeTruthy();
    });

    it("masks known container/VM runtime sockets", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      for (const p of [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/docker/containerd/containerd.sock",
        "/run/buildkit/buildkitd.sock",
        "/run/podman/podman.sock",
        "/var/run/crio/crio.sock",
        "/run/dbus/system_bus_socket",
        "/var/run/dbus/system_bus_socket",
      ]) {
        expect(
          config.linux.maskedPaths.includes(p),
          `expected maskedPaths to include ${p}`,
        ).toBeTruthy();
      }
    });

    it("masks the named-netns directory, so a step can't list the sandboxes running beside it", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.maskedPaths).toContain("/run/netns");
      expect(config.linux.maskedPaths).toContain("/var/run/netns");
    });

    it("doesn't leak the netns directory into readonlyPaths alongside masking it", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        runtime: {
          ...baseArgs.runtime,
          hostMounts: [{ mountPoint: "/run/netns", fsType: "tmpfs" }],
        },
      });
      expect(config.linux.readonlyPaths).not.toContain("/run/netns");
    });

    it("covers /run with an empty tmpfs so the host's sockets never reach the sandbox", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      const runMount = config.mounts.find((m) => m.destination === "/run");
      expect(runMount).toMatchObject({ type: "tmpfs", source: "tmpfs" });
    });

    it("keeps the recreated /run/lock writable even when the host mounts it separately", () => {
      // /run/lock is its own tmpfs on the host, so the host-mount sweep would
      // otherwise force it read-only; the coverage layer reports it writable.
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        runtime: {
          ...baseArgs.runtime,
          hostMounts: [{ mountPoint: "/run/lock", fsType: "tmpfs" }],
        },
      });
      expect(config.linux.readonlyPaths).not.toContain("/run/lock");
    });

    it("also masks the rootless runtime sockets under $XDG_RUNTIME_DIR when set", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        env: { ...baseArgs.env, XDG_RUNTIME_DIR: "/run/user/1000" },
      });
      expect(config.linux.maskedPaths).toContain("/run/user/1000/docker.sock");
      expect(config.linux.maskedPaths).toContain("/run/user/1000/podman/podman.sock");
    });

    it("doesn't add rootless runtime socket paths when $XDG_RUNTIME_DIR is unset", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.maskedPaths).not.toContain("/run/user/1000/docker.sock");
      expect(config.linux.maskedPaths).not.toContain("/run/user/1000/podman/podman.sock");
    });

    it("masks /run/user/<uid> (the systemd --user bus dir) built from identity.uid, even without $XDG_RUNTIME_DIR", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.maskedPaths).toContain("/run/user/1000");
    });

    it("masks /run/user/<uid> and a different $XDG_RUNTIME_DIR when the two diverge", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        env: { ...baseArgs.env, XDG_RUNTIME_DIR: "/run/custom-xdg" },
      });
      expect(config.linux.maskedPaths).toContain("/run/user/1000");
      expect(config.linux.maskedPaths).toContain("/run/custom-xdg");
    });

    it("doesn't leak /run/user/<uid> into readonlyPaths alongside masking it", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        runtime: {
          ...baseArgs.runtime,
          hostMounts: [{ mountPoint: "/run/user/1000", fsType: "tmpfs" }],
        },
      });
      expect(config.linux.maskedPaths).toContain("/run/user/1000");
      expect(config.linux.readonlyPaths).not.toContain("/run/user/1000");
    });

    it("keeps masking /run/user/<uid> even when writable: / disables the read-only root", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
      });
      expect(config.linux.maskedPaths).toContain("/run/user/1000");
    });

    it("drops the /run coverage tmpfs under writable: /, the documented full opt-out", () => {
      // write_through: / hands the whole host back writable, /run included, so
      // covering /run would be the one exception to "you get what you opened".
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
      });
      expect(config.mounts.find((m) => m.destination === "/run")).toBeUndefined();
      expect(config.mounts.find((m) => m.destination === "/run/lock")).toBeUndefined();
    });
  });

  describe("the read-only root and its writable exceptions", () => {
    it("makes root read-only and binds workdir/home/tmp/writablePaths as writable exceptions", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/opt/cache"] },
      });
      expect(config.root.readonly).toBe(true);
      expect(config.root.path).toBe(baseArgs.runtime.rootfsBindDir);
      const rw = config.mounts.filter((m) => m.options?.includes("rw")).map((m) => m.destination);
      expect(rw.sort()).toStrictEqual(
        ["/opt/cache", "/tmp", baseArgs.writable.home, baseArgs.writable.workdir].sort(),
      );
    });

    it("fails closed when a writable path names a destination runc mounts itself", () => {
      for (const path of ["/proc", "/sys", "/proc/self"]) {
        const attempt = () =>
          build(fakeBaseSpec(), {
            ...baseArgs,
            writable: { ...baseArgs.writable, writablePaths: [path] },
          });
        expect(attempt).toThrow(/the sandbox mounts itself/);
        expect(attempt).toThrow(WritablePathConflictError);
      }
    });

    it("keeps RUNNER_TEMP writable (rw bind) and out of readonlyPaths", () => {
      const runnerTemp = "/opt/actions-runner/_work/_temp"; // self-hosted: outside $HOME
      const hostMounts = [
        { mountPoint: "/", fsType: "ext4" },
        { mountPoint: runnerTemp, fsType: "ext4" },
      ];
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: [], runnerTemp },
        runtime: { ...baseArgs.runtime, hostMounts },
      });
      const rw = config.mounts.filter((m) => m.options?.includes("rw")).map((m) => m.destination);
      expect(rw.includes(runnerTemp), "RUNNER_TEMP must be bind-mounted writable").toBeTruthy();
      expect(
        !config.linux.readonlyPaths.includes(runnerTemp),
        "RUNNER_TEMP must not be forced read-only",
      ).toBeTruthy();
    });

    it("does not double-mount RUNNER_TEMP when it duplicates another writable path", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: [], runnerTemp: "/tmp" },
      });
      const tmpMounts = config.mounts.filter(
        (m) => m.destination === "/tmp" && m.options?.includes("rw"),
      );
      expect(tmpMounts.length).toBe(1);
    });

    it("adds a read-only resolv.conf bind mount", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      const resolv = config.mounts.find((m) => m.destination === "/etc/resolv.conf");
      expect(resolv).toStrictEqual({
        destination: "/etc/resolv.conf",
        type: "none",
        source: baseArgs.runtime.resolvConfPath,
        options: ["rbind", "ro"],
      });
    });

    it("forces real host mount points not already writable into readonlyPaths (root.readonly alone doesn't cover them)", () => {
      const hostMounts = [
        { mountPoint: "/", fsType: "ext4" },
        { mountPoint: "/proc", fsType: "proc" },
        { mountPoint: "/mnt", fsType: "ext4" },
        { mountPoint: baseArgs.writable.workdir, fsType: "ext4" },
      ];
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: [] },
        runtime: { ...baseArgs.runtime, hostMounts },
      });
      expect(
        config.linux.readonlyPaths.includes("/mnt"),
        "a real, separate host mount not covered by root.readonly must be listed explicitly",
      ).toBeTruthy();
      expect(
        !config.linux.readonlyPaths.includes("/"),
        "'/' itself is already covered by root.readonly",
      ).toBeTruthy();
      expect(
        !config.linux.readonlyPaths.includes("/proc"),
        "pseudo-filesystems get their own fresh mount, not a readonly remount of the host copy",
      ).toBeTruthy();
      expect(
        !config.linux.readonlyPaths.includes(baseArgs.writable.workdir),
        "workdir must stay writable, not be added to readonlyPaths",
      ).toBeTruthy();
    });

    it("forces a kernel pseudo-fs into readonlyPaths when runc's own base spec doesn't mount it fresh", () => {
      // A fresh-mount exemption has to match runc's own base spec rather than
      // merely look like proc/sysfs/etc: fakeBaseSpec here declares only /proc
      // and /sys, so anything else (e.g. securityfs at /sys/kernel/security,
      // commonly mounted read-write on AppArmor-enabled hosts) never gets a
      // fresh, isolated mount.
      const hostMounts = [{ mountPoint: "/sys/kernel/security", fsType: "securityfs" }];
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: [] },
        runtime: { ...baseArgs.runtime, hostMounts },
      });
      expect(config.linux.readonlyPaths.includes("/sys/kernel/security")).toBeTruthy();
    });

    it("builds both path lists from scratch when the base spec lists neither", () => {
      const spec = fakeBaseSpec();
      const bare = {
        ...spec,
        linux: { ...spec.linux, maskedPaths: undefined, readonlyPaths: undefined },
      };
      const config = build(bare, baseArgs);
      expect(config.linux.maskedPaths).toContain("/proc/sysrq-trigger");
      // Nothing is invented for readonlyPaths: it is the base spec plus the
      // host-mount sweep, and here there is neither.
      expect(config.linux.readonlyPaths).toStrictEqual([]);
    });
  });

  describe("the action's own host directories", () => {
    it("adds them to readonlyPaths, which runc applies over every writable layer", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        readonlyHostDirs: ["/home/runner/.docker", "/home/runner/work/_actions/x/y/v1"],
      });
      expect(config.linux.readonlyPaths).toEqual(
        expect.arrayContaining(["/home/runner/.docker", "/home/runner/work/_actions/x/y/v1"]),
      );
    });

    it("binds each rename-guard dir onto itself read-write, after the writable layers", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        renameGuardDirs: ["/home/runner/work", "/home/runner/work/_actions"],
      });
      for (const dir of ["/home/runner/work", "/home/runner/work/_actions"]) {
        const mount = config.mounts.find((m) => m.destination === dir);
        expect(mount).toMatchObject({ source: dir, options: ["rbind", "rw"] });
      }
      expect(config.linux.readonlyPaths).not.toContain("/home/runner/work");
    });
  });

  describe("the scratch base, which nothing may make writable", () => {
    it("does not mount anything over rootfsBindDir (it lives under the scratch base, so nothing re-exposes it)", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/opt/cache"] },
      });
      expect(
        !config.mounts.some((m) => m.destination === baseArgs.runtime.rootfsBindDir),
      ).toBeTruthy();
    });

    it("masks the scratch base with an empty tmpfs and reveals only this run's execDir", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      const mask = config.mounts.find((m) => m.destination === SANDBOX_SCRATCH_BASE);
      expect(mask).toStrictEqual({
        destination: SANDBOX_SCRATCH_BASE,
        type: "tmpfs",
        source: "tmpfs",
        options: ["nosuid", "nodev", "mode=0555"],
      });
      expect(config.mounts).toContainEqual({
        destination: baseArgs.runtime.execDir,
        type: "none",
        source: baseArgs.runtime.execDir,
        options: ["bind", "ro"],
      });
    });

    it("orders the mask last of all, and the execDir reveal after it", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/opt/cache"] },
      });
      const destinations = config.mounts.map((m) => m.destination);
      expect(destinations.slice(-2)).toStrictEqual([
        SANDBOX_SCRATCH_BASE,
        baseArgs.runtime.execDir,
      ]);
    });

    it("masks the scratch base in ephemeral mode too, after the overlays", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        ephemeral: { overlayRoots: [], allowWrite: ["/home/runner/work"] },
      });
      const destinations = config.mounts.map((m) => m.destination);
      expect(destinations.slice(-2)).toStrictEqual([
        SANDBOX_SCRATCH_BASE,
        baseArgs.runtime.execDir,
      ]);
    });

    it("masks the scratch base even with the read-only restriction disabled", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
      });
      expect(config.mounts.some((m) => m.destination === SANDBOX_SCRATCH_BASE)).toBe(true);
    });

    // Which shapes the guard rejects is assertScratchBaseNotWritable's own
    // (see paths.test.ts); what this says is that write_through reaches it.
    it("fails closed when writable: names the scratch base", () => {
      expect(() =>
        build(fakeBaseSpec(), {
          ...baseArgs,
          writable: { ...baseArgs.writable, writablePaths: [SANDBOX_SCRATCH_BASE] },
        }),
      ).toThrow(/overlaps the sandbox's own scratch directory/);
    });

    it("fails closed when $HOME or RUNNER_TEMP itself overlaps the scratch base", () => {
      expect(() =>
        build(fakeBaseSpec(), {
          ...baseArgs,
          writable: { ...baseArgs.writable, home: SANDBOX_SCRATCH_BASE, writablePaths: [] },
        }),
      ).toThrow(/overlaps/);
    });

    it("does not fail closed for an unrelated sibling under /var/tmp", () => {
      expect(() =>
        build(fakeBaseSpec(), {
          ...baseArgs,
          writable: { ...baseArgs.writable, writablePaths: ["/var/tmp/some-other-tool"] },
        }),
      ).not.toThrow();
    });
  });

  describe("mount order", () => {
    it("mounts in layer order: base spec, /run coverage, writable binds, this action's own, scratch tmpfs, execDir", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.mounts.map((m) => m.destination)).toStrictEqual([
        "/proc",
        "/sys",
        "/dev/shm",
        // The /run tmpfs and its writable /run/lock come before the writable
        // binds, so a write_through entry under /run is re-exposed on top of the
        // fresh tmpfs rather than buried by it.
        "/run",
        "/run/lock",
        baseArgs.writable.workdir,
        baseArgs.writable.home,
        "/tmp",
        RESOLV_CONF_DESTINATION,
        SANDBOX_SCRATCH_BASE,
        baseArgs.runtime.execDir,
      ]);
    });

    it("re-exposes a write_through path under /run on top of the coverage tmpfs", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/run/snapd.socket"] },
      });
      const dests = config.mounts.map((m) => m.destination);
      // The bind lands after the /run tmpfs, so it is visible rather than shadowed.
      expect(dests.indexOf("/run/snapd.socket")).toBeGreaterThan(dests.indexOf("/run"));
      expect(config.mounts.find((m) => m.destination === "/run/snapd.socket")).toMatchObject({
        options: ["rbind", "rw"],
      });
    });

    it("keeps its own mounts after a write_through entry that contains them", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/etc"] },
      });
      const destinations = config.mounts.map((m) => m.destination);
      expect(destinations.indexOf(RESOLV_CONF_DESTINATION)).toBeGreaterThan(
        destinations.indexOf("/etc"),
      );
    });
  });

  describe("`writable: /`, the documented full opt-out", () => {
    it("`writable: /` is exempt from the scratch-base guard (documented full opt-out)", () => {
      expect(() =>
        build(fakeBaseSpec(), {
          ...baseArgs,
          writable: { ...baseArgs.writable, writablePaths: ["/"] },
        }),
      ).not.toThrow();
    });

    it("`writable: /` disables the read-only root and skips the individual writable-path mounts", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
      });
      expect(config.root.readonly).toBe(false);
      const rw = config.mounts.filter((m) => m.options?.includes("rw"));
      expect(rw.length).toBe(0);
    });

    it("`writable: /` still keeps the action's own host directories read-only", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
        readonlyHostDirs: ["/home/runner/.docker"],
      });
      expect(config.linux.readonlyPaths).toContain("/home/runner/.docker");
    });

    it("`writable: /` skips the host-mount readonly pass entirely", () => {
      const hostMounts = [{ mountPoint: "/mnt", fsType: "ext4" }];
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
        runtime: { ...baseArgs.runtime, hostMounts },
      });
      expect(!config.linux.readonlyPaths.includes("/mnt")).toBeTruthy();
    });
  });
});

describe("buildOciConfig: ephemeral mode", () => {
  const baseArgs = {
    identity: { uid: 1000, gid: 1000 },
    writable: {
      workdir: "/home/runner/work/repo/repo",
      home: "/home/runner",
      writablePaths: [] as string[],
    },
    runtime: {
      netnsPath: "/var/run/netns/buildcage-sandbox-abcd1234",
      rootfsBindDir: "/var/tmp/buildcage-1000/sandbox-xyz/rootfs",
      resolvConfPath: "/var/tmp/buildcage-1000/sandbox-xyz/resolv.conf",
      seccompProfile: { defaultAction: "SCMP_ACT_ERRNO" },
      execDir: "/var/tmp/buildcage-1000/sandbox-xyz/exec",
      envLoaderPath: "/var/tmp/buildcage-1000/sandbox-xyz/exec/env-loader.sh",
      scriptPath: "/var/tmp/buildcage-1000/sandbox-xyz/exec/run-script.sh",
    },
    env: { FOO: "bar" },
  };

  const ephemeral = {
    overlayRoots: [
      {
        path: "/home/runner",
        upper: "/var/tmp/buildcage-1000/sandbox-xyz/ephemeral/_home_runner/upper",
        work: "/var/tmp/buildcage-1000/sandbox-xyz/ephemeral/_home_runner/work",
      },
      {
        path: "/tmp",
        upper: "/var/tmp/buildcage-1000/sandbox-xyz/ephemeral/_tmp/upper",
        work: "/var/tmp/buildcage-1000/sandbox-xyz/ephemeral/_tmp/work",
      },
    ],
    allowWrite: [baseArgs.writable.workdir],
  };

  it("emits one overlay mount per overlay root, with lowerdir/upperdir/workdir set from the given paths", () => {
    const config = build(fakeBaseSpec(), { ...baseArgs, ephemeral });
    for (const root of ephemeral.overlayRoots) {
      expect(config.mounts).toContainEqual({
        destination: root.path,
        type: "overlay",
        source: "overlay",
        options: [`lowerdir=${root.path}`, `upperdir=${root.upper}`, `workdir=${root.work}`],
      });
    }
  });

  it("fails closed when a write_through entry names a destination runc mounts itself", () => {
    expect(() =>
      build(fakeBaseSpec(), {
        ...baseArgs,
        ephemeral: { ...ephemeral, allowWrite: ["/proc"] },
      }),
    ).toThrow(/the sandbox mounts itself/);
  });

  it("emits a plain rw rbind for each write_through entry", () => {
    const config = build(fakeBaseSpec(), { ...baseArgs, ephemeral });
    expect(config.mounts).toContainEqual({
      destination: baseArgs.writable.workdir,
      type: "none",
      source: baseArgs.writable.workdir,
      options: ["rbind", "rw"],
    });
  });

  it("does not fall back to the persistent writableDirs logic (workdir/home/tmp/RUNNER_TEMP) when ephemeral is set", () => {
    const config = build(fakeBaseSpec(), {
      ...baseArgs,
      ephemeral,
      writable: { ...baseArgs.writable, writablePaths: ["/opt/should-be-ignored"] },
    });
    expect(config.mounts.some((m) => m.destination === "/opt/should-be-ignored")).toBe(false);
  });

  it("orders mounts as the base spec, then overlay roots shallow-first, then write_through entries shallow-first", () => {
    const deepEphemeral = {
      overlayRoots: [
        { path: "/home/runner/deep", upper: "/scratch/deep/upper", work: "/scratch/deep/work" },
        { path: "/home", upper: "/scratch/home/upper", work: "/scratch/home/work" },
      ],
      allowWrite: ["/home/runner/deep/allow-deep", "/allow-shallow"],
    };
    const config = build(fakeBaseSpec(), { ...baseArgs, ephemeral: deepEphemeral });
    const indexOf = (destination: string) =>
      config.mounts.findIndex((m) => m.destination === destination);

    const homeIdx = indexOf("/home");
    const homeRunnerDeepIdx = indexOf("/home/runner/deep");
    const allowShallowIdx = indexOf("/allow-shallow");
    const allowDeepIdx = indexOf("/home/runner/deep/allow-deep");

    expect(homeIdx).toBeLessThan(homeRunnerDeepIdx);
    expect(homeRunnerDeepIdx).toBeLessThan(allowShallowIdx);
    expect(allowShallowIdx).toBeLessThan(allowDeepIdx);
  });

  it("keeps root.readonly true even though no writablePaths sentinel applies", () => {
    const config = build(fakeBaseSpec(), { ...baseArgs, ephemeral });
    expect(config.root.readonly).toBe(true);
  });

  it("never places an overlay root's upper/work dir under rootfsBindDir", () => {
    const config = build(fakeBaseSpec(), { ...baseArgs, ephemeral });
    const overlayMounts = config.mounts.filter((m) => m.type === "overlay");
    for (const m of overlayMounts) {
      for (const opt of m.options ?? []) {
        if (opt.startsWith("upperdir=") || opt.startsWith("workdir=")) {
          expect(opt.startsWith(`${baseArgs.runtime.rootfsBindDir}/`)).toBe(false);
        }
      }
    }
  });

  it("feeds overlay roots and write_through paths into the readonlyPaths host-mount pass as protected", () => {
    const hostMounts = [
      { mountPoint: "/", fsType: "ext4" },
      { mountPoint: "/home/runner", fsType: "ext4" },
      { mountPoint: baseArgs.writable.workdir, fsType: "ext4" },
      { mountPoint: "/mnt", fsType: "ext4" },
    ];
    const config = build(fakeBaseSpec(), {
      ...baseArgs,
      ephemeral,
      runtime: { ...baseArgs.runtime, hostMounts },
    });
    expect(config.linux.readonlyPaths.includes("/home/runner")).toBe(false);
    expect(config.linux.readonlyPaths.includes(baseArgs.writable.workdir)).toBe(false);
    expect(config.linux.readonlyPaths.includes("/mnt")).toBe(true);
  });

  it("still fails closed if an overlay root or write_through entry somehow overlaps the scratch base", () => {
    expect(() =>
      build(fakeBaseSpec(), {
        ...baseArgs,
        ephemeral: { overlayRoots: [], allowWrite: [SANDBOX_SCRATCH_BASE] },
      }),
    ).toThrow(/overlaps the sandbox's own scratch directory/);
  });
});

// inspect engine only: universal never passes caTrust, and the tests
// above (which don't) already cover that this is fully opt-in.
describe("buildOciConfig: caTrust", () => {
  const baseArgs = {
    identity: { uid: 1000, gid: 1000 },
    writable: {
      workdir: "/home/runner/work/repo/repo",
      home: "/home/runner",
      writablePaths: [] as string[],
    },
    runtime: {
      netnsPath: "/var/run/netns/buildcage-sandbox-abcd1234",
      rootfsBindDir: "/tmp/buildcage-sandbox-xyz/rootfs",
      resolvConfPath: "/tmp/buildcage-sandbox-xyz/resolv.conf",
      seccompProfile: { defaultAction: "SCMP_ACT_ERRNO" },
      execDir: "/tmp/buildcage-sandbox-xyz/exec",
      envLoaderPath: "/tmp/buildcage-sandbox-xyz/exec/env-loader.sh",
      scriptPath: "/tmp/buildcage-sandbox-xyz/exec/run-script.sh",
    },
    env: { FOO: "bar", UNSET: undefined },
  };
  const caTrust = {
    ownCaPath: "/scratch/buildcage-ca.pem",
    systemCa: { path: "/scratch/system-ca-bundle.pem", destination: SYSTEM_STORE },
    jvmKeystores: [],
  };

  it("adds no CA mounts when caTrust is omitted", () => {
    const config = build(fakeBaseSpec(), baseArgs);
    expect(config.mounts.some((m) => m.destination === OWN_CA_DESTINATION)).toBe(false);
    expect(config.mounts.some((m) => m.destination === SYSTEM_STORE)).toBe(false);
  });

  // The matching CA env vars are resolveSandboxEnv's job; see
  // env-loader.test.ts.
  it("adds the CA mounts when caTrust is given", () => {
    const config = build(fakeBaseSpec(), { ...baseArgs, caTrust });
    expect(config.mounts).toContainEqual({
      destination: OWN_CA_DESTINATION,
      type: "none",
      source: caTrust.ownCaPath,
      options: ["rbind", "ro"],
    });
    expect(config.mounts).toContainEqual({
      destination: SYSTEM_STORE,
      type: "none",
      source: caTrust.systemCa.path,
      options: ["rbind", "ro"],
    });
  });

  it("keeps the CA mounts after a write_through entry containing them", () => {
    const config = build(fakeBaseSpec(), {
      ...baseArgs,
      writable: { ...baseArgs.writable, writablePaths: ["/etc"] },
      caTrust,
    });
    const destinations = config.mounts.map((m) => m.destination);
    for (const ca of [OWN_CA_DESTINATION, SYSTEM_STORE]) {
      expect(destinations.indexOf(ca)).toBeGreaterThan(destinations.indexOf("/etc"));
    }
  });
});

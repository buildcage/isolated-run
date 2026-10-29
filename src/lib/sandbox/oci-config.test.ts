import { describe, it, expect, beforeEach } from "vitest";

import { OWN_CA_DESTINATION } from "./ca-trust.ts";
import { parseNofileLimit, type HostProbes } from "./host-probes.ts";
import type { BuildOciConfigOptions } from "./oci-config.ts";
import { buildOciConfig } from "./oci-config.ts";
import { RESOLV_CONF_DESTINATION } from "./oci-mounts.ts";
import { WritablePathConflictError } from "./paths.ts";
import { SANDBOX_SCRATCH_BASE } from "./scratch-dir.ts";
import type { OciSpec } from "./types.ts";

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
    varRunRealPath: () => "/run",
    realpath: (path) => path,
    cgroupPath: () => RUNNER_CGROUP,
    kernelBtf: () => true,
  };
}

const RUNNER_CGROUP = "/system.slice/hosted-compute-agent.service";

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

const baseArgs = {
  identity: { uid: 1000, gid: 1000 },
  writable: {
    workdir: "/home/runner/work/repo/repo",
    home: "/home/runner",
    writablePaths: [] as string[],
  },
  runtime: {
    netnsPath: "/var/run/netns/buildcage-sandbox-abcd1234",
    cgroupName: "buildcage-proxy-abcd1234",
    rootfsBindDir: "/tmp/buildcage-sandbox-xyz/rootfs",
    resolvConfPath: "/tmp/buildcage-sandbox-xyz/resolv.conf",
    seccompProfile: { defaultAction: "SCMP_ACT_ERRNO" },
    execDir: "/tmp/buildcage-sandbox-xyz/exec",
    envLoaderPath: "/tmp/buildcage-sandbox-xyz/exec/buildcage-init",
    scriptPath: "/tmp/buildcage-sandbox-xyz/exec/run-script.sh",
  },
  env: { FOO: "bar", UNSET: undefined },
};

describe("buildOciConfig", () => {
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

    it("starts in the working directory when given one, the workdir staying writable", () => {
      const config = build(fakeBaseSpec(), { ...baseArgs, cwd: "/opt/app" });
      expect(config.process.cwd).toBe("/opt/app");
      expect(config.mounts.map((m) => m.destination)).toContain(baseArgs.writable.workdir);
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
        "__BUILDCAGE_ENV_END__",
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

    function withNamespaces(namespaces: { type: string; path?: string }[]) {
      const spec = fakeBaseSpec();
      spec.linux.namespaces = namespaces;
      return spec;
    }

    const without = (type: string) =>
      fakeBaseSpec().linux.namespaces.filter((ns) => ns.type !== type);

    it.each(["pid", "network", "mount", "ipc", "uts"])(
      "refuses a default spec with no %s namespace",
      (type) => {
        expect(() => build(withNamespaces(without(type)), baseArgs)).toThrow(
          `exactly one new ${type} namespace`,
        );
      },
    );

    it("refuses a default spec that joins an existing namespace instead of making one", () => {
      const spec = withNamespaces([...without("pid"), { type: "pid", path: "/proc/1/ns/pid" }]);
      expect(() => build(spec, baseArgs)).toThrow("exactly one new pid namespace");
    });

    it("refuses a default spec that lists a namespace twice", () => {
      const spec = withNamespaces([...fakeBaseSpec().linux.namespaces, { type: "network" }]);
      expect(() => build(spec, baseArgs)).toThrow("exactly one new network namespace");
    });

    // runc leaves the cgroup namespace out on a cgroup v1 host.
    it("does not require a cgroup namespace", () => {
      const config = build(withNamespaces(without("cgroup")), baseArgs);
      expect(config.linux.namespaces.map((ns) => ns.type)).toStrictEqual([
        "pid",
        "network",
        "ipc",
        "uts",
        "mount",
      ]);
    });
  });

  describe("the cgroup", () => {
    it("makes it a child of the runner's own, named after the container", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.cgroupsPath).toBe(`${RUNNER_CGROUP}/buildcage-proxy-abcd1234`);
    });

    // What a runner in a cgroup namespace of its own sees.
    it("puts it at the top of a cgroup namespace whose root the runner is in", () => {
      probes = { ...pinnedProbes(), cgroupPath: () => "/" };
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.cgroupsPath).toBe("/buildcage-proxy-abcd1234");
    });

    it("leaves it to runc on a host that is not cgroup v2 only", () => {
      probes = { ...pinnedProbes(), cgroupPath: () => undefined };
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux).not.toHaveProperty("cgroupsPath");
    });
  });

  describe("paths masked from the step", () => {
    it("keeps runc's own masked and read-only paths beside the action's own masks", () => {
      const config = build(fakeBaseSpec(), baseArgs);
      expect(config.linux.maskedPaths).toEqual(
        expect.arrayContaining(["/proc/kcore", "/proc/timer_list"]),
      );
      expect(config.linux.readonlyPaths).toContain("/proc/bus");
      expect(config.linux.maskedPaths).toContain("/proc/kallsyms");
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

    it("masks an $XDG_RUNTIME_DIR outside /run, which the tmpfs doesn't reach", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        env: { ...baseArgs.env, XDG_RUNTIME_DIR: "/tmp/runtime-runner" },
      });
      expect(config.linux.maskedPaths).toContain("/tmp/runtime-runner");
    });

    it("covers a /var/run that isn't a link to /run with its own tmpfs, before the writable layers", () => {
      probes = { ...pinnedProbes(), varRunRealPath: () => "/var/run" };
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/var/run/docker.sock"] },
      });
      const destinations = config.mounts.map((m) => m.destination);
      const varRun = destinations.indexOf("/var/run");
      expect(config.mounts[varRun]).toMatchObject({ type: "tmpfs" });
      expect(varRun).toBeLessThan(destinations.indexOf("/var/run/docker.sock"));
    });

    it("drops the /run coverage tmpfs under write-through: /, the documented full opt-out", () => {
      // write-through: / hands the whole host back writable, /run included, so
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

    // Which destinations count is persistentLayers' own; this says runc's base spec feeds it.
    it("fails closed when a writable path names a destination runc mounts itself", () => {
      const attempt = () =>
        build(fakeBaseSpec(), {
          ...baseArgs,
          writable: { ...baseArgs.writable, writablePaths: ["/proc/self"] },
        });
      expect(attempt).toThrow(WritablePathConflictError);
    });

    it("forces host mounts read-only except the writable layers and what runc mounts fresh", () => {
      const runnerTemp = "/opt/actions-runner/_work/_temp"; // self-hosted: outside $HOME
      const hostMounts = [
        { mountPoint: "/", fsType: "ext4" },
        { mountPoint: "/proc", fsType: "proc" },
        { mountPoint: "/mnt", fsType: "ext4" },
        { mountPoint: runnerTemp, fsType: "ext4" },
        { mountPoint: baseArgs.writable.workdir, fsType: "ext4" },
      ];
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: [], runnerTemp },
        runtime: { ...baseArgs.runtime, hostMounts },
      });
      const rw = config.mounts.filter((m) => m.options?.includes("rw")).map((m) => m.destination);
      expect(rw).toContain(runnerTemp);
      expect(config.linux.readonlyPaths).toContain("/mnt");
      for (const p of ["/", "/proc", runnerTemp, baseArgs.writable.workdir]) {
        expect(config.linux.readonlyPaths).not.toContain(p);
      }
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
        readonlyHostPaths: ["/home/runner/.docker", "/home/runner/work/_actions/x/y/v1"],
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

  it("never binds a rename guard on or around a path the sandbox mounts fresh", () => {
    const config = build(fakeBaseSpec(), {
      ...baseArgs,
      renameGuardDirs: ["/dev", "/dev/shm", "/dev/shm/x", "/home/runner"],
    });
    const guarded = config.mounts
      .filter((m) => m.source === m.destination && m.options?.includes("rbind"))
      .map((m) => m.destination);
    expect(guarded).not.toContain("/dev");
    expect(guarded).not.toContain("/dev/shm");
    expect(guarded).not.toContain("/dev/shm/x");
    expect(guarded).toContain("/home/runner");
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
    // (see paths.test.ts); what this says is that write-through reaches it.
    it("fails closed when write-through: names the scratch base", () => {
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
        // binds, so a write-through entry under /run is re-exposed on top of the
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

    it("re-exposes a write-through path under /run on top of the coverage tmpfs", () => {
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

    it("keeps its own mounts after a write-through entry that contains them", () => {
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

  describe("`write-through: /`, the documented full opt-out", () => {
    it("`write-through: /` is exempt from the scratch-base guard (documented full opt-out)", () => {
      expect(() =>
        build(fakeBaseSpec(), {
          ...baseArgs,
          writable: { ...baseArgs.writable, writablePaths: ["/"] },
        }),
      ).not.toThrow();
    });

    it("`write-through: /` disables the read-only root and skips the individual writable-path mounts", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
      });
      expect(config.root.readonly).toBe(false);
      const rw = config.mounts.filter((m) => m.options?.includes("rw"));
      expect(rw.length).toBe(0);
    });

    it("`write-through: /` still keeps the action's own host directories read-only", () => {
      const config = build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/"] },
        readonlyHostPaths: ["/home/runner/.docker"],
      });
      expect(config.linux.readonlyPaths).toContain("/home/runner/.docker");
    });

    it("`write-through: /` skips the host-mount readonly pass entirely", () => {
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

  it("mounts each overlay root as an overlay and each write-through entry as a writable bind", () => {
    const config = build(fakeBaseSpec(), { ...baseArgs, ephemeral });
    const overlays = config.mounts.filter((m) => m.type === "overlay").map((m) => m.destination);
    expect(overlays.toSorted()).toStrictEqual(["/home/runner", "/tmp"]);
    expect(
      config.mounts.find((m) => m.destination === baseArgs.writable.workdir)?.options,
    ).toContain("rw");
  });

  it("fails closed when a write-through entry names a destination runc mounts itself", () => {
    expect(() =>
      build(fakeBaseSpec(), { ...baseArgs, ephemeral: { ...ephemeral, allowWrite: ["/proc"] } }),
    ).toThrow(WritablePathConflictError);
  });

  it("does not fall back to the persistent writableDirs logic (workdir/home/tmp/RUNNER_TEMP) when ephemeral is set", () => {
    const config = build(fakeBaseSpec(), {
      ...baseArgs,
      ephemeral,
      writable: { ...baseArgs.writable, writablePaths: ["/opt/should-be-ignored"] },
    });
    expect(config.mounts.some((m) => m.destination === "/opt/should-be-ignored")).toBe(false);
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

  it("feeds overlay roots and write-through paths into the readonlyPaths host-mount pass as protected", () => {
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

  it("still fails closed if an overlay root or write-through entry somehow overlaps the scratch base", () => {
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
  const systemStore = {
    kind: "systemStore" as const,
    path: "/scratch/system-ca-bundle.pem",
    destination: SYSTEM_STORE,
  };
  const caTrust = { ownCaPath: "/scratch/buildcage-ca.pem", stores: [systemStore] };

  it("refuses a write-through entry naming a keystore it mounts, in either mode", () => {
    const keystore = "/usr/lib/jvm/jdk/lib/security/cacerts";
    const withKeystore = {
      ...caTrust,
      stores: [
        { kind: "jvmKeystore" as const, path: "/scratch/jvm-0/cacerts", destination: keystore },
      ],
    };
    expect(() =>
      build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: [keystore] },
        caTrust: withKeystore,
      }),
    ).toThrow(WritablePathConflictError);
    expect(() =>
      build(fakeBaseSpec(), {
        ...baseArgs,
        ephemeral: { overlayRoots: [], allowWrite: [keystore] },
        caTrust: withKeystore,
      }),
    ).toThrow(WritablePathConflictError);
  });

  it("refuses a write-through entry where a symlinked CA directory leads", () => {
    const anchors = "/etc/pki/ca-trust/source/anchors";
    probes = { ...pinnedProbes(), realpath: (p) => (p === anchors ? "/opt/anchors" : p) };
    expect(() =>
      build(fakeBaseSpec(), {
        ...baseArgs,
        writable: { ...baseArgs.writable, writablePaths: ["/opt/anchors"] },
        caTrust: {
          ...caTrust,
          stores: [{ kind: "caDir" as const, path: "/scratch/ca-dir0", destination: anchors }],
        },
      }),
    ).toThrow(WritablePathConflictError);
  });

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
      options: ["rbind", "ro", "nosuid", "nodev", "noexec"],
    });
    expect(config.mounts).toContainEqual({
      destination: SYSTEM_STORE,
      type: "none",
      source: systemStore.path,
      options: ["rbind", "ro"],
    });
  });

  it("keeps the system store and CA directory mounts after a write-through entry containing them", () => {
    const anchors = "/etc/pki/ca-trust/source/anchors";
    const config = build(fakeBaseSpec(), {
      ...baseArgs,
      writable: { ...baseArgs.writable, writablePaths: ["/etc"] },
      caTrust: {
        ...caTrust,
        stores: [
          systemStore,
          { kind: "caDir" as const, path: "/scratch/ca-dir0", destination: anchors },
        ],
      },
    });
    const destinations = config.mounts.map((m) => m.destination);
    expect(destinations.indexOf(SYSTEM_STORE)).toBeGreaterThan(destinations.indexOf("/etc"));
    expect(destinations.indexOf(anchors)).toBeGreaterThan(destinations.indexOf("/etc"));
  });

  // Mounted before the tmpfs, the file would be hidden under it.
  it("mounts the CA-only file after runc's /dev tmpfs, which it sits under", () => {
    const spec = fakeBaseSpec();
    spec.mounts.unshift({ destination: "/dev", type: "tmpfs", source: "tmpfs" });
    const destinations = build(spec, { ...baseArgs, caTrust }).mounts.map((m) => m.destination);
    expect(OWN_CA_DESTINATION.startsWith("/dev/")).toBe(true);
    expect(destinations.indexOf(OWN_CA_DESTINATION)).toBeGreaterThan(destinations.indexOf("/dev"));
  });
});

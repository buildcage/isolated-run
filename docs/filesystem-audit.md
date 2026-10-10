# Filesystem audit

> [!WARNING]
> `filesystem_audit` is **experimental**: its behavior, inputs, and output format may still change
> in a future release without following semver. Try it in a non-critical workflow first, and pin
> this action to a commit SHA rather than a version tag if you adopt it.

`filesystem_audit: record` records every file the isolated step opens, reads, writes, moves,
deletes, changes the attributes of, and executes. It adds a section to the Job Summary and uploads
the full record as an artifact. It watches from the kernel, so a static binary or a tool that
bypasses libc is seen like any other, and it only records: it never blocks an access. What the step
may write is decided by [`filesystem_mode` and `write_through`](../README.md#filesystem-access).

## What it is for

- **Finding what `write_through` needs.** Under `filesystem_mode: ephemeral` every write is thrown
  away when the step ends, except under the paths `write_through` names. Run the step once with
  both, and the `W`, `M` and `D` rows show where it wrote: the build output and the files a later
  step reads, such as `$GITHUB_OUTPUT`, belong in `write_through`, and the rest is what ephemeral
  discards on purpose.

  ```yaml
  - uses: buildcage/isolated-run@<sha>
    with:
      filesystem_mode: ephemeral
      filesystem_audit: record
      write_through: |
        $GITHUB_OUTPUT
        ./dist
      run: npm ci && npm run build
  ```

- **Checking what a dependency read.** A row such as `R ~/.npmrc`, `R ~/.ssh/**` or
  `R ~/.docker/config.json` says a command in the step opened a credential file. The details say
  which command, and the artifact says when and from which process.
- **Seeing what an install ran.** The executed table lists every program the step started, so a
  `postinstall` script that runs `curl` or a binary it just downloaded shows up there.
- **Seeing what was refused.** A lowercase flag with `!` is an access the sandbox, a file's
  permissions or a read-only location refused, such as a write to `/usr/local/bin`, which the
  sandbox makes read-only, or a read of `/etc/shadow`.

## Getting started

### Which runners

GitHub-hosted `ubuntu-latest`, `ubuntu-22.04`, `ubuntu-24.04` and their `-arm` variants meet every
requirement: their kernels are Linux 6.8 or newer, on cgroup v2, with BTF and tracefs. On a
self-hosted runner, check the host before turning it on:

```sh
uname -rm                         # Linux 6.1 or newer; 6.4 or newer on aarch64
stat -fc %T /sys/fs/cgroup        # cgroup2fs
ls /sys/kernel/btf/vmlinux        # the kernel's type information (BTF)
sudo ls /sys/kernel/tracing/events >/dev/null   # tracefs, or /sys/kernel/debug/tracing
```

A host that falls short fails the step before the command runs, with the reason; see
[Troubleshooting](#troubleshooting).

### Turning it on

```yaml
- id: build
  uses: buildcage/isolated-run@<sha>
  with:
    filesystem_audit: record
    run: npm ci
```

The step's Job Summary gets a **Filesystem audit** section after the traffic report, and the
`filesystem_audit_artifact_name` output names the uploaded record:

```yaml
- if: steps.build.outputs.filesystem_audit_artifact_name != ''
  uses: actions/download-artifact@v5
  with:
    name: ${{ steps.build.outputs.filesystem_audit_artifact_name }}
```

The output is empty when nothing was recorded or the upload failed, and `download-artifact` with an
empty name downloads every artifact of the run, hence the `if:`.

`filesystem_audit_retention_days` sets how long the artifact is kept; empty uses the repository's
default. The artifact names each program the step ran but not its arguments, which can carry
secrets. It still holds every path the step touched, including the names of files it only tried to
open, so treat it as sensitive, like the traffic artifact.

## Reading the summary

```
### Filesystem audit
R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied

#### Executed
| Path                  |
| --------------------- |
| `/usr/local/bin/node` |

#### Accessed paths
| Access | Path                  |
| ------ | --------------------- |
| RWD    | `./node_modules/**`   |
| R      | `./package.json`      |
| Rr!    | `/etc/**`             |

📂 Filesystem details
first-last access
00:00.412:           R   node ./package.json
00:00.415-00:00.418: Rr! node /etc/**
00:00.530-00:41.207: RWD node ./node_modules/**
```

- **Executed** lists each program once, in the order it first ran.
- **Accessed paths** combines every command's actions on a path in one row, in path order: the
  workspace first, then `$HOME`, then the rest.
- **📂 Filesystem details**, folded, has one row per command and path, in the order the rows were
  first touched. The command is the name the process gave itself, as `ps` shows it. The time is when
  that command first and last touched the path, counted from the proxy's start like the
  communication details, or from the first access if that start is unknown.

### Flags

| Flag | Means                                                                                          |
| ---- | ---------------------------------------------------------------------------------------------- |
| `R`  | Read, or mapped for reading                                                                    |
| `W`  | Written, mapped shared and writable, created or truncated: a file, a directory, a link         |
| `X`  | Run as a program                                                                               |
| `M`  | Moved (renamed), from or to this path                                                          |
| `D`  | Deleted                                                                                        |
| `A`  | Attributes changed: mode, owner, times, extended attributes                                    |
| `r`  | Lowercase: the action failed every time it was tried here, such as opening a missing file      |
| `r!` | Refused: for want of permission, by the sandbox or the file's own mode, or on a read-only path |

A refusal shows even where the same action also succeeded, after the uppercase letters: `RWr!` on
`/etc/**` means reads and writes under `/etc` succeeded and at least one read was refused. A failed
open shows as `r` whatever it was opened for. A row's flags do not say which action came first; the
artifact has every access in order.

### Paths

| Shown as               | Means                                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `./…`                  | Under `$GITHUB_WORKSPACE`                                                                                        |
| `~/…`                  | Under `$HOME`                                                                                                    |
| `dir/**`               | Three or more entries directly under `dir` were touched, so it is shown as one row with every flag below it      |
| `…/name`               | A relative name whose directory was closed before it could be read, or a path too deep to record in full         |
| `memfd:"name"`         | A file that exists only in memory and has no path; the name is whatever its creator chose                        |
| `path (deleted)`       | A file deleted while it was open, or created without a name and never given one; not shown inside a `dir/**` row |
| `\n`, `\u{202e}`, `\\` | A control or invisible character, or a backslash, in a path or command name                                      |

`/`, `/home`, `/tmp`, `/proc`, the workspace, `$HOME` and the directories above them are never
folded into a `dir/**` row, nor is `/proc/<pid>`, which stands for any process's own directory.

A program is shown under the file it ran, with symlinks followed, and a script under its own path
rather than its interpreter's. A failed access is shown under the name the command passed, joined to
its working directory, or the directory it passed by descriptor, without resolving `..`. A command reading or writing through a file it
inherited or was passed is shown under its own name, except for a pipe, a socket or a device such as
`/dev/null`, which counts once.

### What is left out

The summary leaves out what any program does just to start: the shared libraries it loads, its
reads of them and of `/etc/ld.so.cache`, and its own reads of the program file. Another program
reading those files is shown. A file counts as a library when the kernel loads it to start a
program, or when its name ends in `.so`, `.so.<version>` or `.node` and it is neither in memory only
nor deleted.

A file kept open counts only the first read and the first write through it by each program, so the
last time in the details can be earlier than its last write.

## The artifact

The artifact named `buildcage-filesystem-audit-<id>` holds one file of JSON lines, one access per
line in the order they happened, with absolute paths. A few examples:

```sh
# Every file the step wrote, created or truncated, and every directory it made
jq -r 'select((.failed | not) and (.kind == "write" or .kind == "mkdir"
  or (.kind == "open" and (.access // "" | test("[ct]"))))) | .path' filesystem-audit-*.jsonl | sort -u

# Who opened a credential file, and when
jq -c 'select(.path // "" | endswith("/.npmrc")) | {t, comm, pid, kind}' filesystem-audit-*.jsonl

# Every refused open
jq -c 'select(.kind == "open-failed" and (.err == 1 or .err == 13 or .err == 30))' filesystem-audit-*.jsonl
```

Where a recorded `path` differs from the name the command passed, the name is kept as `name`, or
`to_name` for a move's target. A program's line keeps the name it was run by as `name`. A memfd is
marked `"memfd":true`, a deleted file `"deleted":true`, a program the kernel loaded to start a
process `"image":true`, and a rename that swapped two paths `"exchange":true`, which shows `M` on
both.

The last line is the end line, such as
`{"kind":"end","dropped":0,"untracked":0,"host_missed":0}`, written only after every access the
tracer caught:

- `dropped` counts accesses lost because the tracer's buffer was full.
- `untracked` counts calls it could not follow because too many files were open, or too many calls
  in progress, at once.
- `host_missed` counts hooks the kernel skipped anywhere on the host while the step ran; see
  [Skipped hooks](#skipped-hooks).

## Troubleshooting

The step fails before the command runs with
`filesystem_audit could not start (<reason>); the command was not run.`

| Reason                                                   | What to do                                                                                               |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `the runner is not on cgroup v2`                         | Boot the host with cgroup v2 (the default on Ubuntu 22.04 and later)                                     |
| `the kernel exposes no BTF`                              | Use a kernel built with BTF (`/sys/kernel/btf/vmlinux`), as Ubuntu's and most distributions' are         |
| `the kernel is older than Linux 6.1`                     | Move to Linux 6.1 or newer                                                                               |
| `attach <name>: …` on arm64                              | Move to Linux 6.4 or newer, the first arm64 kernel that lets the tracer hook kernel functions            |
| `attach <name>: neither debugfs nor tracefs are mounted` | Mount tracefs: `sudo mount -t tracefs tracefs /sys/kernel/tracing`                                       |
| `the tracer did not attach in time`                      | The host was too busy to start the tracer; run the job again                                             |
| Anything else                                            | The tracer's own error; please [open an issue](https://github.com/buildcage/isolated-run/issues) with it |

The summary can also open with a warning:

- **This record is incomplete.** `dropped` or `untracked` is nonzero, or the tracer did not stop
  cleanly. Some accesses are missing from both the summary and the artifact. A step that touches a
  very large number of files at once can cause it.
- **The recording could not be read.** The summary has none of the step's accesses, a warning is
  logged, and no artifact is uploaded.

## What it does not record

- A `stat`, or an open that only obtains a handle (`O_PATH`), which reads no content. What a command
  then does through such a handle, such as running or reopening the file, is recorded.
- Work handed to a process outside the sandbox, such as an `ssh-agent` or `gpg-agent` reached over a
  socket.
- A change through a file the command inherited from the program that ran it, an extended attribute
  change other than through `setxattr` or `lsetxattr`, a failed `exec`, and a `mkdir`, `mknod`,
  `symlink`, `link` or `truncate` that fails before reaching its file.
- The sandbox's own setup, and the step's shell reading its script.

[Filesystem audit](./security.md#filesystem-audit) in the security details covers what the step
itself can do to the record, and what the record can be trusted for.

## Requirements and limits

- **Kernel.** A cgroup v2 host on Linux 6.1 or newer, 6.4 or newer on arm64, with kernel BTF and
  tracefs mounted. cgroup v2 and BTF are checked before the proxy starts, the kernel version and
  tracefs when the tracer starts.
- **Cost to the whole host.** While the step runs, the tracer's hooks run on every system call and
  every file read or write on the runner host, not only the step's, since a hook has to run to tell
  whose call it is. That adds roughly 100 nanoseconds to each system call of every process on the
  machine, the proxy, Docker and other jobs on a shared runner included. Copying a file a byte at a
  time outside the step took nearly twice as long in a test, while a typical build, which spends
  little of its time in system calls, barely changes. Inside the step, each program's first read or
  write of a file is also recorded, which costs more.
- **Job Summary size.** When the traffic report and this section would pass GitHub's 1 MiB cap,
  the filesystem details give way first and this section's tables after the traffic report's
  communication log; [The Job Summary size cap](../README.md#the-job-summary-size-cap) has the full
  order. What is cut is replaced by a note naming the artifact, which still holds every access, or
  saying the record was not kept when the upload failed.

### Skipped hooks

The kernel can skip one of the tracer's hooks: those for failed operations while another BPF
program, such as a security or monitoring agent's, is running on the same CPU, and, on a kernel
built for full preemption, a hook entered again while it is paused mid-run. A stock Ubuntu kernel,
as on GitHub-hosted runners, does not pause the hooks. `host_missed` counts skips anywhere on the
host while the step ran, so 0 means none of the step's accesses was skipped. The summary does not
warn on a nonzero count, since a skip cannot be tied to the step. Before Linux 6.7 the kernel does
not count a skipped hook for failed operations.

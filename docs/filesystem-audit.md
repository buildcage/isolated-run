# Filesystem audit

> [!WARNING]
> `filesystem_audit` is **experimental**: its behavior, inputs, and output format may still change
> in a future release without following semver. Try it in a non-critical workflow first, and pin
> this action to a commit SHA rather than a version tag if you adopt it.

`filesystem_audit: record` records every file the isolated step reads, writes, moves, deletes,
changes the attributes of, and executes, and adds a **Process Activity Report** section to the Job
Summary:

```yaml
- uses: buildcage/isolated-run@<sha>
  with:
    filesystem_audit: record
    run: npm ci
```

It watches from the kernel, so a static binary or a tool that bypasses libc is seen like any other,
and it works the same whatever `proxy_mode` and `proxy_engine` are set to. It records and never
blocks an access: what the step may write is decided by
[`filesystem_mode` and `write_through`](../README.md#filesystem-access).

## What it is for

- **Finding what `write_through` needs** under `filesystem_mode: ephemeral`: the audit shows where
  the step wrote, so you keep only what a later step reads. See
  [Choosing `write_through`](#choosing-write_through).
- **Checking what a dependency read, wrote, ran, or was refused.** See
  [What to look for](#what-to-look-for).

It suits a step's first runs, a dependency update, or an investigation. It can also stay on, since a
typical build barely slows down, and then each run leaves a record to compare against.

## Before you turn it on

### What it needs

A cgroup v2 host on Linux 6.1 or newer, 6.4 or newer on arm64, with the kernel's type information
(BTF). GitHub-hosted `ubuntu-latest`, `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-26.04`,
`ubuntu-22.04-arm`, `ubuntu-24.04-arm` and `ubuntu-26.04-arm` meet all of it: their kernels are
Linux 6.8 or newer. On a self-hosted runner, check the host before turning it on:

```sh
uname -rm                         # Linux 6.1 or newer; 6.4 or newer on aarch64
stat -fc %T /sys/fs/cgroup        # cgroup2fs
ls -l /sys/kernel/btf/vmlinux     # the kernel's type information (BTF), not empty
```

A host that falls short fails the step before the command runs, with the reason; see
[Troubleshooting](#troubleshooting).

### What changes in the step

- **No 32-bit programs.** The tracer reads only the native 64-bit system calls, so with the audit on
  the sandbox refuses one through a 32-bit ABI, from an i386 or ARM32 program or `int 0x80`: the
  kernel kills the thread that made it with `SIGSYS`. A single-threaded program dies, which a shell
  reports as `Bad system call`. The summary's note then reads
  `Killed for a 32-bit system call: <command>`. Run such a program in a step without the audit.
- **A small cost to the whole host.** A typical build, which spends little of its time in system
  calls, barely changes. While the step runs, though, the tracer's hooks run on every system call on
  the runner host, not only the step's, since a hook has to run to tell whose call it is. A
  GitHub-hosted runner runs one job, so only that job pays. On a self-hosted runner shared by
  several jobs, they all do. Each hook adds roughly 60 nanoseconds to each system call, about 100 to
  each read or write, and about 250 to opening and closing a file. Copying a file a byte at a time
  outside the step took about one and a half times as long in a test. Inside the step, each
  program's first read or write of a file is also recorded, which costs more.

## Getting started

With `filesystem_audit: record` alone, as above, the step's Job Summary gets a **Process Activity
Report** section after the traffic report. The full record, with every access in order, is uploaded
only when asked for, as the traffic artifact is. It can be downloaded from the run's page, or by a
later step to query with `jq`, as in [The artifact](#the-artifact):

```yaml
- id: build
  uses: buildcage/isolated-run@<sha>
  with:
    filesystem_audit: record
    upload_filesystem_audit_artifact: true
    run: npm ci

- if: steps.build.outputs.filesystem_audit_artifact_name != ''
  uses: actions/download-artifact@<sha>
  with:
    name: ${{ steps.build.outputs.filesystem_audit_artifact_name }}
```

The `filesystem_audit_artifact_name` output names the uploaded artifact. It is empty when nothing
was uploaded, and without the `if:`, `download-artifact` would then download every artifact of the
run.

Each step with the audit on gets its own section and, when uploaded, its own artifact,
`buildcage-filesystem-audit-<id>`, where `<id>` is the same random suffix as that step's traffic
artifact, so several steps in one job never collide. Each section follows its step's traffic report,
and both headings carry the step's `label`, so set `label` to tell the steps apart.

`filesystem_audit_retention_days` sets how long the artifact is kept; see
[Reference](./reference.md#action-inputs). The artifact names each program the step ran but not its
arguments, which can carry secrets. It still holds every path the step touched, including the names
of files it only tried to open, so treat it as sensitive, like the traffic artifact.

## Reading the summary

A shortened example:

```
## Process Activity Report
> 🚫 Refused system calls: io_uring_setup (node).

### Executed Programs
| Path                  | Count |
| --------------------- | ----: |
| `/usr/local/bin/node` |     1 |
| `/usr/bin/dash`       |    12 |

▶ Accessed Paths (4)
R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused
| Program               | Access | Path                  |
| --------------------- | ------ | --------------------- |
| `/usr/local/bin/node` | RWD    | `./node_modules/**`   |
| `/usr/local/bin/node` | R      | `./package.json`      |
| `/usr/local/bin/node` | Rr!    | `/etc/**`             |
| `/usr/local/bin/node` | w!     | `/usr/local/bin/node` |

🔍 Process details
first-last access since the proxy started · flags · command · path
00:00.401-00:00.420: Xw! node /usr/local/bin/node
00:00.402:           !   node syscall:io_uring_setup
00:00.412:           R   node ./package.json
00:00.415-00:00.418: Rr! node /etc/**
00:00.530-00:41.207: RWD node ./node_modules/**
00:00.531-00:40.982: X   sh   /usr/bin/dash

./ workspace · ~/ $HOME · dir/** a folded directory · the full record is in the
buildcage-filesystem-audit-<id> artifact · how to read this
```

Where there is no artifact, the line closing the section says how to ask for one, or that the upload
failed. A step that touched no file shows `No file access was recorded.` instead of the tables. One
that only ran programs has no accessed paths table, and the flag legend opens the details instead.

From the top:

- The **🚫 Refused system calls** note names system calls the sandbox does not allow, such as
  `io_uring_setup`, and the commands that made them; see
  [Refused system calls](#refused-system-calls).
- **Executed Programs** lists each program once, in the order it first ran, with how many times it
  ran.
- **Accessed Paths**, folded, has one row per program and path, with a [flag](#flags) for each
  action. Programs are in the order they first ran, and each one's paths in path order: the
  workspace, then `$HOME`, then the rest. A `dir/**` row combines several paths under one
  directory; see [Paths](#paths).
- **🔍 Process details**, folded, has one row per command and path, in the order the rows were
  first touched. The command is the name the process gave itself, as `ps` shows it. The time is when
  that command first and last touched the path. It counts from the start of the step's proxy, about
  when the step starts, on the same clock as the traffic report's Communication details, so a file
  access can be matched to a request. Where that start is unknown, it counts from the first access.
- The closing line explains the `./`, `~/` and `dir/**` notations, names the artifact that holds the
  full record and links to this section.

[How rows are grouped](#how-rows-are-grouped) covers which program and path a row is shown under.

### What to look for

- **A credential file read by something other than its tool.** A row such as `R ~/.npmrc`,
  `R ~/.ssh/**` or `R ~/.docker/config.json` says a program opened it. npm reads `~/.npmrc` on
  every run, and npm and a package's install script both show as `node`, so the program alone does
  not tell them apart. The details do: npm names itself after its command, such as `npm ci`, while
  a script it starts shows under its own name, such as `node`. The artifact, if uploaded, also gives
  each read's parent process.
- **A write meant to outlive the step.** `W` on `./.git/hooks/**`, `./package.json`, `~/.bashrc`,
  `~/.npmrc` or another file a later step or job runs or reads. A write to `$GITHUB_ENV` or
  `$GITHUB_PATH` is refused (`w!`) unless `write_through` names it, since both are read-only in the
  sandbox otherwise, but the attempt is just as telling. `filesystem_mode: ephemeral` discards such
  writes; see the [README](../README.md#filesystem-access).
- **A program you did not expect.** **Executed Programs** lists every program the step started, so
  a `postinstall` script that runs `curl` or a binary it just downloaded shows up there.
- **A refusal.** A flag followed by `!`, such as `w!`, is an access the sandbox, a file's
  permissions or a read-only location refused: a write to `/usr/local/bin`, which the sandbox makes
  read-only, or a read of `/etc/shadow`. A system call the sandbox refused, such as `unshare`, is
  named in the **🚫 Refused system calls** note under the heading instead.

### Flags

| Flag | Means                                                                                          |
| ---- | ---------------------------------------------------------------------------------------------- |
| `R`  | Read, or mapped for reading or to run                                                          |
| `W`  | Written, mapped shared and writable, created or truncated: a file, a directory, a link         |
| `X`  | Run as a program; shown in the details only, as the executed table lists every program         |
| `M`  | Moved (renamed) away from this path; where it went is in the artifact                          |
| `L`  | Given a second name by a hard link, which shows as `W`; reads through it show under that name  |
| `D`  | Deleted                                                                                        |
| `A`  | Attributes changed: mode, owner, times, extended attributes                                    |
| `r`  | Lowercase: the action failed every time it was tried here, such as opening a missing file      |
| `r!` | Refused: for want of permission, by the sandbox or the file's own mode, or on a read-only path |

- A refusal shows even where the same action also succeeded, after the uppercase letters. `RWr!` on
  `/etc/**` means reads and writes under `/etc` succeeded and at least one read was refused.
- A failed open shows what it asked for: `w` to write, create or truncate, `r` to read, and both
  for one opened to read and write, as bash does `/dev/tty`.
- A swap of two paths (`renameat2` with `RENAME_EXCHANGE`) shows `M` on both.
- A row's flags do not say which action came first; the artifact has every access in order.

### Paths

| Shown as        | Means                                                                                                                                                            |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `./…`           | Under `$GITHUB_WORKSPACE`                                                                                                                                        |
| `~/…`           | Under `$HOME`                                                                                                                                                    |
| `dir/**`        | `dir` and the entries touched directly under it would take three or more rows, so they are shown as one with the flags of everything at and under `dir` combined |
| `/proc/<pid>/…` | Under a process's own directory in `/proc`, every process's shown as one                                                                                         |

Some paths stay on rows of their own rather than fold into a `dir/**` row, such as the workspace,
`$HOME` and a program run; [How rows are grouped](#how-rows-are-grouped) lists them, and
[Other notations](#other-notations) covers cut, in-memory, deleted and escaped names.

## Choosing `write_through`

Under `filesystem_mode: ephemeral` every write is thrown away when the step ends, except under the
paths `write_through` names. Two kinds of path are easy to miss:

- **The runner's files.** `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY` are written like any other
  file, so the step's outputs and its own summary are lost unless named. `$GITHUB_ENV` and
  `$GITHUB_PATH` are read-only in either mode, and need naming to be written at all.
- **Caches.** `actions/cache`, and setup actions with `cache:`, save a directory such as `~/.npm`
  after the job. Unless it is named, the save finds nothing the step added to it.

To name only what a later step needs:

1. Run the step with `filesystem_mode: ephemeral`, `filesystem_audit: record` and
   `upload_filesystem_audit_artifact: true`, and in `write_through` only what you already know a
   later step reads.
2. Look at the `W`, `D`, `A` and `M` rows under **Accessed Paths**. A file a tool writes under a
   temporary name and then renames into place shows `M` under the temporary name; its new name is
   the `to` on its `rename` line in the artifact.
3. Of those, add to `write_through` what a later step or the end of the job uses: build output,
   test reports, coverage, a cache directory. Run again. The rest is what ephemeral discards on
   purpose.

A build that sets outputs and writes `./dist` ends up with this; the audit can be left on or taken
off:

```yaml
- uses: buildcage/isolated-run@<sha>
  with:
    filesystem_mode: ephemeral
    write_through: |
      $GITHUB_OUTPUT
      ./dist
    run: npm ci && npm run build
```

## Troubleshooting

The step fails before the command runs with
`filesystem_audit could not start (<reason>); the command was not run.`

| Reason                               | What to do                                                                                                                                                                   |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `the runner is not on cgroup v2`     | Boot the host with cgroup v2 (the default on Ubuntu 22.04 and later). On a cgroup v2 host, it means the runner's own cgroup lies outside its cgroup namespace or was removed |
| `the kernel exposes no BTF`          | Use a kernel built with BTF (`/sys/kernel/btf/vmlinux`), as Ubuntu's and most distributions' are. An empty file, such as `/dev/null` mounted there, counts as none           |
| `read kernel BTF: …`                 | See below the table                                                                                                                                                          |
| `the kernel is older than Linux 6.1` | Move to Linux 6.1 or newer                                                                                                                                                   |
| `attach <name>: …` on arm64          | Move to Linux 6.4 or newer, the first arm64 kernel that lets the tracer hook kernel functions                                                                                |
| `the tracer did not attach in time`  | The host was too busy to start the tracer; run the job again                                                                                                                 |
| Anything else                        | The tracer's own error; please [open an issue](https://github.com/buildcage/isolated-run/issues) with it                                                                     |

`read kernel BTF: …` ending in `unknown kind …`, `header contains non-zero trailer` or
`unsupported flags …` means the kernel's BTF is newer than the tracer can read. Please
[open an issue](https://github.com/buildcage/isolated-run/issues) with the output of `uname -r`.
Other endings, such as `no valid BTF header` or `no BTF found …`, mean
`/sys/kernel/btf/vmlinux` is not the kernel's own or root cannot read it.

The summary can also open with a warning, or be missing:

- **❗ This record is incomplete.** `dropped` or `untracked` on the record's
  [end line](#the-end-line) is nonzero, or the tracer did not stop cleanly. Some accesses are
  missing from both the summary and the artifact. A step that touches a very large number of files
  at once can cause it.
- **❗ This record is incomplete, with the error
  `The filesystem audit tracer stopped before it finished its record`.** The step fails, in `audit`
  too. The record has no [end line](#the-end-line): the tracer exited before the step ended, or did
  not finish the record when the step stopped it. A reason the tracer gave is in the step log on a
  `filesystem-audit: fatal:` line, such as one ending in `no space left on device` once the step
  filled the disk. A cancelled step does not add this error.
- **❗ The kernel skipped the tracer's hooks N times.** `host_missed` on the end line is nonzero, so
  some accesses may be missing; see [Skipped hooks](#skipped-hooks).
- **❗ The recording could not be read**, with a `Failed to read the filesystem audit recording`
  warning. The summary has none of the step's accesses, and no artifact is uploaded.
- **❗ The recording could not be read, with the error `The filesystem audit recording is gone`.**
  The step fails, in `audit` too. The recording was removed after the tracer started, by a process
  on the runner host outside the sandbox.
- **No section, and a `Failed to render the filesystem audit summary` warning.** The recording was
  read but its summary could not be written; the artifact is still uploaded if asked for. Please
  [open an issue](https://github.com/buildcage/isolated-run/issues) with the warning.

A program in the step that dies with `Bad system call` made a 32-bit system call, which the audit
refuses; see [What changes in the step](#what-changes-in-the-step).

### Skipped hooks

On a GitHub-hosted runner there is nothing to do here. Read on only if a self-hosted runner shows a
nonzero `host_missed`, or the note above.

On some kernels one of the tracer's hooks can be paused mid-run, and is then skipped when it is
entered again. GitHub-hosted runners boot `-azure` kernels, 7.0 on `ubuntu-26.04`, and these do not
pause the hooks. Nor do Ubuntu 24.04's `generic` kernel or 22.04's 6.8 hardware enablement kernel in
their default preemption mode. Ubuntu 26.04's `generic` kernel and the 7.0 hardware enablement
kernel of 24.04 do. On a self-hosted runner, `sudo cat /sys/kernel/debug/sched/preempt` prints the
modes with the one in use in parentheses, such as `full (lazy)`, and hooks can be skipped when it is
`(full)` or `(lazy)`. That file needs debugfs mounted at `/sys/kernel/debug`. Where it is missing
even so, the kernel cannot switch modes, and hooks can be skipped when `/boot/config-$(uname -r)`
sets `CONFIG_PREEMPT_RCU=y`.

`host_missed` counts skips anywhere on the host while the step ran, so 0 means none of the step's
accesses was skipped. A nonzero count opens the summary with a note that some accesses may be
missing; a skip cannot be tied to the step, so the note cannot say they are. A skipped hook drops
the access it was following rather than reporting it against the wrong call, save where a recorded
path may be an earlier one's: an open may carry an earlier open's path, and a delete, move or other
path change whose own hook was skipped too an earlier such change's. For a complete record, use a
kernel that does not pause the hooks, such as one booted with `preempt=voluntary` where the kernel
offers that mode.

## The artifact

With `upload_filesystem_audit_artifact: true`, the artifact named `buildcage-filesystem-audit-<id>`
holds one file, `filesystem-audit-<id>.step.jsonl`: one JSON object per line, in the order the
tracer caught the accesses. Opens and path changes are written when their call returns, so lines
from different threads can be slightly out of `t` order. It holds only the step's own accesses, as
the summary does: the sandbox's setup is left out, and the step's shell is named `bash`. A record
marked incomplete can hold the setup too. A few examples:

```sh
# Every path written, made or moved to
jq -r 'select(.failed | not)
  | if (.kind | IN("write", "mkdir", "mknod", "symlink", "truncate"))
      or (.kind == "open" and (.access // "" | test("[ct]")))
      or (.kind == "mmap" and .access == "w") then .path
    elif .kind == "link" or .kind == "rename" then .to
    else empty end
  | select(. != null and (startswith("/") or startswith("…/") or startswith("memfd:")))' \
  filesystem-audit-*.jsonl | sort -u

# Who opened a credential file, and when
jq -c 'select(.path // "" | endswith("/.npmrc")) | {t, comm, pid, ppid, kind}' filesystem-audit-*.jsonl

# Every refused open
jq -c 'select(.kind == "open" and .failed and (.err == 1 or .err == 13 or .err == 30))' filesystem-audit-*.jsonl
```

The last `select` of the first example drops pipes and sockets, which the summary leaves out too.
Unlike the summary, it also lists a directory that was made and then written under.

### Fields

| Field      | On                                             | Notes                                                                                                                                                |
| ---------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `t`        | every line but `end`                           | ISO 8601 UTC, to the millisecond                                                                                                                     |
| `kind`     | every line                                     | what happened; see [Kinds](#kinds)                                                                                                                   |
| `pid`      | every line but `end`                           | the process, as the runner host numbers it                                                                                                           |
| `ppid`     | every line but `end`                           | its parent at the time; on `fork`, the process that made it                                                                                          |
| `comm`     | every line but `end`                           | the name the process gave itself, up to 15 bytes                                                                                                     |
| `path`     | all but `fork`, `syscall`, `end`               | the file acted on; on `rename` and `link` the old name; absent, with `err`, when it could not be read. See below for when it is not an absolute path |
| `to`       | `rename`, `link`, `symlink`                    | the new name; on `symlink`, the link's contents as written, absent on a failed one                                                                   |
| `name`     | where it differs from `path`, and every `exec` | the name the command passed; on `exec`, the name it was run by                                                                                       |
| `to_name`  | where it differs from `to`                     | as `name`, for `to`                                                                                                                                  |
| `access`   | `open`, `mmap`                                 | what was asked for; see [Access letters](#access-letters)                                                                                            |
| `flags`    | `open`                                         | the `open(2)` flags as a number, which the kernel gives `O_LARGEFILE` even on a plain read-only open                                                 |
| `mode`     | `chmod`                                        | the new mode in octal, such as `"0755"`                                                                                                              |
| `owner`    | `chown`                                        | the new `uid:gid`, with `-1` for a side left as it was                                                                                               |
| `failed`   | a failed operation                             | `true`                                                                                                                                               |
| `err`      | a failed operation                             | the error number; see [Error numbers](#error-numbers). Without `failed`, a negative number: why an open file's path could not be read                |
| `image`    | `mmap`                                         | a file the kernel mapped to start a program: the program, its loader or a script's interpreter                                                       |
| `memfd`    | a file in memory only                          | `path` is `memfd:` and the name its creator chose                                                                                                    |
| `deleted`  | a deleted or never-named file                  | a file deleted while it was open, or created without a name and never given one                                                                      |
| `exchange` | `rename`                                       | a swap of two paths, which shows `M` on both in the summary                                                                                          |
| `syscall`  | `syscall`                                      | the system call's name, or its number where the tracer has no name for it                                                                            |
| `compat`   | `syscall`                                      | a 32-bit or x32 system call                                                                                                                          |
| `killed`   | `syscall`                                      | seccomp killed the program for it, with `SIGSYS`; `err` is absent                                                                                    |

A field is absent where it does not apply, and `failed`, `image`, `memfd`, `deleted` and `exchange`
are absent rather than `false`.

`path` is absolute except for a file in memory only (`memfd:…`), a pipe, socket or other file the
kernel names without a path (such as `pipe:[1234]`), a path too deep to record in full (`…/…`), and
the relative name of a failed call or an attribute change whose directory could not be read. A
failed open's `path` and `name` end in `…` where its name was too long to record in full.

A byte of a name that is not UTF-8 is written as a lone surrogate, `\udcff` for the byte `0xff`, as
Python's `surrogateescape` does, so `os.fsencode` gives back the name's exact bytes. jq prints it as
`�`; the summary shows it as `\xff`.

### Kinds

A failed operation keeps the kind it would have had, with `"failed":true` and `err`, and shows its
letter lowercase in the summary. A failed `open`, `unlink`, `rmdir` or `rename`, and a failed
`chmod`, `chown`, `attr` or `truncate`, on a path or through a file descriptor as `fchmod` or
`ftruncate` do, is recorded however it failed. One through a descriptor that the kernel refused
before reaching its file is recorded only if, when the call returns, the descriptor is still open on
a regular file or a directory other than a memfd. An `open` refused before the kernel looked its
name up, as one a seccomp filter stopped or one with no free descriptor, is not recorded, unless it
failed with `ENAMETOOLONG`, which is recorded under the name the command passed. A failed `mkdir`,
`mknod`, `symlink` or `link` is recorded too unless its name was already there (`EEXIST`), which
changed nothing and which `mkdir -p` meets at every level it keeps. A failed `mmap` is not recorded,
nor is a failed `exec`, though the file it opened before failing can show as an `open` with `x`.

| `kind`                                  | Records                                                                                                                                                                                                                                                                                                             | Summary                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `open`                                  | a file opened; the summary counts one that creates or truncates, or that failed                                                                                                                                                                                                                                     | `W`, `r`, `w`                                                |
| `read`, `write`                         | the first read, or the first write, through each opened file by each program a process runs; through a device, a pipe or a socket, by any program                                                                                                                                                                   | `R`, `W`                                                     |
| `mmap`                                  | a file mapped into memory                                                                                                                                                                                                                                                                                           | `R`, or `W` for a shared writable mapping                    |
| `exec`                                  | a program run                                                                                                                                                                                                                                                                                                       | `X`                                                          |
| `fork`                                  | a new process; `pid` is the child                                                                                                                                                                                                                                                                                   | none                                                         |
| `unlink`, `rmdir`                       | a file or a directory deleted                                                                                                                                                                                                                                                                                       | `D`                                                          |
| `rename`                                | a move from `path` to `to`                                                                                                                                                                                                                                                                                          | `M` on `path`                                                |
| `mkdir`, `mknod`, `symlink`, `truncate` | a directory, a special file or Unix socket, or a symlink made; or a file cut to size                                                                                                                                                                                                                                | `W`                                                          |
| `link`                                  | a hard link made from `path` to `to`. One across mounts, such as from `$HOME` into the workspace, fails (`EXDEV`). A refused one marks `to` refused, except on `EPERM`, which marks `path`, as `EPERM` mostly comes from `protected_hardlinks` refusing a file the step does not own and cannot both read and write | `W` on `to`, `L` on `path` unless it is `deleted` or `memfd` |
| `chmod`, `chown`, `attr`                | a mode, an owner, or times or extended attributes changed                                                                                                                                                                                                                                                           | `A`                                                          |
| `syscall`                               | a system call the sandbox's seccomp profile refused, once per program, unless recorded as a failed path change; or a 32-bit one seccomp killed the program for                                                                                                                                                      | `!` in the details                                           |
| `end`                                   | the last line; see below                                                                                                                                                                                                                                                                                            | none                                                         |

### Access letters

| On     | Letters                                                                                                           |
| ------ | ----------------------------------------------------------------------------------------------------------------- |
| `open` | `r`, `w` or `rw`, then `c` if it asked to create, `t` to truncate and, on one that succeeded, `x` to run the file |
| `mmap` | `r`, `w` for a shared writable mapping, or `x` for an executable one                                              |

### Error numbers

`err` is the Linux error number, the same on x86_64 and arm64 for those a step meets most:

| `err` | Name        | Usually                                                        |
| ----- | ----------- | -------------------------------------------------------------- |
| 1     | `EPERM`     | not permitted, such as changing a file the step does not own   |
| 2     | `ENOENT`    | no such file                                                   |
| 13    | `EACCES`    | permission denied by the file's mode                           |
| 17    | `EEXIST`    | already exists                                                 |
| 20    | `ENOTDIR`   | a path component is not a directory                            |
| 21    | `EISDIR`    | a directory where a file was expected                          |
| 30    | `EROFS`     | a read-only location, such as one the sandbox mounts read-only |
| 39    | `ENOTEMPTY` | a directory that is not empty                                  |

The summary marks 1, 13 and 30 with `!`.

### The end line

The last line is the end line, such as
`{"kind":"end","dropped":0,"untracked":0,"host_missed":0}`, written only after every access the
tracer caught:

- `dropped` counts accesses lost because the tracer's buffer was full.
- `untracked` counts calls it could not follow because too many files were open, or too many calls
  in progress, at once, and calls whose record it had to cut short or drop. An open whose call's
  return it never saw, as one still waiting when it stopped, counts here too, and is recorded as
  done. The tracer's tally in
  the step log ends with `tails-peak=<used>/<max>`: the most room for long paths it needed at once,
  out of the room it has.
- `host_missed` counts hooks the kernel skipped anywhere on the host while the step ran; see
  [Skipped hooks](#skipped-hooks).

## More about the summary

### How rows are grouped

**Which program.** A program is named as in the executed table, a script run through its `#!` line
by its own path; a script starting `#!/usr/bin/env node` runs `node` in turn, and what follows shows
under `node`. A process that forks without running anything counts as its parent's program, and the
step's own shell, which runs the `run` script, shows as `bash`. Running a program is left to the
executed table.

**Which path.**

- A program is shown under the file it ran, with symlinks followed.
- A failed access is shown under the name the command passed, joined to its working directory, or
  the directory it passed by descriptor, without resolving `..`. One made through a file descriptor
  alone, as `fchmod`, is shown under that file's path.
- A command reading or writing a file it inherited or was passed, such as a shell's redirection, is
  shown on its own row under that file's path.
- Reads and writes through a device such as `/dev/null` are recorded once for each time it is
  opened, under the first program to make them. A pipe or a socket is left out of the summary.

**Folding.** A `dir/**` row does not say which path under it was refused. The details fold each
command's paths on their own, so they often name it; the artifact always does.

Never folded into a `dir/**` row, nor counted toward its three rows:

- `/`, `/home`, `/tmp`, `/proc`, the workspace, `$HOME`, the directories above them, and
  `/proc/<pid>`.
- A program run, a path containing `..`, which may lead elsewhere through a symlink, and a memfd. A
  file a program loaded is not counted either.

That changes once a table or the details would pass 300 KB, more rows than anyone reads:

- Each of those directories folds once five entries directly under it are not themselves among
  them. Those that are keep rows of their own: `/` folds into `/**`, but `/home/runner` still shows
  its own rows.
- Paths with `..` fold once five share what comes before their first `..`, into a row such as
  `./a/../**`.
- Memfds fold once there are five, into `memfd:**`: five of one program's in the table, of one
  command's in the details.
- A program run still never folds.

**Quoting.** A command or path holding a space is quoted in the details, as `"VM Thread"`, except a
memfd's name, which is quoted already, and a refused system call.

### Other notations

| Shown as                     | Means                                                                                                             |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `…/name`                     | A relative name whose directory was closed before it could be read, or a path too deep to record in full          |
| `path…`                      | A failed open's name too long to record in full, cut at its end                                                   |
| `memfd:"name"`               | A file that exists only in memory and has no path; the name is whatever its creator chose                         |
| `path (deleted)`             | A file deleted while it was open, or created without a name and never given one; not shown inside a `dir/**` row  |
| `\n`, `\u{202e}`, `\"`, `\\` | A control, invisible or blank character, a space at either end, a quote or a backslash, in a path or command name |
| `\xff`                       | A byte that is not UTF-8 in a path or command name                                                                |

### Refused system calls

A refused system call is one the sandbox's seccomp profile does not allow, such as `io_uring_setup`
or `unshare`, which fails with `EPERM`. The note under the heading names the first 10, each with
the first commands that made it, and counts the rest; the details, where they fit, show each once
per program, as `syscall:io_uring_setup` with `!`.

- One already recorded as a failed change to a path is not repeated.
- One the profile allows only for some arguments, as `clone`, is not recorded even when refused,
  since the kernel's own `EPERM` for it would read the same.
- A program killed for a 32-bit system call shows as `syscall:32-bit <name> (killed)`; a thread
  killed while others run on is not recorded.
- Past 200 command and system call pairs, the details add a row only for each system call's first
  refusal that did not kill the command, and for every kill; the artifact, if uploaded, has the
  rest.

### What the summary leaves out

The summary leaves out what any program does just to start: the shared libraries it loads, its
reads of them and of `/etc/ld.so.cache`, and its own reads of the program file. Another program
reading those files is shown. A file counts as a library when the kernel loads it to start a
program, or when it is mapped to run and its name ends in `.so`, `.so` with a version such as
`.so.1.2.3`, or `.node`, and it is neither in memory only nor deleted. A `.so` file only read, as a
packaging tool reads it, is shown.

A directory's own row is left out when every flag on it shows on a row below it too and none of it
was refused: after `mkdir dist` and a write to `dist/app.js`, only `./dist/app.js` shows. Such a
row does not count toward a fold either.

A regular file or directory kept open counts only the first read and the first write through it by
each program, so the last time in the details can be earlier than its last write. Through a device,
only the first read and the first write after each open count, whichever program makes them.

## What it does not record

- A call that only looks a file up or reads its metadata: `stat`, `access`, `readlink`,
  `getxattr`, `listxattr`, and a successful open that only obtains a handle (`O_PATH`). What a
  command then does through such a handle, such as running or reopening the file, is recorded, and
  a failed `O_PATH` open is recorded as a failed read.
- Work handed to a process outside the sandbox, such as an `ssh-agent` or `gpg-agent` reached over a
  socket.
- An inode flag change through `ioctl`, as `chattr` makes, an extended attribute change other than
  through `setxattr`, `lsetxattr` or `fsetxattr`, a failed `exec`, a `mkdir`, `mknod`, `symlink` or
  `link` on a name already there, and one made by `bind(2)` that the kernel refuses before reaching
  its file.
- The sandbox's own setup, and the step's shell reading its script.
- The kernel writing a core dump when a process crashes, where `core_pattern` names a path: the file
  is created and written by the kernel, not through a system call, so neither is recorded. Reading
  that file afterwards is. GitHub-hosted runners pipe core dumps to a handler, which does not write
  a file here.

io_uring is not among them: the sandbox refuses `io_uring_setup`, so no access goes through it, and
the refusal is recorded as a `syscall`.

[Filesystem audit](./security.md#filesystem-audit) in the security details covers what the step
itself can do to the record, and what the record can be trusted for.

## Limits

- **Job Summary size.** When the traffic report and this section would pass GitHub's 1 MiB cap, the
  process details give way first, and this section's tables after the traffic report's timeline;
  [The Job Summary size cap](../README.md#the-job-summary-size-cap) has the full order. A part that
  does not fit is cut at a line, with a note after what is kept, or replaced by the note when none
  of it fits. The note names the artifact, which still holds every access, or says how to ask for
  one, or, when the upload failed, that the record was not kept.
- **One part too large.** The accessed-paths table or the details that alone would pass 300 KB folds
  the directories, `..` paths and memfds it otherwise keeps on rows of their own (see
  [How rows are grouped](#how-rows-are-grouped)). One that would pass 1 MiB even so keeps the rows
  that fit in it, takes no new ones, and ends with a note; the Job Summary's cap then decides how
  much of it prints. It is left out whole, under a note that says why, when not one row fits, or
  once its folded tree holds more than 200,000 files and directories, counting every directory on
  the way and each program's tree apart in the table, each command's in the details. When the table
  is left out, the details go with it.

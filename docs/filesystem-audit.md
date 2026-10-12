# Filesystem audit

> [!WARNING]
> `filesystem_audit` is **experimental**: its behavior, inputs, and output format may still change
> in a future release without following semver. Try it in a non-critical workflow first, and pin
> this action to a commit SHA rather than a version tag if you adopt it.

`filesystem_audit: record` records every file the isolated step reads, writes, moves,
deletes, changes the attributes of, and executes. It adds a section to the Job Summary and, with
`upload_filesystem_audit_artifact: true`, uploads the full record as an artifact. It watches from
the kernel, so a static binary or a tool that bypasses libc is seen like any other. It works the
same whatever `proxy_mode` and `proxy_engine` are set to.

It records and never blocks an access: what the step may write is decided by
[`filesystem_mode` and `write_through`](../README.md#filesystem-access). Turning it on still
changes two things, covered in [Does it fit your step?](#does-it-fit-your-step): a 32-bit system
call kills the thread that made it, and every system call on the runner host gets slightly slower
while the step runs.

## What it is for

- **Finding what `write_through` needs.** Under `filesystem_mode: ephemeral` every write is thrown
  away when the step ends, except under the paths `write_through` names. The audit shows where the
  step wrote, so you can name only what a later step needs:

  1. Run the step with `filesystem_mode: ephemeral` and `filesystem_audit: record`, and in
     `write_through` only what you already know a later step reads, such as `$GITHUB_OUTPUT` if the
     step sets outputs.
  2. Look at the `W`, `D` and `A` rows under **Accessed paths**, and at the `M` rows. `M` marks
     only the path a file was moved away from, so a file a tool writes under a temporary name and
     then renames into place shows under the temporary name; the artifact has where it went, as
     `to` on its `rename` line.
  3. Add what a later step reads, usually the build output, to `write_through`, and run again. The
     rest is what ephemeral discards on purpose.

  A build that sets outputs and writes `./dist` ends up with:

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
  which command, and the artifact, if uploaded, says when and from which process.
- **Seeing what an install ran.** The executed table lists every program the step started, so a
  `postinstall` script that runs `curl` or a binary it just downloaded shows up there.
- **Seeing what was refused.** A flag followed by `!`, such as `w!`, is an access the sandbox, a
  file's permissions or a read-only location refused, such as a write to `/usr/local/bin`, which
  the sandbox makes read-only, or a read of `/etc/shadow`.

## Does it fit your step?

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
  kernel kills the thread that made it with `SIGSYS`. A single-threaded program dies, and a shell
  reports it as `Bad system call`. Run such a program in a step without the audit.
- **Cost to the whole host.** While the step runs, the tracer's hooks run on every system call and
  every file read or write on the runner host, not only the step's, since a hook has to run to tell
  whose call it is. That adds roughly 100 nanoseconds to each system call of every process on the
  machine, the proxy, Docker and other jobs on a shared runner included. Copying a file a byte at a
  time outside the step took nearly twice as long in a test, while a typical build, which spends
  little of its time in system calls, barely changes. Inside the step, each program's first read or
  write of a file is also recorded, which costs more.

## Getting started

```yaml
- uses: buildcage/isolated-run@<sha>
  with:
    filesystem_audit: record
    run: npm ci
```

The step's Job Summary gets a **Filesystem audit** section after the traffic report. The full
record, with every access in order, is uploaded only when asked for, as the traffic artifact is:

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

Each step with the audit on gets its own section and its own artifact,
`buildcage-filesystem-audit-<id>`, where `<id>` is the same random suffix as that step's traffic
artifact, so several steps in one job never collide. Each section follows its step's traffic
report, whose heading carries the step's `label`, so set `label` to tell the steps apart.

`filesystem_audit_retention_days` sets how long the artifact is kept; empty uses the repository's
default, and a value above the repository's maximum is lowered to it, with a warning. A value that
is not a whole number above zero fails the step even when nothing is uploaded. The artifact names
each program the step ran but not its arguments, which can carry secrets. It still holds every path
the step touched, including the names of files it only tried to open, so treat it as sensitive,
like the traffic artifact.

## Reading the summary

```
### 🗂️ Filesystem audit
./ workspace · ~/ $HOME · dir/** a folded directory · the full record is in the
buildcage-filesystem-audit-<id> artifact · how to read this

#### Executed
| Path                  | Runs |
| --------------------- | ---- |
| `/usr/local/bin/node` | 1    |
| `/usr/bin/dash`       | 12   |

#### Accessed paths
R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = denied
| Access | Path                  |
| ------ | --------------------- |
| RWD    | `./node_modules/**`   |
| R      | `./package.json`      |
| Rr!    | `/etc/**`             |
| w!     | `/usr/local/bin/node` |

📂 Filesystem details
first-last access since the proxy started · flags · command · path
00:00.401-00:00.420: Xw! node /usr/local/bin/node
00:00.412:           R   node ./package.json
00:00.415-00:00.418: Rr! node /etc/**
00:00.530-00:41.207: RWD node ./node_modules/**
00:00.531-00:40.982: X   sh   /usr/bin/dash
```

Where there is no artifact, the line under the heading says how to ask for one, or that the upload
failed. A step that touched no file shows `No file access was recorded.` instead of the tables. One
that only ran programs has no accessed paths table, and the flag legend opens the details instead.

- **Executed** lists each program once, in the order it first ran, with how many times it ran.
- **Accessed paths** combines every command's actions on a path in one row, in path order: the
  workspace first, then `$HOME`, then the rest. Running a program is left to the executed table.
  A `dir/**` row does not say which path under it was refused. The details fold each command's
  paths on their own, so they often name it; the artifact always does.
- **📂 Filesystem details**, folded, has one row per command and path, in the order the rows were
  first touched. The command is the name the process gave itself, as `ps` shows it. The time is when
  that command first and last touched the path, counted from the proxy's start like the
  communication details, or from the first access if that start is unknown.

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

A refusal shows even where the same action also succeeded, after the uppercase letters: `RWr!` on
`/etc/**` means reads and writes under `/etc` succeeded and at least one read was refused. A failed
open shows what it asked for: `w` to write, create or truncate, `r` to read, and both for one opened
to read and write, as bash does `/dev/tty`. A swap of two paths (`renameat2` with
`RENAME_EXCHANGE`) shows `M` on both. A row's flags do not say which action came first; the
artifact has every access in order.

### Paths

| Shown as               | Means                                                                                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `./…`                  | Under `$GITHUB_WORKSPACE`                                                                                                                                        |
| `~/…`                  | Under `$HOME`                                                                                                                                                    |
| `dir/**`               | `dir` and the entries touched directly under it would take three or more rows, so they are shown as one with the flags of everything at and under `dir` combined |
| `/proc/<pid>/…`        | Under a process's own directory in `/proc`, every process's shown as one                                                                                         |
| `…/name`               | A relative name whose directory was closed before it could be read, or a path too deep to record in full                                                         |
| `memfd:"name"`         | A file that exists only in memory and has no path; the name is whatever its creator chose                                                                        |
| `path (deleted)`       | A file deleted while it was open, or created without a name and never given one; not shown inside a `dir/**` row                                                 |
| `\n`, `\u{202e}`, `\\` | A control or invisible character, or a backslash, in a path or command name                                                                                      |
| `\xff`                 | A byte that is not UTF-8 in a path or command name                                                                                                               |

Never folded into a `dir/**` row, nor counted toward its three rows:

- `/`, `/home`, `/tmp`, `/proc`, the workspace, `$HOME`, the directories above them, and
  `/proc/<pid>`.
- A program run, a path containing `..`, which may lead elsewhere through a symlink, and a memfd. A
  file a program loaded is not counted either.

Which path a row is shown under:

- A program is shown under the file it ran, with symlinks followed, and a script under its own path
  rather than its interpreter's.
- A failed access is shown under the name the command passed, joined to its working directory, or
  the directory it passed by descriptor, without resolving `..`.
- A command reading or writing a file it inherited or was passed, such as a shell's redirection, is
  shown on its own row under that file's path.
- Reads and writes through a device such as `/dev/null` are recorded once for each time it is
  opened, under the first program to make them. A pipe or a socket is left out of the summary.

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
jq -c 'select(.path // "" | endswith("/.npmrc")) | {t, comm, pid, kind}' filesystem-audit-*.jsonl

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
| `path`     | all but `fork`, `end`                          | the file acted on; on `rename` and `link` the old name; absent, with `err`, when it could not be read. See below for when it is not an absolute path |
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

A field is absent where it does not apply, and `failed`, `image`, `memfd`, `deleted` and `exchange`
are absent rather than `false`.

`path` is absolute except for a file in memory only (`memfd:…`), a pipe, socket or other file the
kernel names without a path (such as `pipe:[1234]`), a path too deep to record in full (`…/…`), and
the relative name of a failed call or an attribute change whose directory could not be read.

A byte of a name that is not UTF-8 is written as a lone surrogate, `\udcff` for the byte `0xff`, as
Python's `surrogateescape` does, so `os.fsencode` gives back the name's exact bytes. jq prints it as
`�`; the summary shows it as `\xff`.

### Kinds

A failed operation keeps the kind it would have had, with `"failed":true` and `err`, and shows its
letter lowercase in the summary. A failed `open`, `unlink`, `rmdir` or `rename`, and a failed
`chmod`, `chown`, `attr` or `truncate` on a path, is recorded however it failed; through a file
descriptor, as `fchmod` or `ftruncate` do, only if the kernel refused it after checking the file. A
failed `mkdir`, `mknod`, `symlink` or `link` is recorded too unless its name was already there
(`EEXIST`), which changed nothing and which `mkdir -p` meets at every level it keeps. A failed
`mmap` is not recorded, nor is a failed `exec`, though the file it opened before failing can show
as an `open` with `x`.

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
  in progress, at once, and calls whose record it had to cut short or drop. The tracer's tally in the step log ends with `tails-peak=<used>/<max>`: the
  most room for long paths it needed at once, out of the room it has.
- `host_missed` counts hooks the kernel skipped anywhere on the host while the step ran; see
  [Skipped hooks](#skipped-hooks).

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

- **This record is incomplete.** `dropped` or `untracked` is nonzero, or the tracer did not stop
  cleanly. Some accesses are missing from both the summary and the artifact. A step that touches a
  very large number of files at once can cause it.
- **The kernel skipped the tracer's hooks N times.** `host_missed` is nonzero, so some accesses may
  be missing; see [Skipped hooks](#skipped-hooks).
- **The recording could not be read.** The summary has none of the step's accesses, a warning is
  logged, and no artifact is uploaded.
- **The same note, with an error and a failed step, in any mode.** The recording was removed after
  the tracer started, by a process on the runner host outside the sandbox.
- **No section, and a `Failed to render the filesystem audit summary` warning.** The recording was
  read but its summary could not be written; the artifact is still uploaded if asked for. Please
  [open an issue](https://github.com/buildcage/isolated-run/issues) with the warning.

A program in the step that dies with `Bad system call` made a 32-bit system call, which the audit
refuses; see [What changes in the step](#what-changes-in-the-step).

### Skipped hooks

On some kernels one of the tracer's hooks can be paused mid-run, and is then skipped when it is
entered again. The kernels on GitHub-hosted runners do not pause the hooks, nor do Ubuntu 22.04's
and 24.04's `generic` kernels as they boot by default; Ubuntu 26.04's, and the 7.0 hardware
enablement kernel of 24.04, do. On a self-hosted runner, `sudo cat /sys/kernel/debug/sched/preempt`
prints the modes with the one in use in parentheses, such as `full (lazy)`, and hooks can be skipped
when it is `(full)` or `(lazy)`. That file needs debugfs mounted at `/sys/kernel/debug`. Where it is
missing even so, the kernel cannot switch modes, and hooks can be skipped when
`/boot/config-$(uname -r)` sets `CONFIG_PREEMPT_RCU=y`.

`host_missed` counts skips anywhere on the host while the step ran, so 0 means none of the step's
accesses was skipped. A nonzero count opens the summary with a note that some accesses may be
missing; a skip cannot be tied to the step, so the note cannot say they are. For a complete record,
use a kernel that does not pause the hooks, such as one booted with `preempt=voluntary` where the
kernel offers that mode.

## What it does not record

- A call that only looks a file up or reads its metadata: `stat`, `access`, `readlink`,
  `getxattr`, `listxattr`, and a successful open that only obtains a handle (`O_PATH`). What a
  command then does through such a handle, such as running or reopening the file, is recorded, and
  a failed `O_PATH` open is recorded as a failed read.
- Work handed to a process outside the sandbox, such as an `ssh-agent` or `gpg-agent` reached over a
  socket.
- An inode flag change through `ioctl`, as `chattr` makes, an extended attribute change other than
  through `setxattr` or `lsetxattr`, a failed `exec`, a `mkdir`, `mknod`, `symlink` or `link` on a
  name already there, and one made by `bind(2)` that the kernel refuses before reaching its file.
- The sandbox's own setup, and the step's shell reading its script.

io_uring is not among them: the sandbox refuses `io_uring_setup`, so no access goes through it.

[Filesystem audit](./security.md#filesystem-audit) in the security details covers what the step
itself can do to the record, and what the record can be trusted for.

## Limits

- **Job Summary size.** When the traffic report and this section would pass GitHub's 1 MiB cap,
  the filesystem details give way first and this section's tables after the traffic report's
  communication log; [The Job Summary size cap](../README.md#the-job-summary-size-cap) has the full
  order. A part that does not fit is cut at a line, with a note after what is kept, or replaced by
  the note when none of it fits. The note names the artifact, which still holds every access, or
  says how to ask for one, or that the record was not kept when the upload failed.
- **One part too large.** The accessed-paths table or the details is left out whole, under a note
  that says why, when it alone would pass 1 MiB, or once its folded tree holds more than 200,000
  files and directories, every directory on the way counted, and each command's counted apart in
  the details. When the table is left out, the details go with it.

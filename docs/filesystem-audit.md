# Filesystem audit

> [!WARNING]
> `filesystem_audit` is **experimental**: its behavior, inputs, and output format may still change
> in a future release without following semver. Try it in a non-critical workflow first, and pin
> this action to a commit SHA rather than a version tag if you adopt it.

`filesystem_audit: record` records every file the isolated step reads, writes, moves,
deletes, changes the attributes of, and executes. It adds a section to the Job Summary and, with
`upload_filesystem_audit_artifact: true`, uploads the full record as an artifact. It watches from
the kernel, so a static binary or a tool that bypasses libc is seen like any other, and it only
records: it never blocks an access. What the step may write is decided by
[`filesystem_mode` and `write_through`](../README.md#filesystem-access).

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
  which command, and the artifact, if uploaded, says when and from which process.
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
  uses: actions/download-artifact@v5
  with:
    name: ${{ steps.build.outputs.filesystem_audit_artifact_name }}
```

The `filesystem_audit_artifact_name` output names the uploaded artifact. It is empty when nothing
was uploaded, and without the `if:`, `download-artifact` would then download every artifact of the
run.

`filesystem_audit_retention_days` sets how long the artifact is kept; empty uses the repository's
default, and a value above the repository's maximum is lowered to it, with a warning. The value is
checked even when nothing is uploaded. The artifact names each program the step ran but not its
arguments, which can carry secrets. It still holds every path the step touched, including the names
of files it only tried to open, so treat it as sensitive, like the traffic artifact.

## Reading the summary

```
### Filesystem audit
R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied
./ workspace · ~/ $HOME · dir/** a folded directory · the full record is in the
buildcage-filesystem-audit-<id> artifact · how to read this

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
| w!     | `/usr/local/bin/node` |

📂 Filesystem details
first-last access since the proxy started · flags · command · path
00:00.412:           R   node ./package.json
00:00.415-00:00.418: Rr! node /etc/**
00:00.420:           w!  node /usr/local/bin/node
00:00.530-00:41.207: RWD node ./node_modules/**
```

Where there is no artifact, the legend says how to ask for one, or that the upload failed.

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
open shows what it asked for: `w` to write, create or truncate, `r` to read, and both for one opened
to read and write, as bash does `/dev/tty`. A row's flags do not say which action came first; the
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
| `\xff`                 | A byte that is not UTF-8 in a path or command name                                                               |

`/`, `/home`, `/tmp`, `/proc`, the workspace, `$HOME` and the directories above them are never
folded into a `dir/**` row, nor is `/proc/<pid>`, which stands for any process's own directory.

A program is shown under the file it ran, with symlinks followed, and a script under its own path
rather than its interpreter's. A failed access is shown under the name the command passed, joined to
its working directory, or the directory it passed by descriptor, without resolving `..`. A command
reading or writing through a file it inherited or was passed is shown under its own name, except for
a pipe, a socket or a device such as `/dev/null`, which counts once.

### What the summary leaves out

The summary leaves out what any program does just to start: the shared libraries it loads, its
reads of them and of `/etc/ld.so.cache`, and its own reads of the program file. Another program
reading those files is shown. A file counts as a library when the kernel loads it to start a
program, or when its name ends in `.so`, `.so.<version>` or `.node` and it is neither in memory only
nor deleted.

A file kept open counts only the first read and the first write through it by each program, so the
last time in the details can be earlier than its last write.

## The artifact

With `upload_filesystem_audit_artifact: true`, the artifact named `buildcage-filesystem-audit-<id>`
holds one file,
`filesystem-audit-<id>.step.jsonl`: one JSON object per line, in the order the accesses happened,
with absolute paths. It holds only the step's own accesses, as the summary does: the sandbox's setup
is left out, and the step's shell is named `bash`. A record marked incomplete can hold the setup too.
A few examples:

```sh
# Every path the summary shows as written
jq -r 'select((.failed | not) and ((.kind | IN("write", "mkdir", "mknod", "symlink", "link", "truncate"))
  or (.kind == "open" and (.access // "" | test("[ct]")))))
  | if .kind == "link" then .to else .path end' filesystem-audit-*.jsonl | sort -u

# Who opened a credential file, and when
jq -c 'select(.path // "" | endswith("/.npmrc")) | {t, comm, pid, kind}' filesystem-audit-*.jsonl

# Every refused open
jq -c 'select(.kind == "open" and .failed and (.err == 1 or .err == 13 or .err == 30))' filesystem-audit-*.jsonl
```

### Fields

| Field      | On                          | Notes                                                                                                                                                  |
| ---------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `t`        | every line but `end`        | ISO 8601 UTC, to the millisecond                                                                                                                       |
| `kind`     | every line                  | what happened; see [Kinds](#kinds)                                                                                                                     |
| `pid`      | every line but `end`        | the process, as the runner host numbers it                                                                                                             |
| `ppid`     | every line but `end`        | its parent at the time; on `fork`, the process that made it                                                                                            |
| `comm`     | every line but `end`        | the name the process gave itself, up to 15 bytes                                                                                                       |
| `path`     | all but `fork`, `end`       | the file acted on; on `rename` and `link` the old name; absent, with `err`, when it could not be read                                                  |
| `to`       | `rename`, `link`, `symlink` | the new name; on `symlink`, the link's contents as written                                                                                             |
| `name`     |                             | the name the command passed, where `path` differs from it; on `exec`, the name it was run by                                                           |
| `to_name`  |                             | as `name`, for `to`                                                                                                                                    |
| `access`   | `open`, `mmap`              | what was asked for; see [Access letters](#access-letters)                                                                                              |
| `flags`    | `open`                      | the `open(2)` flags as a number; absent when 0, as for a plain read-only open                                                                          |
| `mode`     | `chmod`                     | the new mode in octal, such as `"0755"`; absent on most failed ones                                                                                    |
| `owner`    | `chown`                     | the new `uid:gid`; absent on most failed ones                                                                                                          |
| `failed`   |                             | `true` when the operation failed                                                                                                                       |
| `err`      |                             | on a failed one, the error number; see [Error numbers](#error-numbers). Without `failed`, a negative number: why an open file's path could not be read |
| `image`    |                             | on `mmap`, a file the kernel mapped to start a program: the program, its loader or a script's interpreter                                              |
| `memfd`    |                             | a file that exists only in memory; `path` is `memfd:` and the name its creator chose                                                                   |
| `deleted`  |                             | a file deleted while it was open, or created without a name and never given one                                                                        |
| `exchange` |                             | on `rename`, a swap of two paths, which shows `M` on both in the summary                                                                               |

A field is absent where it does not apply, and `failed`, `image`, `memfd`, `deleted` and `exchange`
are absent rather than `false`.

A byte of a name that is not UTF-8 is written as a lone surrogate, `\udcff` for the byte `0xff`, as
Python's `surrogateescape` does, so `os.fsencode` gives back the name's exact bytes. jq prints it as
`�`; the summary shows it as `\xff`.

### Kinds

A failed operation keeps the kind it would have had, with `"failed":true` and `err`, and shows its
letter lowercase in the summary. A failed `open`, `unlink`, `rmdir`, `rename`, `chmod`, `chown` or
`attr` is recorded however it failed; a `mkdir`, `mknod`, `symlink`, `link` or `truncate` only when
the kernel refused it after reaching its file, and a failed `exec` not at all.

| `kind`                                          | Records                                                                                          | Summary                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| `open`                                          | a file opened; the summary counts one that creates or truncates, or that failed                  | `W`, `r`, `w`                             |
| `read`, `write`                                 | the first read, or the first write, through each opened file by each program a process runs      | `R`, `W`                                  |
| `mmap`                                          | a file mapped into memory                                                                        | `R`, or `W` for a shared writable mapping |
| `exec`                                          | a program run                                                                                    | `X`                                       |
| `fork`                                          | a new process; `pid` is the child                                                                | none                                      |
| `unlink`, `rmdir`                               | a file or a directory deleted                                                                    | `D`                                       |
| `rename`                                        | a move from `path` to `to`                                                                       | `M`                                       |
| `mkdir`, `mknod`, `symlink`, `link`, `truncate` | a directory, a special file or Unix socket, a symlink or a hard link made, or a file cut to size | `W`                                       |
| `chmod`, `chown`, `attr`                        | a mode, an owner, or times or extended attributes changed                                        | `A`                                       |
| `end`                                           | the last line; see below                                                                         | none                                      |

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
  saying how to ask for one, or that the record was not kept when the upload failed.
- **Distinct paths.** The accessed-paths table or the details is left out the same way, under a
  note that says why, once its folded tree holds more than 200,000 files and directories, every
  directory on the way counted, and each command's counted apart in the details.

### Skipped hooks

The kernel can skip one of the tracer's hooks: those for failed operations while another BPF
program, such as a security or monitoring agent's, is running on the same CPU, and, on a kernel
built for full preemption, a hook entered again while it is paused mid-run. A stock Ubuntu kernel,
as on GitHub-hosted runners, does not pause the hooks. `host_missed` counts skips anywhere on the
host while the step ran, so 0 means none of the step's accesses was skipped. The summary does not
warn on a nonzero count, since a skip cannot be tied to the step. Before Linux 6.7 the kernel does
not count a skipped hook for failed operations.

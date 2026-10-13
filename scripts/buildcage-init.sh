#!/bin/bash
# Applies the step environment from stdin, then runs the script $2 as a child:
# forwards signals to it, reaps orphans, and exits with its status. $1 is the
# record that ends the environment. See src/lib/sandbox/env-loader.ts for the
# wire format.
#
# The records go to env(1) rather than being exported, so a step variable
# named like one of this script's, or like a bash readonly or dynamic variable
# (UID, SECONDS), arrives as set. No eval: each record is one argument, never
# re-interpreted, so a value containing $(...) or a backtick stays literal.
#
# Not #!/bin/sh: runners' /bin/sh is dash, which has no `read -d`. bash is
# guaranteed present, since the sandbox rootfs is the runner's own `/` and
# run-isolated.sh already runs there under it. Only builtins, and env (and
# sleep, in the fallback below) by their absolute paths, so the empty
# environment runc starts this with is enough. Short of that fallback, it
# starts no process once the step runs, so the filesystem audit sees nothing
# of it but its own accesses.
#
# Stays PID 1 so the command doesn't have to be: the kernel drops any signal
# PID 1 has no handler for and hands it every orphan, which a user's command
# (or python, node) neither handles nor reaps.
set -u
terminator=$1
script=$2

# Trapped before reading, as PID 1 drops untrapped signals. Any that arrive
# before the child exists are held for it. TERM and INT stop the step, so
# they go to everything the step started, a process it moved out of the
# child's group with setsid included; the rest go to that group, which holds
# the command the script runs.
child=
# As the sandbox's PID 1, -1 reaches every process in its pid namespace but
# itself; anywhere else, as in this script's own tests, it would reach every
# process the user owns, so it stops at the child's group.
stop_target=
[ "$$" = 1 ] && stop_target=-1
pending=
stopping=
forward() {
  if [ -n "$child" ]; then
    case "$1" in
      TERM | INT)
        stopping=1
        kill -s "$1" -- "${stop_target:--$child}" 2>/dev/null
        ;;
      *) kill -s "$1" -- "-$child" 2>/dev/null ;;
    esac
  else
    pending="$pending $1"
  fi
}
# shellcheck disable=SC2064 # Each trap names its own signal, so $sig expands now.
for sig in TERM INT HUP QUIT USR1 USR2; do trap "forward $sig" "$sig"; done

complete=
records=()
while IFS= read -r -d '' record; do
  if [ "$record" = "$terminator" ]; then
    complete=1
    break
  fi
  [[ $record =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
  records+=("$record")
done

if [ -z "$complete" ]; then
  echo "buildcage: the sandbox environment ended before its terminator; refusing to run" >&2
  exit 1
fi

# Never hand the run script the tail of this blob.
exec 0</dev/null

# A pipe this process holds both ends of, so `read -t` on it waits out its
# timeout: a pause that starts no process, unlike sleep(1). Opened before the
# step starts, so its one fork happens before then. Linux reopens the
# pipe through /dev/fd; where that fails, the wait falls back to sleep(1).
nap=
if ! { exec 9<> <(:); } 2>/dev/null; then
  nap=/usr/bin/sleep
  [ -x "$nap" ] || nap=/bin/sleep
fi

# Tells run-isolated.sh that the command is starting. The command never gets
# fd 3.
{ printf 1 >&3; } 2>/dev/null
exec 3>&-

# Job control puts the child in a process group of its own, and leaves SIGINT
# and SIGQUIT as they are rather than ignoring them in it. Held signals are
# raised from inside the child.
held=$pending
set -m
{
  for sig in $held; do kill -s "$sig" "$BASHPID"; done
  exec 9>&-
  # The script's path holds no "=" for env to read as a record.
  exec /usr/bin/env -i -- ${records[@]+"${records[@]}"} "$script"
} &
child=$!
set +m
# Signals that arrived during the fork.
for sig in ${pending#"$held"}; do forward "$sig"; done
# Keeps bash's "Killed" job notice out of the step's output. The child has its
# own stderr.
exec 2>/dev/null
# A trapped signal interrupts `wait` with 128+n; the final `wait` returns the
# child's own status, 128+n if a signal killed it, as runc reports for an init.
while kill -0 "$child" 2>/dev/null; do wait "$child"; done
wait "$child"
status=$?
# The script can exit on a SIGTERM or SIGINT while the command it ran is still
# winding down, and this process exiting would kill it. Anything that ignores
# the signal holds the step until it is killed from outside.
if [ -n "$stopping" ]; then
  while kill -0 -- "${stop_target:--$child}" 2>/dev/null; do
    if [ -n "$nap" ]; then "$nap" 0.1; else read -r -t 0.1 -u 9 _ || :; fi
  done
fi
exit $status

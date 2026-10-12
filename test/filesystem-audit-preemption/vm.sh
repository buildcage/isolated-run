#!/bin/sh
# Runs inside the VM as root: the tracer over a cgroup holding three processes
# pinned to one CPU, each making its own kind of change, while the host is
# loaded. $1 holds the tracer and these scripts.
set -eux
dir=$1
uname -rv
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
cat /sys/kernel/debug/sched/preempt || true

work=/tmp/w
mkdir -p "$work"
for role in opener maker misser; do cp "$(readlink -f /usr/bin/python3)" "$work/$role"; done
cg=/sys/fs/cgroup/fsprobe

"$dir/filesystem-audit" --cgroup "$cg" --out /tmp/rec.jsonl --ready /tmp/ready 2>/tmp/tracer.err &
tracer=$!
i=0
until [ -e /tmp/ready ]; do
	i=$((i + 1))
	if [ "$i" -gt 300 ]; then cat /tmp/tracer.err; exit 1; fi
	sleep 0.1
done

for i in $(seq 16); do timeout 40 python3 -c 'while 1: open("/etc/hostname").close()' & done

pids=
for job in "opener open" "maker mkdir" "misser missing"; do
	set -- $job
	sh -c "echo \$\$ > $cg/cgroup.procs; exec taskset -c 0 $work/$1 $dir/work.py $2 $work 30" &
	pids="$pids $!"
done
wait $pids
sleep 12
kill -TERM "$tracer"
wait "$tracer"
tail -3 /tmp/tracer.err
python3 "$dir/check.py" /tmp/rec.jsonl

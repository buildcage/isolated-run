#!/usr/bin/env bash
# Runs each workload under main's tracer, this branch's, and none, a few times
# in turn, keeping each run's tracer log and workload output in results/.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out=$root/out
res=$root/results
mkdir -p "$res"
sudo sysctl -qw kernel.bpf_stats_enabled=1
# A working directory as deep as a checkout's, which a failed open's base walks.
work=$RUNNER_TEMP/home/runner/work/isolated-run/isolated-run/node_modules/.pnpm/pkg@1.0.0/node_modules/pkg
mkdir -p "$work"
"$out/stress" -mode prep -dir "$work"
npmdir=$RUNNER_TEMP/npm
mkdir -p "$npmdir"
cp test/filesystem-audit/package.json test/filesystem-audit/package-lock.json "$npmdir/"
sudo chown -R root "$work" "$npmdir"
# Warms root's npm cache, so the runs below are offline.
sudo sh -c "cd '$npmdir' && npm ci --ignore-scripts --no-audit --no-fund >/dev/null"
[ -x /usr/bin/time ] || sudo apt-get install -qy time >/dev/null

run() { # bin label rep cmd...
	local bin=$1 label=$2 rep=$3
	shift 3
	local id=$label.$bin.$rep cg=/sys/fs/cgroup/bench-$RANDOM
	local ready=$res/$id.ready pidf=$res/$id.pid
	local tp=
	if [ "$bin" != none ]; then
		sudo BENCH_PROFILE="${profile:+$res/$id.pprof}" /usr/bin/time -f "bench: cpu user=%U sys=%S" "$out/$bin" --cgroup "$cg" --out "$res/$id.jsonl" \
			--ready "$ready" --pidfile "$pidf" 2>"$res/$id.log" &
		tp=$!
		for _ in $(seq 300); do [ -e "$ready" ] && break; sleep 0.1; done
		[ -e "$ready" ] || { cat "$res/$id.log"; exit 1; }
	else
		sudo mkdir "$cg"
	fi
	local start end
	start=$(date +%s%N)
	sudo sh -c 'echo $$ > "$1/cgroup.procs"; shift; cd "$1"; shift; exec "$@"' sh "$cg" "$work" "$@" >"$res/$id.wl" 2>&1
	end=$(date +%s%N)
	echo "bench: wall_ms=$(((end - start) / 1000000))" >>"$res/$id.wl"
	if [ -n "$tp" ]; then
		sudo kill -INT "$(cat "$pidf")"
		wait "$tp" || true
		sudo rm -f "$res/$id.jsonl"
	else
		sudo rmdir "$cg"
	fi
	echo "$id: $(grep -h 'stress:\|wall_ms' "$res/$id.wl" | tr '\n' ' ') $(grep -h 'total=' "$res/$id.log" 2>/dev/null || true)"
}

if [ "${BENCH_MODE:-}" = profile ]; then
	profile=1
	sudo apt-get install -qy "linux-tools-$(uname -r)" >/dev/null 2>&1 || sudo apt-get install -qy linux-tools-generic >/dev/null 2>&1 || true
	perf=$(ls /usr/lib/linux-tools/*/perf 2>/dev/null | head -1)
	for w in open fail ops; do
		run none $w-w4 1 "$out/stress" -mode $w -workers 4 -dur 5s -dir "$work"
		run pr $w-w4 1 "$out/stress" -mode $w -workers 4 -dur 5s -dir "$work"
		if [ -n "$perf" ]; then
			# The whole system while the tracer runs, kernel and BPF included.
			sudo "$perf" record -q -a -g -o "$res/$w.perf" -- bash -c "$(declare -f run); out='$out' res='$res' work='$work' profile= run pr $w-w4 2 '$out/stress' -mode $w -workers 4 -dur 5s -dir '$work'" >/dev/null 2>&1 || true
		fi
	done
	run pr npm-ci 1 sh -c "cd '$npmdir' && rm -rf node_modules && npm ci --ignore-scripts --no-audit --no-fund --offline"
	for f in "$res"/*.pprof; do
		echo "::group::$(basename "$f")"
		grep -h "gc=\|cpu user" "${f%.pprof}.log" || true
		grep -h "prog=" "${f%.pprof}.log" | sort -t= -k4 -n -r | head -15 || true
		go tool pprof -top -nodecount 30 "$f" 2>/dev/null
		go tool pprof -top -cum -nodecount 30 "$f" 2>/dev/null
		echo "::endgroup::"
	done
	for f in "$res"/*.perf; do
		[ -e "$f" ] || continue
		echo "::group::$(basename "$f")"
		sudo "$perf" report -i "$f" --no-children --sort comm,dso,sym --stdio 2>/dev/null | grep -v '^#' | grep '%' | head -60
		echo "::endgroup::"
	done
	exit 0
fi
profile=
for rep in 1 2 3; do
	for bin in none main base pr; do
		for w in 1 4 16 64; do
			run $bin open-w$w $rep "$out/stress" -mode open -workers $w -dur 5s -dir "$work"
		done
		run $bin fail-w4 $rep "$out/stress" -mode fail -workers 4 -dur 5s -dir "$work"
		run $bin fail-w16 $rep "$out/stress" -mode fail -workers 16 -dur 5s -dir "$work"
		run $bin ops-w4 $rep "$out/stress" -mode ops -workers 4 -dur 5s -dir "$work"
		run $bin npm-ci $rep sh -c "cd '$npmdir' && rm -rf node_modules && npm ci --ignore-scripts --no-audit --no-fund --offline"
	done
done
python3 bench/summary.py "$res" | tee -a "$GITHUB_STEP_SUMMARY"

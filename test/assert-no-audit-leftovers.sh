#!/bin/bash
# Checks a finished filesystem audit step left no tracer and no sandbox cgroup
# behind. With --no-files, also no audit file, which a step that started its
# command leaves for the post step instead.
set -euo pipefail

if pgrep -x filesystem-audi; then
  echo "::error::the tracer outlived its step"
  exit 1
fi
cg="/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)"
if ls -d "$cg"/buildcage-proxy-* 2>/dev/null; then
  echo "::error::the sandbox's cgroup was left"
  exit 1
fi
if [ "${1:-}" = --no-files ] && ls -d "/var/tmp/buildcage-$(id -u)"/filesystem-audit-* 2>/dev/null; then
  echo "::error::the step left the audit's files"
  exit 1
fi

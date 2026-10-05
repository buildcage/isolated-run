#!/bin/sh
# Scenario for file-audit-poc.sh: one of each access kind the tracer records.
cat /etc/passwd >/dev/null
ls /run >/dev/null
cd /tmp
echo hi > poc-a.txt
mv poc-a.txt poc-b.txt
mkdir -p poc-dir && rmdir poc-dir
rm poc-b.txt
cat /proc/self/status >/dev/null
/bin/true --some-arg "with space"
cat /nonexistent 2>/dev/null || true
echo x > /tmp/poc-c.sh && chmod +x /tmp/poc-c.sh && ln -s /etc/shadow /tmp/poc-link && rm /tmp/poc-link /tmp/poc-c.sh

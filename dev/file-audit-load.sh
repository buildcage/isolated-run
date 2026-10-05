#!/bin/sh
# Load scenario for file-audit-poc.sh: many small-file creates, reads, an
# archive round trip and deletes, roughly what a dependency install does.
set -e
D=/tmp/poc-load
rm -rf $D && mkdir -p $D/src
i=0
while [ $i -lt 200 ]; do
  mkdir -p $D/src/d$i
  j=0
  while [ $j -lt 50 ]; do echo "file $i $j" > $D/src/d$i/f$j.js; j=$((j+1)); done
  i=$((i+1))
done
tar -C $D -czf $D/a.tgz src
mkdir $D/x && tar -C $D/x -xzf $D/a.tgz
find $D/x -type f -exec cat {} + > /dev/null
rm -rf $D

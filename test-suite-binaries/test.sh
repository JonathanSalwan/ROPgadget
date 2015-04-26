#!/bin/bash
FILES=`ls`
for f in $FILES
do
  if [ "$f" != "test.sh" ] && [ "$f" != "core" ]
  then
    python ../ROPgadget.py --depth 5 --binary $f 1>/dev/null
    echo "$f analyzed"
  fi
done

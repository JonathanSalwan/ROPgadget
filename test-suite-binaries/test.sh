#!/bin/bash
FILES=`ls`
for f in $FILES
do
  if [ "$f" != "test.sh" ]
  then
    python ../ROPgadget.py --binary $f 1>/dev/null
    echo "$f analyzed"
  fi
done

#!/usr/bin/env sh
# from https://wiki.alpinelinux.org/wiki/Finding_the_fastest_mirror

# this script will test all mirrors for response time

data=""
for s in $(wget -qO- http://rsync.alpinelinux.org/alpine/MIRRORS.txt); do
	t=$(command time -f "%E" wget --timeout=1 -q "$s/MIRRORS.txt" -O /dev/null 2>&1)
	echo "$s was $t"
	data="$data$t $s\n"
done

echo "===RESULTS==="

echo "$data" | sort

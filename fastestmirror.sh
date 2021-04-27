#!/usr/bin/env sh
set -eu
# from https://wiki.alpinelinux.org/wiki/Finding_the_fastest_mirror

data=""
for s in $(wget -qO- http://rsync.alpinelinux.org/alpine/MIRRORS.txt); do
	t=$(time -f "%E" wget -q $s/MIRRORS.txt -O /dev/null 2>&1)
	echo "$s was $t"
	data="$data$t $s\n"
done

echo "===RESULTS==="

echo -e $data | sort

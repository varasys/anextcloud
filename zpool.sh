#!/bin/sh
set -eu

POOL="${1:?missing pool name argument}"
shift
if [ $# -lt 1 ]; then
	printf "missing device argument(s)\n" >&2
	exit 1
fi

zpool create \
	-o ashift=12 \
	-o autotrim=on \
	-O acltype=posixacl \
	-O mountpoint=none \
	-O compression=on \
	-O dnodesize=auto \
	-O normalization=formD \
	-O relatime=on \
	-O xattr=sa \
	-O encryption=on \
	-O keylocation=prompt \
	-O keyformat=passphrase \
	"$POOL" \
	"$@"

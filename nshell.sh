#!/usr/bin/env sh
set -eu

# this is a simple script to determine the main PID
# for a running systemd-nspawn container and then change
# into that namespace (which is the equivelent of logging
# into the machine)

# for containers running systemd (in the container), the
# `machinectl shell ...` and `machinectl login ...`
# commands can be used instead, but this script is for
# containers that aren't running systemd

# Leader is the systemd-nspawn term for the main process
# of a systemd-nspawn container

if [ "$#" -eq 0 ]; then
	printf "error: missing arguments\n" >&2
	echo "usage: $0 machine [args]\n" >&2
	exit 1
fi

LEADER=$(machinectl show --property=Leader "$1")
shift
printf "entering namespace for %s ...\n" "$LEADER" >&2

if [ "$#" -eq 0 ]; then
	set -- /bin/sh -l
fi

exec nsenter -a -t "${LEADER##Leader=}" "$@"

#!/usr/bin/env sh
set -eu

# this is a simple script to determine the main PID
# for a running systemd-nspawn container and then change
# into that namespace (which is the equivelent of logging
# into the machine)

# Leader is the systemd-nspawn term for the main process
LEADER=$(machinectl show --property=Leader "$1")
shift
echo "entering namespace for $LEADER ..."

exec nsenter -a -t "${LEADER##Leader=}" "$@"

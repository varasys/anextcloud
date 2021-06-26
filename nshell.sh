#!/usr/bin/env sh
set -eu

# this is a simple script to determine the main PID
# for a running systemd-nspawn container and then change
# into that namespace (which is the equivelent of logging
# into the machine)

# for containers running systemd (in the container), the
# `machinectl shell ...` and `machinectl login ...`
# commands can be used instead, but this script is for
# containers that aren't running systemd in the container

# Leader is the systemd-nspawn term for the main process
# of a systemd-nspawn container

print_help() {
	cat >&2 <<-EOF
		$(basename "$0") - enter namespace of a running machinectl container

		usage: $0 machine [prog [args ...]]
		where:
		  'machine' is a complete or unique partial machine name
		    (use \`machinectl list\` to see running machines)
		  'prog' is a program to run in the machine (default = sh)
		  'args ...' are optional arguments to 'prog'

	EOF
}

if [ "$#" -eq 0 ]; then
	printf "error: missing arguments\n\n"
	print_help
	exit 1
fi

if echo "$1" | grep -q '^-\?-h'; then
	print_help
	exit 0
fi

MACHINES=$(machinectl --no-legend list | grep -o "^[^ ]*$1[^ ]*")
case "$(echo "$MACHINES" | wc -l)" in
	0)
		printf 'fatal error: failed to find machine "%s"' "$1"
		exit 1
		;;
	1)
		echo enter the machine
		LEADER=$(machinectl show --property=Leader "$MACHINES")
		PID="${LEADER##Leader=}"
		printf "entering namespace for %s (PID %s) ...\n" "$MACHINES" "$PID" >&2
		shift

		if [ "$#" -eq 0 ]; then
			set -- /bin/sh -l
		fi

		exec nsenter -a -t "$PID" "$@"
		exit 0
		;;
	*)
		printf "fatal error: failed to find unique name for \"%s\" in: \n%s\n" "$1" "$MACHINES"
		exit 1
		;;
esac

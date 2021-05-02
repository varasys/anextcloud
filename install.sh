#!/usr/bin/env sh
set -e # fail fast

# this script must be run as a file, it can't be piped via stdin for two reasons:
# 1) it will restart itself if not run as root, and
# 2) it pipes itself into the container, and then runs within the container to finish the configuration

# define colors - change to empty strings if you don't want colors
NC='\e[0m'
RED='\e[0;31m'
YELLOW='\e[0;33m'
BLUE='\e[0;34m'
PURPLE='\e[0;35m'

# define logging utility functions
log() {
	msg=$1; shift
	printf "%b$msg%b\n" "$BLUE" "$@" "$NC" >&2
}
warn() {
	msg=$1; shift
	printf "%b$msg%b\n" "$YELLOW" "$@" "$NC" >&2
}
error() {
	msg=$1; shift
	printf "%b$msg%b\n" "$RED" "$@" "$NC" >&2
}
prompt() { # does not include newline (so user input is on the same line)
	msg=$1; shift
	printf "%b$msg%b" "$PURPLE" "$@" "$NC" >&2
	IFS= read -r var
	printf "%s" "$var"
}

setup_host() {
	# this function is run in the host

	# restart as root if not root already
	if [ "$(id -u)" -ne "0" ]; then
		echo 'restarting as root ...' >&2
		exec "$0" "$@"
	fi

	if [ -n "$CONF" ]; then
		log 'using configuration file at: %s' "$CONF"
	elif [ -f "./conf.env" ]; then
		log 'using configuration file at: %s' './conf.env'
		CONF='./conf.env'
	else
		log 'CONF environment variable not set; using default config values'
	fi
	# shellcheck source=./conf.env # shellcheck directive needed here due to dynamic source in next line
	[ -n "$CONF" ] && . "$CONF"

	# print config variables to stdout for info
	cat <<-EOF
		# hostname of the container
		HOSTNAME='${HOSTNAME:="alpine"}'
		# domain of the container
		DOMAIN='${DOMAIN:="domain.local"}'
		# location of the container rootfs (on the host)
		TARGET='${TARGET:="/var/lib/machines/$HOSTNAME"}'
		# alpine linux mirror location
		MIRROR='${MIRROR:="https://dl-cdn.alpinelinux.org/alpine"}'
		# alpine linux stream
		VERSION='${VERSION:="latest-stable"}'
		# host machine achitecture
		ARCH='${ARCH:="$(arch)"}'
		# host network interface for MACVLAN
		IFACE='${IFACE:="eth0"}'
		# network interface prefix in the container
		IFACE_PREFIX='${IFACE_PREFIX:="mv-"}'
	EOF

	log "installing alpine linux ..."

	if [ ! -d "$TARGET" ]; then
		mkdir -p "$TARGET"
	elif [ "$(find "$TARGET" -maxdepth 1 ! -wholename "$TARGET" | wc -l)" -ne 0 ]; then
		warn "target directory is not empty"
		ls -lA "$TARGET" >&2
		[ ! "$(prompt "delete all files in '%s'? (y|n): " "$TARGET")" = "y" ] \
			&& error "aborted since target directory is not empty" \
			&& exit 1
		find "$TARGET" ! -wholename "$TARGET" -delete
	fi

	log "installing alpine linux to: $TARGET ..."
	apkdir="$(mktemp --tmpdir="$TARGET" --directory)"
	trap 'rm -rf "$apkdir"' EXIT
	log "using temp directory: '$apkdir'"

	APKTOOLS="$(curl -s -fL "$MIRROR/$VERSION/main/$ARCH" | grep -Eo 'apk-tools-static[^"]+\.apk' | head -n 1)"
	log "using: $MIRROR/$VERSION/main/$ARCH/$APKTOOLS"

	curl -s -fL "$MIRROR/$VERSION/main/$ARCH/$APKTOOLS" | tar -xz -C "$apkdir"

	mkdir -p "$apkdir/keys"
	cat > "$apkdir/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub" <<-EOF
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3v8/ye/V/t5xf4JiXLXa
		hWFRozsnmn3hobON20GdmkrzKzO/eUqPOKTpg2GtvBhK30fu5oY5uN2ORiv2Y2ht
		eLiZ9HVz3XP8Fm9frha60B7KNu66FO5P2o3i+E+DWTPqqPcCG6t4Znk2BypILcit
		wiPKTsgbBQR2qo/cO01eLLdt6oOzAaF94NH0656kvRewdo6HG4urbO46tCAizvCR
		CA7KGFMyad8WdKkTjxh8YLDLoOCtoZmXmQAiwfRe9pKXRH/XXGop8SYptLqyVVQ+
		tegOD9wRs2tOlgcLx4F/uMzHN7uoho6okBPiifRX+Pf38Vx+ozXh056tjmdZkCaV
		aQIDAQAB
		-----END PUBLIC KEY-----
	EOF

	"$apkdir/sbin/apk.static" \
		--keys-dir "$apkdir/keys" \
		--verbose \
		--progress \
		--root "$TARGET" \
		--arch "$ARCH" \
		--initdb \
		--repository "$MIRROR/$VERSION/main" \
		--update-cache \
		add alpine-base

	mkdir -p "/etc/systemd/nspawn"
	cat > "/etc/systemd/nspawn/$(basename "$TARGET").nspawn" <<-EOF
		[Exec]
		PrivateUsers=false

		[Network]
		VirtualEthernet=no
		MACVLAN=$IFACE
	EOF

	echo "$MIRROR/$VERSION/main" > "$TARGET/etc/apk/repositories"
	echo "$MIRROR/$VERSION/community" >> "$TARGET/etc/apk/repositories"

	cat > "$TARGET/etc/network/interfaces" <<-EOF
		auto lo
		iface lo inet loopback

		auto ${IFACE_PREFIX}${IFACE}
		iface ${IFACE_PREFIX}${IFACE} inet dhcp
	EOF

	for i in $(seq 0 10); do
		echo "pts/$i" >> "$TARGET/etc/securetty"
	done

	sed -i '/tty[0-9]:/ s/^/#/' "$TARGET/etc/inittab"
	echo 'console::respawn:/sbin/getty 38400 console' >> "$TARGET/etc/inittab"

	echo "$HOSTNAME" > "$TARGET/etc/hostname"
	echo "127.0.1.1	$HOSTNAME $HOSTNAME.$DOMAIN" >> "$TARGET/etc/hosts"

	cp "$0" "$TARGET/root/install.sh"

	systemd-nspawn \
		--directory="$TARGET" \
		--settings=false \
		--console=pipe \
		--setenv="SCRIPT_ENV=CONTAINER" \
		sh -s < "$0"

	log "finished"
}

setup_container() {
	# this function is meant to be run INSIDE the container (not the host)
	# it is run automatically at the end of the setup_host function
	echo 'in the container'

	rc-update add networking boot
	rc-update add bootmisc boot
	rc-update add hostname boot
	rc-update add syslog boot
	rc-update add killprocs shutdown
	rc-update add savecache shutdown

	apk add postgresql postgresql-contrib postgresql-openrc
	rm "/etc/conf.d/postgresql"
	export PGDATA='/var/lib/postgresql/data'
	su postgres -c initdb
	adduser -HDS nextcloud
	su postgres -c "pg_ctl -o '-k /tmp' start"
	su postgres -c psql <<-EOF
		CREATE USER nextcloud;
		CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
		ALTER DATABASE nextcloud OWNER TO nextcloud;
		GRANT ALL PRIVILEGES ON DATABASE nextcloud TO nextcloud;
	EOF
	su postgres -c 'pg_ctl stop'
	rc-update add postgresql

	log "finished installing nextcloud"
}

# When the script is run by the user the SCRIPT_ENV environment variable
# is not set, so the setup_host function will be run. The setup_host
# function will then copy this file into the container and run it via
# `systemd-nspawn` with the SCRIPT_ENV environment variable set to
# 'CONTAINER' which will cause the setup_container funtion to be run
# (inside the container).
case "${SCRIPT_ENV:='HOST'}" in
	CONTAINER)
		log "setting up the container\n"
		setup_container "$@";;
	*)
		log "setting up the host\n"
		setup_host "$@";;
esac

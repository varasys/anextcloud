#!/usr/bin/env sh
set -eu # fail fast

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

# this is the main entrypoint, and is called from the last line of this
# script after all required functions are defined
main() {
	case "$(basename "$0" ".sh")" in
		install_nextcloud)
			install_nextcloud
			;;
		*)
			install_alpine
			;;
	esac
}

case "$(basename "$0" ".sh")" in
	install)
		;;
	container)
		;;
	*)
		;;
esac

install_alpine() {
	# restart as root if not root already
	if [ "$(id -u)" -ne "0" ]; then
		echo 'restarting as root ...' >&2
		exec "$0" "$@"
	fi

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

	cat > "$TARGET/etc/network/interfaces" <<-EOF
		auto lo
		iface lo inet loopback

		auto ${IFACE_PREFIX}${IFACE}
		iface ${IFACE_PREFIX}${IFACE} inet dhcp
	EOF

	echo "$MIRROR/$VERSION/main" > "$TARGET/etc/apk/repositories"
	echo "$MIRROR/$VERSION/community" >> "$TARGET/etc/apk/repositories"

	for i in $(seq 0 10); do
		echo "pts/$i" >> "$TARGET/etc/securetty"
	done

	sed -i '/tty[0-9]:/ s/^/#/' "$TARGET/etc/inittab"
	echo 'console::respawn:/sbin/getty 38400 console' >> "$TARGET/etc/inittab"

	systemd-nspawn --directory="$TARGET" --settings=false --pipe sh -s <<-EOF
		apk add man-db apk-tools-doc
		rc-update add networking boot
		rc-update add bootmisc boot
		rc-update add hostname boot
		rc-update add syslog boot
		rc-update add killprocs shutdown
		rc-update add savecache shutdown
		echo "$HOSTNAME" > "/etc/hostname"
		echo "127.0.1.1	$HOSTNAME $HOSTNAME.$DOMAIN" >> "/etc/hosts"
	EOF

	log "finished installing alpine linux"
}

install_nextcloud() {
	log "installing nextcloud ..."
	systemd-nspawn --directory="$TARGET" --settings=false --pipe sh -s <<-EOF
		ln -s '/var/lib/postgresql/13/data' '/var/lib/postgresql/data'
		export PGDATA='/var/lib/postgresql/data'
		apk add postgresql postgresql-contrib postgresql-openrc
		su postgres -c initdb
		adduser -HDS nextcloud
		mkdir -p /run/postgresql
		chown postgres:postgres /run/postgresql
		su postgres -c 'pg_ctl start'
		su postgres -c psql <<-EOF2
			CREATE USER nextcloud;
			CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
			ALTER DATABASE nextcloud OWNER TO nextcloud;
			GRANT ALL PRIVILEGES ON DATABASE nextcloud TO nextcloud;
		EOF2
		su postgres -c 'pg_ctl stop'
		rc-update add postgresql
	EOF

	log "finished installing nextcloud"
}

# set the CONF variable with the location of the configuration file (if it exists)
if [ -n "${1-""}" ]; then # config file provided as command argument
	CONF="$1"
elif [ -n "${CONF-""}" ]; then # config file provided as environment variable
	: # NOOP 
elif [ -f "./conf.env" ]; then # config file exists in the default location
	log 'found config file in default location'
	CONF="./conf.env"
fi

# load variables from config file if the CONF environment variable is set
if [ -n "${CONF-""}" ]; then
	log "CONF='${CONF}'"
	# shellcheck source=./conf.env # shellcheck directive needed here due to dynamic source in next line
	. "$CONF"
else
	warn "no config file specified - using default config values"
fi

# print config variables to stdout for info
cat <<EOF
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

install_alpine
install_nextcloud


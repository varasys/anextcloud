#!/usr/bin/env sh
set -eu # fail fast

# restart as root if not root already
if [ "$(id -u)" -ne "0" ]; then
    echo 'restarting as root ...' >&2
    exec "$0" "$@"
fi

# define colors - change to empty strings if you don't want colors
NC='\e[0m'
RED='\e[0;31m'
YELLOW='\e[0;33m'
BLUE='\e[0;34m'
PURPLE='\e[0;35m'

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

install_alpine() {
    log "installing alpine linux ..."

    if [ ! -d "$TARGET" ]; then
        mkdir -p "$TARGET"
    elif [ "$(find "$TARGET" -maxdepth 1 ! -wholename "$TARGET" | wc -l)" -ne 0 ]; then
        warn "target directory is not empty"
        ls -lA "$TARGET" >&2

        [ ! "$(prompt "delete all files in '%s'? (y|n): " "$TARGET")" = "y" ] \
            && error "aborted since target directory is not empty" \
            && exit 1
        # printf "${PURPLE}delete all files in '%s'? (y|n): ${NC}" "$TARGET" >&2
        # IFS= read -r var
        # [ "$var" != "y" ] && error "aborted since target directory is not empty" && exit 1
        find "$TARGET" ! -wholename "$TARGET" -delete
    fi

    log "installing alpine linux to: $TARGET ..."
    apkdir="$(mktemp --tmpdir="$TARGET" --directory)"
    trap 'rm -rf "$apkdir"' EXIT
    log "using temp directory $apkdir"

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
    cat > "/etc/systemd/nspawn/${HOSTNAME}.nspawn" <<-EOF
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
    true
}

# set the CONF variable with the location of the configuration file (if it exists)
if [ -n "${1-""}" ]; then # config file provided as argument
    CONF="$1"
elif [ -n "${CONF-""}" ]; then # config file provided as environment variable
    : # NOP
elif [ -f "./conf.env" ]; then # config file exists in the default location
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

echo "# hostname of the container"
printf "HOSTNAME='%s'\n\n" "${HOSTNAME:="alpine"}"
echo "# domain of the container"
printf "DOMAIN='%s'\n\n" "${DOMAIN:="domain.local"}"
echo "# location of the container rootfs (on the host)"
printf "TARGET='%s'\n\n" "${TARGET:="/var/lib/machines/$HOSTNAME"}"
echo "# alpine linux mirror location"
printf "MIRROR='%s'\n\n" "${MIRROR:="https://dl-cdn.alpinelinux.org/alpine"}"
echo "# alpine linux stream"
printf "VERSION='%s'\n\n" "${VERSION:="latest-stable"}"
echo "# host machine achitecture"
printf "ARCH='%s'\n\n" "${ARCH:="$(arch)"}"
echo "# host machine network interface for MACVLAN"
printf "IFACE='%s'\n\n" "${IFACE:="eth0"}"
echo "# network interface prefix in the container"
printf "IFACE_PREFIX='%s'\n\n" "${IFACE_PREFIX:="mv-"}"

install_alpine
install_nextcloud


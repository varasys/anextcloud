#!/bin/sh -e
echo "MIRROR=${MIRROR:="https://dl-2.alpinelinux.org/alpine"}"
# adapted from https://wildwolf.name/a-simple-script-to-create-systemd-nspawn-alpine-container/

# shellcheck source=./conf.env
[ -f "${CONF:="./conf.env"}" ] && . "$CONF"
echo "installing alpine linux with:"
echo "HOSTNAME=${HOSTNAME:="alpine"}"
echo "DOMAIN=${DOMAIN:="domain.local"}"
echo "TARGET=${TARGET:="/var/lib/machines/$HOSTNAME"}"
echo "MIRROR=${MIRROR:="https://dl-cdn.alpinelinux.org/alpine"}"
echo "VERSION=${VERSION:="latest-stable"}"
echo "ARCH=${ARCH:="$(arch)"}"
echo "IFACE=${IFACE:="mv-eth0"}"
echo ""

if [ "$(id -u)" -ne "0" ]; then
    echo 'restarting as root ...' >&2
    exec "$0" "$@"
fi

if [ ! -d "$TARGET" ]; then
    mkdir -p "$TARGET"
elif [ "$(find "$TARGET" -maxdepth 1 ! -wholename "$TARGET" | wc -l)" -ne 0 ]; then
    echo "target directory is not empty" >&2
    ls -lA "$TARGET" >&2
    printf "delete all files in %s? (y|n): " "$TARGET" >&2
    IFS= read -r var
    [ "$var" != "y" ] && echo "aborted since target directory is not empty" >&2 && exit 1
    find "$TARGET" ! -wholename "$TARGET" -delete
fi

echo "installing alpine linux to: $TARGET ..." >&2
apkdir="$(mktemp --tmpdir="$TARGET" --directory)"
# trap 'rm -rf "$apkdir"' EXIT
echo "using temp directory $apkdir ..." >&2

APKTOOLS="$(curl -s -fL "$MIRROR/$VERSION/main/$ARCH" | grep -Eo 'apk-tools-static[^"]+\.apk' | head -n 1)"
echo "using: $MIRROR/$VERSION/main/$ARCH/$APKTOOLS" >&2

curl -s -fL "$MIRROR/$VERSION/main/$ARCH/$APKTOOLS" | tar -xz -C "$apkdir"

mkdir -p "$apkdir/keys"
cat > "$apkdir/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub" <<EOF
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
# cat > "$apkdir/keys/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub" <<EOF
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr8s1q88XpuJWLCZALdKj
# lN8wg2ePB2T9aIcaxryYE/Jkmtu+ZQ5zKq6BT3y/udt5jAsMrhHTwroOjIsF9DeG
# e8Y3vjz+Hh4L8a7hZDaw8jy3CPag47L7nsZFwQOIo2Cl1SnzUc6/owoyjRU7ab0p
# iWG5HK8IfiybRbZxnEbNAfT4R53hyI6z5FhyXGS2Ld8zCoU/R4E1P0CUuXKEN4p0
# 64dyeUoOLXEWHjgKiU1mElIQj3k/IF02W89gDj285YgwqA49deLUM7QOd53QLnx+
# xrIrPv3A+eyXMFgexNwCKQU9ZdmWa00MjjHlegSGK8Y2NPnRoXhzqSP9T9i2HiXL
# VQIDAQAB
# -----END PUBLIC KEY-----
# EOF

    # --allow-untrusted \
"$apkdir/sbin/apk.static" \
    --keys-dir "$apkdir/keys" \
    --verbose \
    --progress \
    --root "$TARGET" \
    --arch "$ARCH" \
    --initdb \
    --repository "$MIRROR/$VERSION/main" \
    --update-cache \
    add alpine-base \
        # nginx nginx-openrc \
        # postgresql postgresql-contrib postgresql-openrc \
        # mandoc apk-tools-doc

echo "$MIRROR/$VERSION/main" > "$TARGET/etc/apk/repositories"
echo "$MIRROR/$VERSION/community" >> "$TARGET/etc/apk/repositories"

for i in $(seq 0 10); do
    echo "pts/$i" >> "$TARGET/etc/securetty"
done

sed -i '/tty[0-9]:/ s/^/#/' "$TARGET/etc/inittab"
echo 'console::respawn:/sbin/getty 38400 console' >> "$TARGET/etc/inittab"

# for svc in bootmisc hostname syslog; do
#     ln -s "/etc/init.d/$svc" "$TARGET/etc/runlevels/boot/$svc"
# done

# for svc in killprocs savecache; do
#     ln -s "/etc/init.d/$svc" "$TARGET/etc/runlevels/shutdown/$svc"
# done

mkdir -p "/etc/systemd/nspawn"
cat > "/etc/systemd/nspawn/${HOSTNAME}.nspawn" <<-EOF
	[Exec]
	PrivateUsers=false

	[Network]
	VirtualEthernet=no
	MACVLAN=eth0
EOF

cat > "$TARGET/etc/network/interfaces" <<-EOF
	auto lo
	iface lo inet loopback

	auto mv-eth0
	iface mv-eth0 inet dhcp
EOF

systemd-nspawn --directory="$TARGET" --pipe sh -s <<-EOF
rc-update add networking boot
rc-update add bootmisc boot
rc-update add hostname boot
rc-update add syslog boot
rc-update add killprocs shutdown
rc-update add savecache shutdown
echo "$HOSTNAME" > "/etc/hostname"
echo "127.0.1.1	$HOSTNAME $HOSTNAME.$DOMAIN" >> "/etc/hosts"
EOF

echo "Success" >&2
exit 0

#!/bin/sh -eu
# this is just an example of configuring a zfs pool and dataset on a fresh machine

POOL="${1:-"zpool"}"
: "${FQDN:="$(hostname -f)"}"
: "${VDEV:="blah"}" # make sure to set this correctly (ie. sda)

if zpool status "$POOL" 1>/dev/null 2>&1; then
	printf "\nzpool '%s' already exists - exiting\n" "$POOL"
else
	read -p 'enter zpool encryption password (min 8 chars): ' PASSWD
	echo "$PASSWD" >  /root/.dict
	zpool create -O compression=on -O encryption=on -O keyformat=passphrase -O keylocation=file:///root/.dict "$POOL" "/dev/${VDEV}"

	mkdir -p /var/lib/machines
	zfs create -o "mountpoint=/var/lib/machines/$FQDN" "${POOL}/$FQDN"

	mkdir -p '/etc/systemd/system/zfs-import-cache.service.d'
	cat > '/etc/systemd/system/zfs-import-cache.service.d/override.conf' <<-EOF
		[Unit]
		Requires=dev-${VDEV}1.device
		After=dev-${VDEV}1.device
	EOF

	cat > /etc/systemd/system/zfs-mount.service.d/override.conf <<-EOF
		[Service]
		ExecStartPre=/usr/sbin/zfs load-key zpool
	EOF

	systemctl daemon-reload
fi

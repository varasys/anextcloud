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
		# nextcloud tarball
		NEXTCLOUD='${NEXTCLOUD:="https://download.nextcloud.com/server/releases/nextcloud-21.0.1.zip"}'
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
		--setenv="HOSTNAME=$HOSTNAME" \
		--setenv="DOMAIN=$DOMAIN" \
		--setenv="NEXTCLOUD=$NEXTCLOUD" \
		sh -s < "$0"

	log "finished"
}

setup_container() {
	# this function is meant to be run INSIDE the container (not the host)
	# it is run automatically at the end of the setup_host function
	# this is adapted from https://wiki.alpinelinux.org/wiki/Nextcloud
	echo 'in the container'

	rc-update add networking boot
	rc-update add bootmisc boot
	rc-update add hostname boot
	rc-update add syslog boot
	rc-update add killprocs shutdown
	rc-update add savecache shutdown

	log 'installing postgresql ...'
	apk add postgresql postgresql-contrib postgresql-openrc
	export PGDATA='/var/lib/postgresql/data'
	echo "data_dir=\"$PGDATA\"" >> "/etc/conf.d/postgresql"
	sed -i '/^conf_dir/ s/^/#/' "/etc/conf.d/postgresql"
	su postgres -c initdb
	adduser -HDS nextcloud
	su postgres -c "pg_ctl -o '-k /tmp' start"
	su postgres -c psql <<-EOF
		CREATE USER nextcloud;
		CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
		ALTER DATABASE nextcloud OWNER TO nextcloud;
		GRANT ALL PRIVILEGES ON DATABASE nextcloud TO nextcloud;
	EOF
	# don't stop the database, it needs to be running for a later step
	rc-update add postgresql

	log 'installing nextcloud tarball ...'
	apk add curl # use curl since wget wants to use IPV6
	mkdir -p "/usr/share/webapps"
	curl -L "$NEXTCLOUD" | busybox unzip -d "/usr/share/webapps" -


	log 'installing nginx and php7 ...'
	apk add nginx php7 php7-fpm \
		ffmpeg \
		php7-bz2 \
		php7-common \
		php7-ctype \
		php7-curl \
		php7-dom \
		php7-exif \
		php7-fileinfo \
		php7-gd \
		php7-gmp \
		php7-iconv \
		php7-intl \
		php7-json \
		php7-mbstring \
		php7-opcache \
		php7-openssl \
		php7-pdo \
		php7-pdo_pgsql \
		php7-pecl-imagick \
		php7-pgsql \
		php7-posix \
		php7-session \
		php7-simplexml \
		php7-xml \
		php7-xmlreader \
		php7-xmlwriter \
		php7-zip
	# DO THE FOLLOWING TO /etc/nginx.conf
	# REMOVE TLSv1.1 from /etc/nginx/nginx.conf (probably with sed)
	# ENABLE gzipping of responses (I think)

	mv "/etc/nginx/http.d/default.conf" "/etc/nginx/http.d/default.conf.orig"
	cat > "/etc/nginx/http.d/$HOSTNAME.$DOMAIN.conf" <<-EOF
		server {
		  #listen       [::]:80; #uncomment for IPv6 support
		  listen       80;
		  return 301 https://\$host\$request_uri;
		  server_name $HOSTNAME.$DOMAIN;
		}

		server {
		  #listen       [::]:443 ssl; #uncomment for IPv6 support
		  listen       443 ssl;
		  server_name  $HOSTNAME.$DOMAIN;

		  root /usr/share/webapps/nextcloud;
		  index  index.php index.html index.htm;
		  disable_symlinks off;

		  ssl_certificate      /etc/ssl/nginx.crt;
		  ssl_certificate_key  /etc/ssl/nginx.key;
		  ssl_session_timeout  5m;

		  #Enable Perfect Forward Secrecy and ciphers without known vulnerabilities
		  #Beware! It breaks compatibility with older OS and browsers (e.g. Windows XP, Android 2.x, etc.)
		  #ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA;
		  #ssl_prefer_server_ciphers  on;


		  location / {
		    try_files \$uri \$uri/ /index.html;
		  }

		  # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
		  location ~ [^/]\.php(/|$) {
		    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
		    if (!-f \$document_root\$fastcgi_script_name) {
		      return 404;
		    }
		    fastcgi_pass 127.0.0.1:9000;
		    #fastcgi_pass unix:/run/php-fpm/socket;
		    fastcgi_index index.php;
		    include fastcgi.conf;
		  }
		}
	EOF

	sed -i '/^user =/ s/.*/user = nginx/' "/etc/php7/php-fpm.d/www.conf"
	sed -i '/^group =/ s/.*/group = www-data/' "/etc/php7/php-fpm.d/www.conf"
	sed -i 's/^;env/env/' "/etc/php7/php-fpm.d/www.conf"

	rc-update add nginx
	rc-update add php-fpm7

	sed -i '/^memory_limit =/ s/.*/memory_limit = 1G/' "/etc/php7/php.ini"

	log 'creating self signed certificate ...'
	apk add openssl
	openssl req -x509 \
		-nodes \
		-days 365 \
		-newkey rsa:4096 \
		-subj "/CN=$HOSTNAME.$DOMAIN" \
		-keyout /etc/ssl/nginx.key \
		-out /etc/ssl/nginx.crt

	log "finished installing nextcloud"

	ADMIN_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13)"
	echo "$ADMIN_PASS" > "/root/nextcloud_password"
	log "\n\nnextcloud admin user: 'admin'"
	log "nextcloud admin pass: '%s'\n\n" "$ADMIN_PASS"

	log "performing initial nextcloud configuration - this may take some time ..."
	su -s "/bin/sh" nginx -c "php /usr/share/webapps/nextcloud/occ maintenance:install \
		--database 'pgsql' \
		--database-name 'nextcloud' \
		--database-user 'nextcloud' \
		--database-pass '' \
		--admin-user 'admin' \
		--admin-pass '$ADMIN_PASS'"

	su -s "/bin/sh" nginx -c "php /usr/share/webapps/nextcloud/occ \
		config:system:set trusted_domains 1 \
		--value='$HOSTNAME.$DOMAIN'"

	# it is okay to stop the database now
	su postgres -c 'pg_ctl stop'
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

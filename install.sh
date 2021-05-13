#!/usr/bin/env sh
set -e # fail fast (this is important to ensure downloaded files are properly verified)

# this script must be run as a file, it can't be piped via stdin for two reasons:
# 1) it will restart itself if not run as root, and
# 2) it pipes itself into the container, and then runs within the container to finish the configuration

# TODO install certbot (use env variable to know whether to run?)
# TODO run cronjob to update lets encrypt cert
# TODO install pretty link thing

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
		warn 'restarting as root ...'
		exec "$0" "$@"
	fi

	# work out where to get config input from
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
		HOSTNAME='${HOSTNAME:="cloud"}'
		# domain of the container
		DOMAIN='${DOMAIN:="domain.local"}'
		# location of the container rootfs (on the host)
		TARGET='${TARGET:="/var/lib/machines/$HOSTNAME"}'
		# alpine linux mirror location
		MIRROR='${MIRROR:="https://dl-cdn.alpinelinux.org/alpine/"}'
		# alpine linux stream
		VERSION='${VERSION:="latest-stable"}'
		# host machine achitecture
		ARCH='${ARCH:="$(arch)"}'
		# host network interface for MACVLAN
		IFACE='${IFACE:="eth0"}'
		# network interface prefix in the container
		IFACE_PREFIX='${IFACE_PREFIX:="mv-"}'
		# nextcloud download url
		NEXTCLOUD_URL='${NEXTCLOUD_URL:="https://download.nextcloud.com/server/releases/nextcloud-21.0.1.tar.bz2"}'
		# nextcloud signature download url
		NEXTCLOUD_SIG='${NEXTCLOUD_SIG:="${NEXTCLOUD_URL}.asc"}'
	EOF

	# create target directory or ensure it is empty
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

	log 'installing alpine linux to: %s ...' "$TARGET"

	# create temp directory
	apkdir="$(mktemp --tmpdir="$TARGET" --directory)"
	trap 'rm -rf "$apkdir"' EXIT

	APKTOOLS="$(curl -s -fL "$MIRROR/$VERSION/main/$ARCH" | grep -Eo 'apk-tools-static[^"]+\.apk' | head -n 1)"
	log "using: $MIRROR/$VERSION/main/$ARCH/$APKTOOLS"

	log 'downloading alpine linux ...'
	curl -s -fL "$MIRROR/$VERSION/main/$ARCH/$APKTOOLS" | tar -xz -C "$apkdir"

	log 'installing alpine linux key ...'
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

	log 'installing alpine linux ...'
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

	log 'creating systemd-nspawn settings file ...'
	mkdir -p "/etc/systemd/nspawn"
	cat > "/etc/systemd/nspawn/$(basename "$TARGET").nspawn" <<-EOF
		[Exec]
		PrivateUsers=false

		[Network]
		VirtualEthernet=no
		MACVLAN=$IFACE
	EOF

	log 'configuring alpine linux repositories ...'
	echo "$MIRROR/$VERSION/main" > "$TARGET/etc/apk/repositories"
	echo "$MIRROR/$VERSION/community" >> "$TARGET/etc/apk/repositories"

	log 'configuring container networking ...'
	cat > "$TARGET/etc/network/interfaces" <<-EOF
		auto lo
		iface lo inet loopback

		auto ${IFACE_PREFIX}${IFACE}
		iface ${IFACE_PREFIX}${IFACE} inet dhcp
	EOF

	log 'adding pseudo terminals ...'
	for i in $(seq 0 10); do
		echo "pts/$i" >> "$TARGET/etc/securetty"
	done

	log 'enabling console ...'
	sed -i '/tty[0-9]:/ s/^/#/' "$TARGET/etc/inittab"
	echo 'console::respawn:/sbin/getty 38400 console' >> "$TARGET/etc/inittab"

	log 'setting hostname ...'
	echo "$HOSTNAME" > "$TARGET/etc/hostname"
	echo "127.0.1.1	$HOSTNAME $HOSTNAME.$DOMAIN" >> "$TARGET/etc/hosts"

	log 'copying install script into container ...'
	cp "$0" "$TARGET/root/install.sh"

	log 'spawning container ...'
	systemd-nspawn \
		--directory="$TARGET" \
		--settings=false \
		--console=pipe \
		--setenv="SCRIPT_ENV=CONTAINER" \
		--setenv="HOSTNAME=$HOSTNAME" \
		--setenv="DOMAIN=$DOMAIN" \
		--setenv="NEXTCLOUD_URL=$NEXTCLOUD_URL" \
		--setenv="NEXTCLOUD_SIG=$NEXTCLOUD_SIG" \
		sh -s < "$0"

	log "finished"
}

setup_container() {
	# this function is meant to be run INSIDE the container (not the host)
	# it is run automatically at the end of the setup_host function
	# this is adapted from https://wiki.alpinelinux.org/wiki/Nextcloud
	log 'configuring container ...'
	mkdir -p '/usr/local/sbin'

	log 'enabling system services ...'
	rc-update add networking boot
	rc-update add bootmisc boot
	rc-update add hostname boot
	rc-update add syslog boot
	rc-update add killprocs shutdown
	rc-update add savecache shutdown

	log 'installing postgresql ...'
	apk add postgresql postgresql-contrib postgresql-openrc

	log 'configuring postgresql ...'
	export PGDATA='/var/lib/postgresql/data'
	echo "data_dir=\"$PGDATA\"" >> "/etc/conf.d/postgresql"
	sed -i '/^conf_dir/ s/^/#/' "/etc/conf.d/postgresql"
	
	log 'initializing postgresql cluster ...'
	su postgres -c initdb

	# create wrapper script to run `psql` command as nextcloud user
	log 'creating wrapper script at "/usr/local/sbin/psql" ...'
	cat > "/usr/local/sbin/psql" <<-'EOF'
		#!/usr/bin/env sh
		set -eu

		printf "running \`/usr/bin/psql\` utility as user: %s\n" "${PGUSER:="postgres"}" >&2
		printf "set PGUSER environment variable to run as a different user\n" >&2
		CMD="/usr/bin/psql $@"
		su "$PGUSER" -c "$CMD"
	EOF
	chmod +x '/usr/local/sbin/psql'

	log 'creating nextcloud system user ...'
	adduser -HDS nextcloud

	log 'creating nextcloud database ...'
	su postgres -c "pg_ctl -o '-k /tmp' start"
	psql <<-EOF
		CREATE USER nextcloud;
		CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
		ALTER DATABASE nextcloud OWNER TO nextcloud;
		GRANT ALL PRIVILEGES ON DATABASE nextcloud TO nextcloud;
	EOF
	# don't stop the database, it needs to be running for later steps

	log 'enabling postgresql database ...'
	rc-update add postgresql

	log 'installing curl and gnupg ...'
	apk add curl gnupg # use curl since wget wants to use IPV6

	log 'importing nextcloud gpg key ...'
	gpg --import <<-EOF
		-----BEGIN PGP PUBLIC KEY BLOCK-----
		Version: GnuPG v2

		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
		M704NM/xbc23
		=ykUA
		-----END PGP PUBLIC KEY BLOCK-----
	EOF

	log 'downloading nextcloud tarball and signature ...'
	cd '/tmp'
	curl -fLO "$NEXTCLOUD_URL"
	curl -fLO "$NEXTCLOUD_SIG"

	log 'verifying nextcloud tarball ...'
	gpg --verify "./$(basename "$NEXTCLOUD_SIG")" "./$(basename "$NEXTCLOUD_URL")"
	
	log 'extracting nextcloud tarball ...'
	mkdir -p '/usr/share/webapps'
	tar -jxf "./$(basename "$NEXTCLOUD_URL")" -C '/usr/share/webapps'

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

	log 'creating data directory ...'
	mkdir -p '/var/www/nextcloud/data'

	log 'updating directory ownership ...'
	chown -R nginx:www-data '/var/www/nextcloud'
	chown -R nginx:www-data '/usr/share/webapps/nextcloud'

	log 'increasing upload file size ...'
	cp '/etc/php7/php.ini' '/etc/php7/php.ini.orig'
	sed -i '/^memory_limit =/ s/.*/memory_limit = 1G/' "/etc/php7/php.ini"
	sed -i '/^upload_max_filesize =/ s/.*/upload_max_filesize = 16G/' '/etc/php7/php.ini'
	sed -i '/^post_max_size =/ s/.*/post_max_size = 16G/' '/etc/php7/php.ini'
	sed -i '/^\tclient_max_body_size / s/.*/	client_max_body_size 16G;/' '/etc/nginx/nginx.conf'

	log 'disabling TLSv1.1 ...'
	cp '/etc/nginx/nginx.conf' '/etc/nginx/nginx.conf.orig'
	sed -i '/^\tssl_protocols / s/.*/	ssl_protocols TLSv1.2 TLSv1.3;/' '/etc/nginx/nginx.conf'

	log 'configuring nginx ...'
	mv '/etc/nginx/http.d/default.conf' '/etc/nginx/http.d/default.conf.orig'
	cat > "/etc/nginx/http.d/$HOSTNAME.$DOMAIN.conf" <<-EOF
		server {
		  #listen       [::]:80; #uncomment for IPv6 support
		  listen       80;
		  return 301 https://\$host\$request_uri;
		  server_name $HOSTNAME.$DOMAIN;
		}

		server {
		  #listen       [::]:443 ssl http2; #uncomment for IPv6 support
		  listen       443 ssl http2;
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

	log 'configuring php7 ...'
	cp '/etc/php7/php-fpm.d/www.conf' '/etc/php7/php-fpm.d/www.conf.orig'
	sed -i '/^user =/ s/.*/user = nginx/' '/etc/php7/php-fpm.d/www.conf'
	sed -i '/^group =/ s/.*/group = www-data/' '/etc/php7/php-fpm.d/www.conf'
	sed -i 's/^;env/env/' '/etc/php7/php-fpm.d/www.conf'

	log 'enabling nginx and php7 ...'
	rc-update add nginx
	rc-update add php-fpm7

	log 'creating self signed certificate ...'
	apk add openssl
	openssl req -x509 \
		-nodes \
		-days 365 \
		-newkey rsa:4096 \
		-subj "/CN=$HOSTNAME.$DOMAIN" \
		-keyout /etc/ssl/nginx.key \
		-out /etc/ssl/nginx.crt

	log 'generating admin password ...'
	ADMIN_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13)"
	echo "$ADMIN_PASS" > "/root/nextcloud_password"

	# create wrapper script to run `occ` command as nginx user
	log 'creating wrapper script at "/usr/local/sbin/occ" ...'
	cat > "/usr/local/sbin/occ" <<-'EOF'
		#!/usr/bin/env sh
		set -eu

		printf "running occ utility as user: nginx\n" >&2
		CMD="/usr/bin/php /usr/share/webapps/nextcloud/occ $@"
		su -s /bin/sh nginx -c "$CMD"
	EOF
	chmod +x '/usr/local/sbin/occ'

	log 'performing initial nextcloud configuration - this may take some time ...'
	occ maintenance:install \
		--database 'pgsql' \
		--database-name 'nextcloud' \
		--database-user 'nextcloud' \
		--database-pass '' \
		--admin-user 'admin' \
		--admin-pass "$ADMIN_PASS" \
		--data-dir '/var/www/nextcloud/data'

	log 'installing clamav antivirus ...'
	apk add clamav clamav-libunrar

	log 'enabling clamav and freshclam ...'
	rc-update add clamd
	rc-update add freshclam

	log 'downloading clamav database ...'
	# freshclam --show-progress --foreground --on-update-execute=EXIT_0
	freshclam --show-progress --foreground

	log 'installing and enabling "files_antivirus" nextcloud app ...'
	occ app:install 'files_antivirus'

	log 'installing common apps ...'
	occ app:install 'calendar'
	occ app:install 'contacts'
	occ app:install 'groupfolders'
	occ app:install 'notes'
	occ app:install 'tasks'
	occ app:install 'twofactor_totp'
	occ app:install 'spreed'

	# install and configure redis last otherwise the redis server will
	# need to be running to do any operations with `occ`
	log 'installing APCu and redis ...'
	apk add redis php7-pecl-redis redis-openrc php7-pecl-apcu
	
	log 'enabling redis ...'
	rc-update add redis

	log 'configuring redis ...'
	cp '/etc/redis.conf' '/etc/redis.conf.orig'
	# do not listen on tcp (only listen on local socket)
	sed -i '/^port / s/.*/port 0/' '/etc/redis.conf'
	# add nginx user to redis group
	adduser nginx redis

	log 'configuring nextcloud redis caching ...'
	occ config:import <<-EOF
		{
		    "system": {
		        "trusted_domains": [
		            "localhost",
		            "$HOSTNAME.$DOMAIN"
		        ],
		        "memcache.local": "\\\\OC\\\\Memcache\\\\APCu",
		        "memcache.locking": "\\\\OC\\\\Memcache\\\\Redis",
		        "memcache.distributed": "\\\\OC\\\\Memcache\\\\Redis",
		        "redis": {
		            "host": "/run/redis/redis.sock",
		            "port": 0
		        }
		    }
		}
	EOF

	log 'configuring php redis session management ...'
	cp '/etc/php7/php.ini' '/etc/php7/php.ini.orig'
	sed -i '/^session\.save_handler =/ s/.*/session.save_handler = redis/' '/etc/php7/php.ini'
	sed -i '/^;session\.save_path =/ s/.*/session.save_path = "\/run\/redis\/redis.sock"/' '/etc/php7/php.ini'

	cat >> '/etc/php7/php.ini' <<-EOF
		[redis session management]
		redis.session.locking_enabled=1
		redis.session.lock_retries=-1
		redis.session.lock_wait_time=10000
	EOF

	# it is okay to stop the database now
	su postgres -c 'pg_ctl stop --mode=smart'

	log 'finished installing nextcloud'
	warn "\nnextcloud admin user: 'admin'"
	warn "nextcloud admin pass: '%s'\n" "$ADMIN_PASS"
	log 'the admin password is saved in the container at "/root/nextcloud_password"'

	# shellcheck disable=SC2016
	log 'use `systemd-nspawn -bM %s` to manually start container' "$HOSTNAME"
	# shellcheck disable=SC2016
	log 'use `systemctl enable systemd-nspawn@%s.service` to automatically start container at boot' "$HOSTNAME"
	log 'use the wrapper script at '/usr/local/sbin/occ' to run maintenance commands inside the container'
	log 'use the wrapper script at '/usr/local/sbin/psql' to connect to the nextcloud db inside the container'
}

# When the script is run by the user the SCRIPT_ENV environment variable
# is not set, so the setup_host function will be run. The setup_host
# function will then copy this file into the container for future reference
# and run it by piping it into `systemd-nspawn` with the SCRIPT_ENV
# environment variable set to 'CONTAINER' which will cause the
# setup_container funtion to be run inside the container.
case "${SCRIPT_ENV:='HOST'}" in
	'CONTAINER')
		setup_container "$@"
		;;
	*)
		setup_host "$@"
		;;
esac

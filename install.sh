#!/usr/bin/env sh
set -e # fail fast (this is important to ensure downloaded files are properly verified)

# this script must be run as a file, it can't be piped via stdin for two reasons:
# 1) it will restart itself if not run as root, and
# 2) it pipes itself into the container, and then runs within the container to finish the configuration

# TODO install mail server


{ # define utility functions for logging
	NC='\e[0m'
	RED='\e[0;31;1m'
	YELLOW='\e[0;33;1m'
	BLUE='\e[0;34;1m'
	PURPLE='\e[0;35;1m'

	log() {
		msg=$1; shift
		printf "\n%b$msg%b\n" "$BLUE" "$@" "$NC"
	}
	warn() {
		msg=$1; shift
		printf "\n%b$msg%b\n" "$YELLOW" "$@" "$NC" >&2
	}
	error() {
		msg=$1; shift
		printf "\n%b$msg%b\n" "$RED" "$@" "$NC" >&2
	}
	prompt() { # does not include newline (so user input is on the same line)
		msg=$1; shift
		printf "\n%b$msg%b" "$PURPLE" "$@" "$NC" >&2
		IFS= read -r var
		printf "%s" "$var"
	}
}

update_file() { # convenience function to run `sed` inplace with multiple expressions
	file="$1"
	shift
	for exp in "$@"; do
		sed -i "$exp" "$file"
	done
}

is_container() {
	tr '\0' '\n' < '/proc/1/environ' | grep -q 'container=systemd-nspawn'
}

load_config() { # work out where to get config from and source config file if it exists
	if [ $# -gt 0 ]; then
		CONF="$1"
		shift
	fi
	if [ -n "$CONF" ]; then
		log 'sourcing configuration from: "%s"' "$CONF"
		# shellcheck disable=SC1090
		. "$CONF"
	fi
}

print_host_config() { # variables used to setup a host environment
	cat <<-EOF
		# \`systemd-nspawn\` Host Config

		# fully qualified domain name
		FQDN='${FQDN:="${HOSTNAME:="$(hostname -s)"}.${DOMAIN:="$(hostname -d)"}"}'
		# installation location of the container rootfs (on the host)
		TARGET='${TARGET:="/var/lib/machines/$FQDN"}'
		# host architecture
		ARCH='${ARCH:="$(arch)"}'
		# Alpine Linux branch
		ALPINE_BRANCH='${ALPINE_BRANCH:="3.14"}'
		# Alpine Linux release
		ALPINE_RELEASE='${ALPINE_RELEASE:="0"}'
		# Alpine Linux distribution mirror location
		ALPINE_MIRROR='${ALPINE_MIRROR:="https://dl-cdn.alpinelinux.org/alpine"}'
		# Alpine Linux minirootfs url
		ALPINE_URL='${ALPINE_URL:="${ALPINE_MIRROR}/v${ALPINE_BRANCH}/releases/${ARCH}/alpine-minirootfs-${ALPINE_BRANCH}.${ALPINE_RELEASE}-${ARCH}.tar.gz"}'
		# Alpine Linux minirootfs signature url
		ALPINE_SIG_URL='${ALPINE_SIG_URL:="${ALPINE_URL}.asc"}'
		# host network interface (for MACVLAN)
		NET_IFACE='${NET_IFACE:="eth0"}'
		# cache dir
		CACHE_DIR='${CACHE_DIR="./cache"}'
		# apk cache dir
		APK_CACHE_DIR='${APK_CACHE_DIR="${CACHE_DIR+"$CACHE_DIR/apk"}"}'
		# nextcloud cache dir
		NEXTCLOUD_CACHE_DIR='${NEXTCLOUD_CACHE_DIR="${CACHE_DIR+"$CACHE_DIR/nextcloud"}"}'

	EOF
}

print_alpine_config() { # variables used to setup Alpine Linux
	cat <<-EOF
		# Alpine Linux Config

		# fully qualified domain name
		FQDN='${FQDN:="${HOSTNAME:="$(hostname -s)"}.${DOMAIN:="$(hostname -d)"}"}'
		# nextcloud version
		NEXTCLOUD_VER='${NEXTCLOUD_VER:="21"}'
		# nextcloud download url
		NEXTCLOUD_URL='${NEXTCLOUD_URL:="https://download.nextcloud.com/server/releases/latest-${NEXTCLOUD_VER}.tar.bz2"}'
		# nextcloud signature download url
		NEXTCLOUD_SIG='${NEXTCLOUD_SIG:="${NEXTCLOUD_URL}.asc"}'
		# nextcloud app dir prefix
		APP_DIR_PREFIX="${APP_DIR_PREFIX:="/usr/local/share"}"
		# nextcloud data dir
		DATA_DIR_PREFIX="${DATA_DIR_PREFIX:="/var/lib"}"
		# apps to install
		APPS='${APPS="
		  calendar
		  contacts
		  richdocuments
		  richdocumentscode
		  groupfolders
		  notes
		  tasks
		  twofactor_totp
		  spreed
		  drawio
		  files_mindmap
		  keeweb
		  files_bpm
		"}'
	EOF
}

prepare_container() { # prepare the host by installing alpine linux into the $TARGET directory
	if [ $# -gt 0 ] && echo "$1" | grep -qe '^-\?-c'; then # print config and exit
		# the line above uses a regex to check if the first argument starts with --c or -c
		shift
		load_config "$@"
		print_host_config
		print_alpine_config
		exit 0
	fi

	if ! command -v 'systemd-nspawn' >/dev/null; then
		error "fatal error: \`systemd-nspawn\` command not available"
		exit 1
	fi

	if [ "$(id -u)" -ne "0" ]; then
		warn 'restarting as root ...'
		exec sudo "$0" "$@"
	fi

	load_config "$@"
	print_host_config
	if [ -z "$FQDN" ]; then
		error 'fatal error: missing FQDN environment variable'
		exit 1
	fi
	if [ -z "${FQDN#*.}" ]; then
		error 'fatal error: missing domain part of FQDN environment variable'
		exit 1
	fi

	{ # create target directory or ensure it is empty
		if [ ! -d "$TARGET" ]; then
			log 'creating target directory: "%s" ...' "$TARGET"
			mkdir -p "$TARGET"
		elif [ "$(find "$TARGET" -maxdepth 1 ! -wholename "$TARGET" | wc -l)" -ne 0 ]; then
			warn "target directory is not empty"
			ls -lA "$TARGET" >&2
			[ ! "$(prompt "delete all files in '%s'? (y|n): " "$TARGET")" = "y" ] \
				&& error "fatal error: aborted since target directory is not empty" \
				&& exit 1
			find "$TARGET" ! -wholename "$TARGET" -delete
		fi
		TARGET="$(realpath "$TARGET")" # update variable with absolute path
	}

	{
		log 'installing Alpine Linux gpg key ...'
		export GNUPGHOME="$TARGET/gnupg"
		mkdir --mode 700 "$GNUPGHOME"
		gpg --import <<-EOF
			-----BEGIN PGP PUBLIC KEY BLOCK-----
			Version: GnuPG v2

			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
			Mkc=
			=FcYC
			-----END PGP PUBLIC KEY BLOCK-----
		EOF
		log 'setting ultimate trust on Alpine Linux gpg key ...'
		echo '0482D84022F52DF1C4E7CD43293ACD0907D9495A:6:' | gpg --import-ownertrust

		log 'installing alpine linux to: %s ...' "$TARGET"

		if [ -n "$CACHE_DIR" ]; then
			log 'using cache dir "%s"' "$CACHE_DIR"
			mkdir -p "$CACHE_DIR"
			ln -s "$(realpath "$CACHE_DIR")" "$TARGET/alpine"
		else
			mkdir "$TARGET/alpine"
		fi
		(
			cd "$TARGET/alpine"
			if [ ! -f "$(basename "$ALPINE_URL")" ]; then
				log 'downloading Alpine Linux minirootfs ...'
				curl -LO "$ALPINE_URL"
			fi
			if [ ! -f "$(basename "$ALPINE_SIG_URL")" ]; then
				log 'downloading Alpine Linux minirootfs signature ...'
				curl -LO "$ALPINE_SIG_URL"
			fi
			log 'verifying Alpine Linux minirootfs ...'
			gpg --verify "$(basename "$ALPINE_SIG_URL")" "$(basename "$ALPINE_URL")"
			gpgconf --kill gpg-agent # clean up after gpg
			log 'extracting Alpine Linux minirootfs ...'
			tar -axf "$(basename "$ALPINE_URL")" -C "$TARGET"
			mv "$GNUPGHOME" "$TARGET/root/.gnupg"
			rm -r "$TARGET/alpine"
		)
	}

	{
		log 'creating systemd-nspawn service file ...'
		# systemd-nspawn@.service doesn't really work exactly correct, so just create a new service file
		# don't use a template since upgrades in this script may not be applicable to existing instances
		# so by defining the service directly (instead of with a template) allows instance differences to
		# coexist side by side
		cat > "/etc/systemd/system/$FQDN.service" <<-EOF
			[Unit]
			Description=$FQDN NextCloud Server
			PartOf=machines.target
			Before=machines.target
			After=network.target systemd-resolved.service
			RequiresMountsFor=$TARGET

			[Service]
			RuntimeDirectory=haproxy/$FQDN
			ExecStart=systemd-nspawn --quiet --keep-unit --boot --kill-signal=SIGPWR --directory="$TARGET" --machine="$FQDN" --bind=/run/haproxy/$FQDN:/run/nginx --network-macvlan=$NET_IFACE
			KillMode=mixed
			Type=simple
			RestartForceExitStatus=133
			SuccessExitStatus=133
			Slice=machine.slice
			Delegate=yes

			[Install]
			WantedBy=machines.target
		EOF
		systemctl daemon-reload
	}

	{
		log 'configuring container networking ...'
		cat > "$TARGET/etc/network/interfaces" <<-EOF
			auto lo
			iface lo inet loopback

			auto mv-$NET_IFACE
			iface mv-$NET_IFACE inet dhcp
		EOF

		log 'adding pseudo terminals ...'
		for i in $(seq 0 10); do
			echo "pts/$i" >> "$TARGET/etc/securetty"
		done

		log 'enabling console ...'
		update_file "$TARGET/etc/inittab" \
			'/tty[0-9]:/ s/^/#/'
		echo 'console::respawn:/sbin/getty 38400 console' >> "$TARGET/etc/inittab"

		log 'setting hostname ...'
		echo "${FQDN%%.*}" > "$TARGET/etc/hostname"
		echo "127.0.1.1	$FQDN ${FQDN%%.*}" >> "$TARGET/etc/hosts"

		log 'enabling system services ...'
		mkdir -p "$TARGET/etc/runlevels/boot"
		for service in "networking" "bootmisc" "hostname" "syslog"; do
			ln -s "/etc/init.d/$service" "$TARGET/etc/runlevels/boot/$service"
		done
		mkdir -p "$TARGET/etc/runlevels/shutdown"
		for service in "killprocs" "savecache"; do
			ln -s "/etc/init.d/$service" "$TARGET/etc/runlevels/shutdown/$service"
		done

		if [ -d 'letsencrypt' ]; then
			log 'copying letsencrypt directory into container ...'
			cp --recursive 'letsencrypt' "$TARGET/etc/"
		fi
	}

	( # use sub-shell due to EXIT trap below
		log 'copying install script into container ...'
		mkdir "$TARGET/root/nextcloud"
		cp "$0" "$TARGET/root/nextcloud/install.sh"
		print_host_config > "$TARGET/root/nextcloud/nextcloud.conf"
		print_alpine_config >> "$TARGET/root/nextcloud/nextcloud.conf"

		[ -n "$APK_CACHE_DIR" ] && mkdir -p "$APK_CACHE_DIR"
		[ -n "$NEXTCLOUD_CACHE_DIR" ] && mkdir -p "$NEXTCLOUD_CACHE_DIR"

		log 'spawning container ...'
		mkdir -p "/run/haproxy/$FQDN"
		trap 'rm -rf "/run/haproxy/$FQDN"' EXIT
		systemd-nspawn \
			--directory="$TARGET" \
			--console=pipe \
			--network-macvlan=$NET_IFACE \
			--bind="/run/haproxy/$FQDN:/run/nginx" \
			${APK_CACHE_DIR:+--bind="$(cd "$APK_CACHE_DIR"; pwd):/etc/apk/cache"} \
			${NEXTCLOUD_CACHE_DIR:+--bind="$(cd "$NEXTCLOUD_CACHE_DIR"; pwd):/tmp/cache/nextcloud"} \
			sh - <<-EOF
				passwd -d root
				ip link set up mv-$NET_IFACE
				udhcpc -i mv-$NET_IFACE
				apk add alpine-base
				'/root/nextcloud/install.sh' '/root/nextcloud/nextcloud.conf'
			EOF
	)
}

install_nextcloud() { # this function is run in the alpine container, or bare metal/virtual alpine installation
	if [ $# -gt 0 ] && echo "$1" | grep -qe '^-\?-c'; then # print config and exit
		shift
		load_config "$@"
		print_alpine_config
		exit 0
	fi

	if [ "$(id -u)" -ne "0" ]; then
		warn 'restarting as root ...'
		exec "$0" "$@"
	fi

	load_config "$@"
	print_alpine_config
	[ -z "$FQDN" ] && { error 'fatal error: missing FQDN environment variable'; exit 1; }
	[ -z "${FQDN#*.}" ] && { error 'fatal error: missing domain part of FQDN environment variable'; exit 1; }
	mkdir -p '/usr/local/sbin' '/usr/local/bin' # ensure directories for utility scripts exist

	log 'creating data directory ...'
	mkdir -p "$DATA_DIR_PREFIX/nextcloud"
	mkdir -p "$APP_DIR_PREFIX/nextcloud"

	{ # install postgresql
		log 'installing postgresql ...'
		apk add postgresql postgresql-contrib postgresql-openrc
		rc-update add postgresql default

		log 'configuring postgresql ...'
		export PGDATA='/var/lib/postgresql/data'
		mv '/etc/conf.d/postgresql' '/etc/conf.d/postgresql.orig'
		cat > '/etc/conf.d/postgresql' <<-EOF
			data_dir="$PGDATA"
			logfile="/var/log/postgresql/postmaster.log"
		EOF

		log 'creating postgresql wrapper scripts (to run pg utilities as postgres user) ...'
		cat > '/usr/local/sbin/postgres' <<-'EOF'
			#!/bin/sh -eu
			CMD="/usr/bin/$(basename "$0") $@"
			su "${PGUSER:="postgres"}" -c "$CMD"
		EOF
		chmod +x '/usr/local/sbin/postgres'
		(cd '/usr/bin'; find . -name 'pg_*' -exec ln -s './postgres' '/usr/local/sbin/{}' ';')
		ln -s './postgres' '/usr/local/sbin/psql'
		ln -s './postgres' '/usr/local/sbin/initdb'

		log 'initializing postgresql cluster ...'
		initdb --data-checksums --auth-local=trust --encoding=UTF8

		log 'disabling postgresql TCP access ...'
		update_file "$PGDATA/postgresql.conf" \
			"/^#\?listen_addresses = / s/.*/listen_addresses = ''/"

		log 'starting postgresql database ...'
		mkdir '/run/postgresql'
		chown postgres '/run/postgresql'
		pg_ctl start

		log 'creating nextcloud database ...'
		psql <<-EOF
			CREATE USER nextcloud;
			CREATE DATABASE nextcloud TEMPLATE template0 ENCODING 'UNICODE';
			ALTER DATABASE nextcloud OWNER TO nextcloud;
			GRANT ALL PRIVILEGES ON DATABASE nextcloud TO nextcloud;
		EOF
		# don't stop the database, it needs to be running for later steps
	}

	{ # install nginx and php7-fpm
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
			php7-pcntl \
			php7-posix \
			php7-session \
			php7-simplexml \
			php7-xml \
			php7-xmlreader \
			php7-xmlwriter \
			php7-zip \
			php7-bcmath

		log 'enabling nginx and php7 ...'
		rc-update add nginx default
		rc-update add php-fpm7 default

		( # configure tls certificates
			mv '/etc/nginx/http.d/default.conf' '/etc/nginx/http.d/default.conf.orig'
			log 'configuring nginx for letsencrypt ...'
			cat > '/etc/nginx/http.d/http.conf' <<-EOF
				server {
				    listen 80;
				    listen [::]:80;
				    listen unix:/run/nginx/http.sock proxy_protocol;
				    server_name $FQDN;
				    location '/.well-known/acme-challenge' {
				        default_type "text/plain";
				        root /var/lib/nginx/html;
				    }
				    location / {
				        return 301 https://\$server_name\$request_uri;
				    }
				}
			EOF

			log "creating ssl certificate utility script \`/usr/local/sbin/certman\` ..."
			cat > '/usr/local/sbin/certman' <<-EOF
				#!/bin/sh -e
				# generate ssl private key and request/renew related certificate
				FQDN="\$(hostname -f)"
				if [ "\$1" = "--self-signed" ]; then
				  printf "generating self signed certificate\n\n"
				  command -v openssl >/dev/null || apk add openssl
				  openssl req -x509 \
				    -nodes \
				    -days 365 \
				    -newkey ec \
				    -pkeyopt ec_paramgen_curve:secp384r1 \
				    -subj "/CN=\$FQDN" \
				    -keyout '/etc/nginx/key.pem' \
				    -out '/etc/nginx/cert.pem'
				  ln -s './cert.pem' '/etc/nginx/ca.pem'
				elif [ -d "/etc/letsencrypt/\$FQDN" ]; then
				  printf "renewing existing letsencrypt certificate\n\n"
				  command -v certbot >/dev/null || apk add certbot
				  certbot renew --post-hook "rc-service nginx reload"
				else # request a new letsencrypt certificate
				  printf "requesting new letsencrypt certificate\n\n"
				  command -v certbot >/dev/null || apk add certbot
				  certbot certonly --domain "\$FQDN" \
				    --key-type ecdsa \
				    --elliptic-curve secp384r1 \
				    --webroot \
				    --webroot-path="/var/lib/nginx/html" \
				    --email "admin@\$FQDN" \
				    --agree-tos \
				    --non-interactive
				  ln -fs "../letsencrypt/live/\$FQDN/privkey.pem" '/etc/nginx/key.pem'
				  ln -fs "../letsencrypt/live/\$FQDN/fullchain.pem" '/etc/nginx/cert.pem'
				  ln -fs './cert.pem' '/etc/nginx/ca.pem'
				  # create link to run this script weekly to take care of renewals
				  ln -fs "\$(realpath "\$0")" '/etc/periodic/weekly/certman.sh'
				fi
			EOF
			chmod +x '/usr/local/sbin/certman'

			mkdir -p '/run/nginx'
			chown nginx:www-data '/run/nginx'
			nginx # start nginx with minimal config to serve .well-known/acme-challenge
			log 'requesting letsencrypt certificate ...'
			certman || {
				warn 'letsencrypt certificate request failure - generating self-signed certificate ...'
				certman --self-signed
			}
			nginx -s quit
		)

		log 'configuring nginx for nextcloud ...'
		cat > '/etc/nginx/http.d/https.conf' <<-EOF
			# adapted from https://docs.nextcloud.com/server/latest/admin_manual/installation/nginx.html
			upstream php-handler {
			    server unix:/var/run/php-fpm7/php-fpm.sock;
			}

			server {
			    listen 443      ssl http2;
			    listen [::]:443 ssl http2;
			    listen unix:/run/nginx/https.sock ssl http2 proxy_protocol;
			    server_name $FQDN;

			    # generated 2021-06-15, Mozilla Guideline v5.6, nginx 1.18.0, OpenSSL 1.1.1k, modern configuration, no HSTS
			    # https://ssl-config.mozilla.org/#server=nginx&version=1.18.0&config=modern&openssl=1.1.1k&hsts=false&guideline=5.6
			    ssl_certificate /etc/nginx/cert.pem;
			    ssl_certificate_key /etc/nginx/key.pem;
			    ssl_session_timeout 1d;
			    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
			    ssl_session_tickets off;

			    # modern configuration
			    ssl_protocols TLSv1.2 TLSv1.3;
			    ssl_prefer_server_ciphers off;

			    # OCSP stapling
			    ssl_stapling on;
			    ssl_stapling_verify on;

			    # verify chain of trust of OCSP response using Root CA and Intermediate certs
			    ssl_trusted_certificate /etc/nginx/ca.pem;

			    # replace with the IP address of your resolver
			    resolver 127.0.0.1;

			    # set max upload size
			    client_max_body_size 4G;
			    fastcgi_buffers 64 4K;

			    # Enable gzip but do not remove ETag headers
			    gzip on;
			    gzip_vary on;
			    gzip_comp_level 4;
			    gzip_min_length 256;
			    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
			    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

			    # Pagespeed is not supported by Nextcloud, so if your server is built
			    # with the \`ngx_pagespeed\` module, uncomment this line to disable it.
			    #pagespeed off;

			    # HTTP response headers borrowed from Nextcloud \`.htaccess\`
			    add_header Referrer-Policy                      "no-referrer"   always;
			    add_header X-Content-Type-Options               "nosniff"       always;
			    add_header X-Download-Options                   "noopen"        always;
			    add_header X-Frame-Options                      "SAMEORIGIN"    always;
			    add_header X-Permitted-Cross-Domain-Policies    "none"          always;
			    add_header X-Robots-Tag                         "none"          always;
			    add_header X-XSS-Protection                     "1; mode=block" always;

			    # Remove X-Powered-By, which is an information leak
			    fastcgi_hide_header X-Powered-By;

			    # Path to the root of your installation
			    root $APP_DIR_PREFIX/nextcloud;

			    # Specify how to handle directories -- specifying \`/index.php\$request_uri\`
			    # here as the fallback means that Nginx always exhibits the desired behaviour
			    # when a client requests a path that corresponds to a directory that exists
			    # on the server. In particular, if that directory contains an index.php file,
			    # that file is correctly served; if it doesn't, then the request is passed to
			    # the front-end controller. This consistent behaviour means that we don't need
			    # to specify custom rules for certain paths (e.g. images and other assets,
			    # \`/updater\`, \`/ocm-provider\`, \`/ocs-provider\`), and thus
			    # \`try_files \$uri \$uri/ /index.php\$request_uri\`
			    # always provides the desired behaviour.
			    index index.php index.html /index.php\$request_uri;

			    # Rule borrowed from \`.htaccess\` to handle Microsoft DAV clients
			    location = / {
			        if ( \$http_user_agent ~ ^DavClnt ) {
			            return 302 /remote.php/webdav/\$is_args\$args;
			        }
			    }

			    location = /robots.txt {
			        allow all;
			        log_not_found off;
			        access_log off;
			    }

			    # Make a regex exception for \`/.well-known\` so that clients can still
			    # access it despite the existence of the regex rule
			    # \`location ~ /(\\.|autotest|...)\` which would otherwise handle requests
			    # for \`/.well-known\`.
			    location ^~ /.well-known {
			        # The rules in this block are an adaptation of the rules
			        # in \`.htaccess\` that concern \`/.well-known\`.

			        location = /.well-known/carddav { return 301 /remote.php/dav/; }
			        location = /.well-known/caldav  { return 301 /remote.php/dav/; }

			        location /.well-known/acme-challenge    { try_files \$uri \$uri/ =404; }
			        location /.well-known/pki-validation    { try_files \$uri \$uri/ =404; }

			        # Let Nextcloud's API for \`/.well-known\` URIs handle all other
			        # requests by passing them to the front-end controller.
			        return 301 /index.php\$request_uri;
			    }

			    # Rules borrowed from \`.htaccess\` to hide certain paths from clients
			    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
			    location ~ ^/(?:\\.|autotest|occ|issue|indie|db_|console)                { return 404; }

			    # Ensure this block, which passes PHP files to the PHP process, is above the blocks
			    # which handle static assets (as seen below). If this block is not declared first,
			    # then Nginx will encounter an infinite rewriting loop when it prepends \`/index.php\`
			    # to the URI, resulting in a HTTP 500 error response.
			    location ~ \\.php(?:$|/) {
			        fastcgi_split_path_info ^(.+?\\.php)(/.*)\$;
			        set \$path_info \$fastcgi_path_info;

			        try_files \$fastcgi_script_name =404;

			        include fastcgi_params;
			        fastcgi_param REMOTE_ADDR \$proxy_protocol_addr;
			        fastcgi_param REMOTE_PORT \$proxy_protocol_port;
			        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
			        fastcgi_param PATH_INFO \$path_info;
			        fastcgi_param HTTPS on;

			        fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
			        fastcgi_param front_controller_active true;     # Enable pretty urls
			        fastcgi_pass php-handler;

			        fastcgi_intercept_errors on;
			        fastcgi_request_buffering off;
			    }

			    location ~ \\.(?:css|js|svg|gif)$ {
			        try_files \$uri /index.php\$request_uri;
			        expires 6M;         # Cache-Control policy borrowed from \`.htaccess\`
			        access_log off;     # Optional: Don't log access to assets
			    }

			    location ~ \\.woff2?$ {
			        try_files \$uri /index.php\$request_uri;
			        expires 7d;         # Cache-Control policy borrowed from \`.htaccess\`
			        access_log off;     # Optional: Don't log access to assets
			    }

			    # Rule borrowed from \`.htaccess\`
			    location /remote {
			        return 301 /remote.php\$request_uri;
			    }

			    location / {
			        try_files \$uri \$uri/ /index.php\$request_uri;
			    }
			}
		EOF

		cp '/etc/php7/php.ini' '/etc/php7/php.ini.orig'

		log 'configuring php7 upload file size ...'
		# https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/big_file_upload_configuration.html
		update_file '/etc/php7/php.ini' \
			'/^;\?memory_limit \?=/ s/.*/memory_limit = 1G/' \
			'/^;\?upload_max_filesize \?=/ s/.*/upload_max_filesize = 4G/' \
			'/^;\?post_max_size \?=/ s/.*/post_max_size = 4G/' \
			# '/^;\?max_input_time \?=/ s/.*/max_input_time = 3200/' \
			# '/^;\?max_execution_time \?=/ s/.*/max_execution_time = 3200/' \

		log 'configuring php7 opcache ...'
		# https://docs.nextcloud.com/server/latest/admin_manual/installation/server_tuning.html
		update_file '/etc/php7/php.ini' \
			'/^;\?opcache.enable \?=/ s/.*/opcache.enable = 1/' \
			'/^;\?opcache.interned_strings_buffer \?=/ s/.*/opcache.interned_strings_buffer = 8/' \
			'/^;\?opcache.max_accelerated_files \?=/ s/.*/opcache.max_accelerated_files = 10000/' \
			'/^;\?opcache.memory_consumption \?=/ s/.*/opcache.memory_consumption = 128/' \
			'/^;\?opcache.save_comments \?=/ s/.*/opcache.save_comments = 1/' \
			'/^;\?opcache.revalidate_freq \?=/ s/.*/opcache.revalidate_freq = 1/'

		log 'configuring php7 ...'
		cp '/etc/php7/php-fpm.d/www.conf' '/etc/php7/php-fpm.d/www.conf.orig'
		# shellcheck disable=SC2016
		update_file '/etc/php7/php-fpm.d/www.conf' \
			'/^user =/ s/.*/user = nginx/' \
			'/^group =/ s/.*/group = www-data/' \
			'/^listen =/ s/.*/listen = \/var\/run\/php-fpm7\/php-fpm.sock/' \
			'/^;listen\.owner =/ s/.*/listen.owner = nginx/' \
			'/^;listen\.group =/ s/.*/listen.group = www-data/' \
			's/^;env/env/'
	}

	{ # download and install nextcloud
		log 'installing curl and gnupg ...'
		apk add curl gnupg # use `curl` instead of `wget` (since wget wants to use IPV6)

		log 'importing nextcloud gpg key ...'
		gpg --import <<-EOF
			-----BEGIN PGP PUBLIC KEY BLOCK-----
			Version: GnuPG v2

			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
			M704NM/xbc23
			=ykUA
			-----END PGP PUBLIC KEY BLOCK-----
		EOF
		log 'setting ultimate trust on nextcloud gpg key ...'
		echo '28806A878AE423A28372792ED75899B9A724937A:6:' | gpg --import-ownertrust

		mkdir -p '/tmp/cache/nextcloud'
		if [ ! -f "/tmp/cache/nextcloud/$(basename "$NEXTCLOUD_URL")" ]; then
			log 'downloading nextcloud tarball ...'
			curl -fLO "$NEXTCLOUD_URL" --output-dir '/tmp/cache/nextcloud'
		fi
		if [ ! -f "/tmp/cache/nextcloud/$(basename "$NEXTCLOUD_SIG")" ]; then
			log 'downloading nextcloud signature ...'
			curl -fLO "$NEXTCLOUD_SIG" --output-dir '/tmp/cache/nextcloud'
		fi

		log 'verifying nextcloud tarball ...'
		gpg --verify "/tmp/cache/nextcloud/$(basename "$NEXTCLOUD_SIG")" "/tmp/cache/nextcloud/$(basename "$NEXTCLOUD_URL")"
		
		log 'extracting nextcloud tarball ...'
		tar -jxf "/tmp/cache/nextcloud/$(basename "$NEXTCLOUD_URL")" -C "$APP_DIR_PREFIX"

		log 'updating directory ownership ...'
		chown -R nginx:www-data "$DATA_DIR_PREFIX/nextcloud"
		chown -R nginx:www-data "$APP_DIR_PREFIX/nextcloud"

		log 'creating wrapper script at "/usr/local/sbin/occ" ...'
		cat > '/usr/local/sbin/occ' <<-EOF
			#!/bin/sh -eu
			CMD="/usr/bin/php '$APP_DIR_PREFIX/nextcloud/occ' \$@"
			su -s /bin/sh nginx -c "\$CMD"
		EOF
		chmod +x '/usr/local/sbin/occ'

		log 'creating script to view Nextcloud log at "/usr/local/bin/nclog" ...'
		apk add jq
		cat > '/usr/local/bin/nclog' <<-EOF
			#!/bin/sh -eu
			tail -f "$DATA_DIR_PREFIX/nextcloud/nextcloud.log" | jq
		EOF
		chmod +x '/usr/local/bin/nclog'

		log 'generating admin password ...'
		ADMIN_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13)"
		echo "$ADMIN_PASS" > "/root/nextcloud_password"

		log 'performing initial nextcloud configuration - this may take some time ...'
		occ maintenance:install \
			--database 'pgsql' \
			--database-host '/run/postgresql' \
			--database-name 'nextcloud' \
			--database-user 'nextcloud' \
			--database-pass '' \
			--admin-user 'admin' \
			--admin-pass "$ADMIN_PASS" \
			--data-dir "$DATA_DIR_PREFIX/nextcloud"

		log 'configuring trusted_domains ...'
		occ config:import <<-EOF
			{
			  "system": {
			    "trusted_domains": [
			      "localhost",
			      "$FQDN"
			    ]
			  }
			}
		EOF
	}

	{ # install clamav antivirus
		log 'installing clamav antivirus ...'
		apk add clamav clamav-libunrar
		rc-update add clamd default
		rc-update add freshclam default

		log 'downloading clamav database ...'
		freshclam --show-progress --foreground

		log 'installing and enabling "files_antivirus" nextcloud app ...'
		occ app:install 'files_antivirus'
		occ config:import <<-EOF
			{
			  "apps": {
			    "files_antivirus": {
			      "av_mode": "socket",
			      "av_socket": "/run/clamav/clamd.sock"
			    }
			  }
			}
		EOF
	}

	{ # install nextcloud apps
		log 'installing nextcloud apps ...'
		for app in $APPS; do
			log 'installing "%s" ...' "$app"
			if [ "$app" = "richdocumentscode" ] && [ "$(arch)" = 'aarch64' ]; then
				occ app:install 'richdocumentscode_arm64' || warn 'error: install failed for "%s"' "$app"
			else
				occ app:install "$app" || warn 'error: install failed for "%s"' "$app"
			fi
		done
	}

	{ # install redis (cache manager)
		# install and configure redis last otherwise the redis server will
		# need to be running to do any operations with `occ`
		log 'installing APCu and redis ...'
		apk add redis php7-pecl-redis redis-openrc php7-pecl-apcu
		rc-update add redis default

		log 'configuring redis ...'
		cp '/etc/redis.conf' '/etc/redis.conf.orig'
		# do not listen on tcp (only listen on local socket)
		update_file '/etc/redis.conf' \
			'/^port / s/.*/port 0/'
		adduser nginx redis

		log 'configuring redis caching ...'
		occ config:import <<-EOF
			{
			  "system": {
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
		update_file '/etc/php7/php.ini' \
			'/^session\.save_handler =/ s/.*/session.save_handler = redis/' \
			'/^;session\.save_path =/ s/.*/session.save_path = "\/run\/redis\/redis.sock"/'

		cat >> '/etc/php7/php.ini' <<-EOF

			[redis session management]
			redis.session.locking_enabled=1
			redis.session.lock_retries=-1
			redis.session.lock_wait_time=10000

			; https://github.com/nextcloud/vm/issues/2039#issuecomment-875849079
			apc.enable_cli=1
		EOF
	}

	{ # configure cron
		log 'configuring cron ...'
		rc-update add crond default
		crontab -u nginx - <<-EOF
			*/5  *  *  *  * php -f $APP_DIR_PREFIX/nextcloud/cron.php
		EOF
	}

	# it is okay to stop the database now
	log 'stopping postgresql database ...'
	pg_ctl stop --mode=smart

	log 'finished installing Nextcloud'
	warn "\nNextcloud admin user: 'admin'\nNextcloud admin pass: '%s'" "$ADMIN_PASS"
	log 'the admin password above is saved in the container at "/root/nextcloud_password"'

	# shellcheck disable=SC2016
	log 'use `systemctl start %s` to manually start container' "$FQDN"
	# shellcheck disable=SC2016
	log 'use `systemctl enable %s` to automatically start container at boot' "$FQDN"
	log 'use the wrapper script inside the container at '/usr/local/sbin/occ' to run maintenance commands'
	log 'use the wrapper script inside the container at '/usr/local/sbin/psql' to connect to the nextcloud db'
}

# check whether the user is trying to get help (with -h or --help)
if [ $# -gt 0 ] && echo "$1" | grep -qe '^-\?-h'; then
	printf "\nusage: %s [config_file]\n\n" "$(basename "$0")"
	exit 1
fi

# Use the '/etc/os-release' file to determine whether running in Alpine linux
case "${SCRIPT_ENV:="$(. /etc/os-release; echo "$ID")"}" in
	'alpine')
		# running inside Alpine linux, so just install nextcloud
		install_nextcloud "$@"
		;;
	*)
		# not running in Alpine linux, so prepare an Alpine linux container on the host
		prepare_container "$@"
		;;
esac

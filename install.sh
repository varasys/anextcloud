#!/usr/bin/env sh
set -e # fail fast (this is important to ensure downloaded files are properly verified)

# this script must be run as a file, it can't be piped via stdin for two reasons:
# 1) it will restart itself if not run as root, and
# 2) it pipes itself into the container, and then runs within the container to finish the configuration

# TODO install certbot (use env variable to know whether to run?)
# TODO run cronjob to update lets encrypt cert
# TODO enable cron https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/background_jobs_configuration.html
# TODO setup haproxy https://www.haproxy.com/blog/enhanced-ssl-load-balancing-with-server-name-indication-sni-tls-extension/

# define colors - change to empty strings if you don't want colors
NC='\e[0m'
RED='\e[0;31;1m'
YELLOW='\e[0;33;1m'
BLUE='\e[0;34;1m'
PURPLE='\e[0;35;1m'

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

alter_config() { # convievence function to run `sed` inplace with multiple expressions
	file="$1"
	shift
	for exp in "$@"; do
		sed -i "$exp" "$file"
	done
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
		# host network interface for MACVLAN
		IFACE='${IFACE:="eth0"}'
		# network interface prefix in the container
		IFACE_PREFIX='${IFACE_PREFIX:="mv-"}'
		# nextcloud download url
		NEXTCLOUD_URL='${NEXTCLOUD_URL:="https://download.nextcloud.com/server/releases/nextcloud-21.0.1.tar.bz2"}'
		# nextcloud signature download url
		NEXTCLOUD_SIG='${NEXTCLOUD_SIG:="${NEXTCLOUD_URL}.asc"}'
		# apps to install
		APPS='${APPS:=""}'
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

	APKTOOLS="$(curl -s -fL "$MIRROR/$VERSION/main/$(arch)" | grep -Eo 'apk-tools-static[^"]+\.apk' | head -n 1)"
	log "using: $MIRROR/$VERSION/main/$(arch)/$APKTOOLS"

	log 'downloading alpine linux apk-tools ...'
	curl -s -fL "$MIRROR/$VERSION/main/$(arch)/$APKTOOLS" | tar -xz -C "$apkdir"

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
	mkdir -p "$(pwd)/cache/apk"
	"$apkdir/sbin/apk.static" \
		--keys-dir "$apkdir/keys" \
		--verbose \
		--progress \
		--root "$TARGET" \
		--initdb \
		--repository "$MIRROR/$VERSION/main" \
		--cache-dir "$(pwd)/cache/apk" \
		add alpine-base

	log 'creating systemd-nspawn settings file ...'
	mkdir -p "/etc/systemd/nspawn"
	cat > "/etc/systemd/nspawn/$(basename "$TARGET").nspawn" <<-EOF
		[Exec]
		PrivateUsers=false

		[Network]
		VirtualEthernet=no
		MACVLAN=$IFACE

		[Files]
		Bind=/var/lib/haproxy/$HOSTNAME.$DOMAIN:/run/nginx
	EOF
	mkdir -p "/var/lib/haproxy/$HOSTNAME.$DOMAIN"

	log 'configuring alpine linux repositories ...'
	cat > "$TARGET/etc/apk/repositories" <<-EOF
		$MIRROR/$VERSION/main
		$MIRROR/$VERSION/community
	EOF
	# echo "$MIRROR/$VERSION/main" > "$TARGET/etc/apk/repositories"
	# echo "$MIRROR/$VERSION/community" >> "$TARGET/etc/apk/repositories"

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
	alter_config "$TARGET/etc/inittab" \
		'/tty[0-9]:/ s/^/#/'
	# sed -i '/tty[0-9]:/ s/^/#/' "$TARGET/etc/inittab"
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
		--setenv='SCRIPT_ENV=CONTAINER' \
		--setenv="HOSTNAME=$HOSTNAME" \
		--setenv="DOMAIN=$DOMAIN" \
		--setenv="NEXTCLOUD_URL=$NEXTCLOUD_URL" \
		--setenv="NEXTCLOUD_SIG=$NEXTCLOUD_SIG" \
		--setenv="APPS=$APPS" \
		--bind="$(pwd)/cache:/tmp/cache" \
		sh -s < "$0"

	log "finished"
}

setup_container() {
	# this function is meant to be run INSIDE the container (not the host)
	# it is run automatically at the end of the setup_host function
	# this is adapted from https://wiki.alpinelinux.org/wiki/Nextcloud
	log 'configuring container ...'

	mkdir -p '/usr/local/sbin'
	# alias to use the cache directory which which is bind mounted into the container
	alias apk='apk --cache-dir=/tmp/cache/apk'

	log 'installing neovim (for debugging when needed) ...'
	apk add neovim
	cat > '/etc/profile.d/nvim.sh' <<-EOF
		export EDITOR=/usr/bin/nvim
		alias vim=/usr/bin/nvim
	EOF

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
	alter_config '/etc/conf.d/postgresql' \
		'/^conf_dir/ s/^/#/'
	# sed -i '/^conf_dir/ s/^/#/' "/etc/conf.d/postgresql"
	
	log 'initializing postgresql cluster ...'
	su postgres -c initdb

	# create wrapper script to run `psql` command as nextcloud user
	log 'creating wrapper script at "/usr/local/sbin/psql" ...'
	cat > '/usr/local/sbin/psql' <<-'EOF'
		#!/usr/bin/env sh
		set -eu

		printf "running \`/usr/bin/psql\` utility as user: %s\n" "${PGUSER:="postgres"}" >&2
		printf "set PGUSER environment variable to run as a different user\n" >&2
		CMD="/usr/bin/psql $@"
		su "$PGUSER" -c "$CMD"
	EOF
	chmod +x '/usr/local/sbin/psql'
	ln -s '/usr/local/sbin/psql' '/root/psql'

	log 'creating wrapper script at "/usr/local/sbin/pg_dump" ...'
	cat > '/usr/local/sbin/pg_dump' <<-'EOF'
		#!/usr/bin/env sh
		set -eu

		printf "running \`/usr/bin/pg_dump\` utility as user: %s\n" "${PGUSER:="postgres"}" >&2
		printf "set PGUSER environment variable to run as a different user\n" >&2
		if [ "$#" -eq 0 ]; then
		    set - -cvC nextcloud
		fi
		CMD="/usr/bin/pg_dump $@"
		su "$PGUSER" -c "$CMD"
	EOF
	chmod +x '/usr/local/sbin/pg_dump'
	ln -s '/usr/local/sbin/pg_dump' '/root/pg_dump'

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
	rc-update add postgresql default

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
	mkdir -p '/tmp/cache/nextcloud'
	cd '/tmp/cache/nextcloud'
	[ -f "$(basename "$NEXTCLOUD_URL")" ] || curl -fLO "$NEXTCLOUD_URL"
	[ -f "$(basename "$NEXTCLOUD_SIG")" ] || curl -fLO "$NEXTCLOUD_SIG"

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

	log 'creating wrapper script utility to view nextcloud log ...'
	apk add jq # use jq to format the json log
	cat > '/usr/local/sbin/nclog' <<-'EOF'
	#!/usr/bin/env sh
	set -eu

	tail -f '/var/www/nextcloud/data/nextcloud.log' | jq
	EOF
	chmod +x '/usr/local/sbin/nclog'
	ln -s '/usr/local/sbin/nclog' '/root/nclog'

	log 'increasing upload file size ...'
	cp '/etc/php7/php.ini' '/etc/php7/php.ini.orig'
	alter_config '/etc/php7/php.ini' \
		'/^memory_limit =/ s/.*/memory_limit = 1G/' \
		'/^upload_max_filesize =/ s/.*/upload_max_filesize = 16G/' \
		'/^post_max_size =/ s/.*/post_max_size = 16G/'
	# sed -i '/^memory_limit =/ s/.*/memory_limit = 1G/' "/etc/php7/php.ini"
	# sed -i '/^upload_max_filesize =/ s/.*/upload_max_filesize = 16G/' '/etc/php7/php.ini'
	# sed -i '/^post_max_size =/ s/.*/post_max_size = 16G/' '/etc/php7/php.ini'

	log 'disabling TLSv1.1 and increasing nginx client max body size ...'
	cp '/etc/nginx/nginx.conf' '/etc/nginx/nginx.conf.orig'
	alter_config '/etc/nginx/nginx.conf' \
		'/^\tssl_protocols / s/.*/	ssl_protocols TLSv1.2 TLSv1.3;/' \
		'/^\tclient_max_body_size / s/.*/	client_max_body_size 16G;/'
	# sed -i '/^\tssl_protocols / s/.*/	ssl_protocols TLSv1.2 TLSv1.3;/' '/etc/nginx/nginx.conf'
	# sed -i '/^\tclient_max_body_size / s/.*/	client_max_body_size 16G;/' '/etc/nginx/nginx.conf'

	log 'configuring nginx ...'
	mv '/etc/nginx/http.d/default.conf' '/etc/nginx/http.d/default.conf.orig'
	# the following is from https://docs.nextcloud.com/server/latest/admin_manual/installation/nginx.html
	cat > "/etc/nginx/http.d/$HOSTNAME.$DOMAIN.conf" <<-EOF
		upstream php-handler {
		    #server 127.0.0.1:9000;
		    server unix:/var/run/php-fpm7/php-fpm.sock;
		}

		server {
		    listen 80;
		    listen [::]:80;
		    listen unix:/run/nginx/http.sock;
		    server_name $HOSTNAME.$DOMAIN;

		    # Enforce HTTPS
		    return 301 https://\$server_name\$request_uri;
		}

		server {
		    listen 443      ssl http2;
		    listen [::]:443 ssl http2;
		    listen unix:/run/nginx/https.sock ssl http2 proxy_protocol;
		    server_name $HOSTNAME.$DOMAIN;

		    # Use Mozilla's guidelines for SSL/TLS settings
		    # https://mozilla.github.io/server-side-tls/ssl-config-generator/
		    ssl_certificate     /etc/ssl/nginx/$HOSTNAME.$DOMAIN.crt;
		    ssl_certificate_key /etc/ssl/nginx/$HOSTNAME.$DOMAIN.key;

		    # HSTS settings
		    # WARNING: Only add the preload option once you read about
		    # the consequences in https://hstspreload.org/. This option
		    # will add the domain to a hardcoded list that is shipped
		    # in all major browsers and getting removed from this list
		    # could take several months.
		    #add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;

		    # set max upload size
		    client_max_body_size 512M;
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
		    root /usr/share/webapps/nextcloud;

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

	log 'configuring php7 ...'
	cp '/etc/php7/php-fpm.d/www.conf' '/etc/php7/php-fpm.d/www.conf.orig'
	alter_config '/etc/php7/php-fpm.d/www.conf' \
		'/^user =/ s/.*/user = nginx/' \
		'/^group =/ s/.*/group = www-data/' \
		'/^listen =/ s/.*/listen = \/var\/run\/php-fpm7\/php-fpm.sock/' \
		'/^;listen\.owner =/ s/.*/listen.owner = nginx/' \
		'/^;listen\.group =/ s/.*/listen.group = www-data/' \
		's/^;env/env/' \
		# '/^;chroot =/ s/.*/chroot = \/usr\/share\/webapps\/nextcloud/'
	# sed -i '/^user =/ s/.*/user = nginx/' '/etc/php7/php-fpm.d/www.conf'
	# sed -i '/^group =/ s/.*/group = www-data/' '/etc/php7/php-fpm.d/www.conf'
	# sed -i '/^listen =/ s/.*/listen = \/var\/run\/php-fpm7\/php-fpm.sock/' '/etc/php7/php-fpm.d/www.conf'
	# sed -i '/^;listen\.owner =/ s/.*/listen.owner = nginx/' '/etc/php7/php-fpm.d/www.conf'
	# sed -i '/^;listen\.group =/ s/.*/listen.group = www-data/' '/etc/php7/php-fpm.d/www.conf'
	# sed -i 's/^;env/env/' '/etc/php7/php-fpm.d/www.conf'

	log 'enabling nginx and php7 ...'
	rc-update add nginx default
	rc-update add php-fpm7 default

	log 'creating self signed certificate ...'
	apk add openssl
	mkdir -p '/etc/ssl/nginx'
	openssl req -x509 \
		-nodes \
		-days 365 \
		-newkey rsa:4096 \
		-subj "/CN=$HOSTNAME.$DOMAIN" \
		-keyout /etc/ssl/nginx/$HOSTNAME.$DOMAIN.key \
		-out /etc/ssl/nginx/$HOSTNAME.$DOMAIN.crt

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
	rc-update add clamd default
	rc-update add freshclam default

	log 'downloading clamav database ...'
	freshclam --show-progress --foreground

	log 'installing and enabling "files_antivirus" nextcloud app ...'
	occ app:install 'files_antivirus'

	log 'installing nextcloud apps ...'
	for app in $APPS; do
		log "installing $app ..."
		if [ "$app" = "richdocumentscode" ] && [ "$(arch)" = 'aarch64' ]; then
			occ app:install 'richdocumentscode_arm64'
		else
			occ app:install "$app"
		fi
	done

	# install and configure redis last otherwise the redis server will
	# need to be running to do any operations with `occ`
	log 'installing APCu and redis ...'
	apk add redis php7-pecl-redis redis-openrc php7-pecl-apcu
	
	log 'enabling redis ...'
	rc-update add redis default

	log 'configuring redis ...'
	cp '/etc/redis.conf' '/etc/redis.conf.orig'
	# do not listen on tcp (only listen on local socket)
	alter_config '/etc/redis.conf' \
		'/^port / s/.*/port 0/'
	# sed -i '/^port / s/.*/port 0/' '/etc/redis.conf'
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
	alter_config '/etc/php7/php.ini' \
		'/^session\.save_handler =/ s/.*/session.save_handler = redis/' \
		'/^;session\.save_path =/ s/.*/session.save_path = "\/run\/redis\/redis.sock"/'
	# sed -i '/^session\.save_handler =/ s/.*/session.save_handler = redis/' '/etc/php7/php.ini'
	# sed -i '/^;session\.save_path =/ s/.*/session.save_path = "\/run\/redis\/redis.sock"/' '/etc/php7/php.ini'

	cat >> '/etc/php7/php.ini' <<-EOF
		[redis session management]
		redis.session.locking_enabled=1
		redis.session.lock_retries=-1
		redis.session.lock_wait_time=10000
	EOF

	log 'configuring cron ...'
	rc-update add crond default
	crontab -u nginx - <<-EOF
		*/5  *  *  *  * php -f /usr/share/webapps/nextcloud/cron.php
	EOF

	# it is okay to stop the database now
	log 'stopping postgresql database ...'
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

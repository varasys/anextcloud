#!/bin/sh -eu
# adapted from https://wiki.alpinelinux.org/wiki/Nextcloud

readonly NC='\e[0m'
readonly RED='\e[0;31;1m'
readonly YELLOW='\e[0;33;1m'
readonly BLUE='\e[0;34;1m'
readonly PURPLE='\e[0;35;1m'

log() {
	local readonly msg=$1; shift
	printf "\n%b$msg%b\n" "$BLUE" "$@" "$NC"
}
warn() {
	local readonly msg=$1; shift
	printf "\n%b$msg%b\n" "$YELLOW" "$@" "$NC" >&2
}
error() {
	local readonly msg=$1; shift
	printf "\n%b$msg%b\n" "$RED" "$@" "$NC" >&2
}
prompt() { # does not include newline (so user input is on the same line)
	local readonly msg=$1; shift
	printf "\n%b$msg%b" "$PURPLE" "$@" "$NC" >&2
	local var
	IFS= read -r var
	printf "%s" "$var"
}

if [ $(id -u) -ne 0 ]; then
	log "restarting as root ..."
	exec doas "$0" "$@"
fi

FQDN="${FQDN:-"$(hostname -f)"}"
log "using FQDN: %s" "$FQDN"

apk update
apk upgrade

update_file() { # convenience function to run `sed` inplace with multiple expressions
	local readonly file="$1"
	cp "$file" /tmp/$(basename "$file").orig
	shift
	local exp
	for exp in "$@"; do
		sed -i "$exp" "$file"
	done
	cp "$file" /tmp/$(basename "$file").updated
}

log "installing postgresql ..."
apk add nextcloud-pgsql postgresql14 postgresql14-client
rc-update add postgresql default

PGDATA=/var/lib/postgresql/14/data

log "initializing database ..."
su postgres -c "initdb --data-checksums --encoding=UTF8 --auth-local=trust -D '$PGDATA'"

log 'disabling postgresql TCP access ...'
update_file "$PGDATA/postgresql.conf" \
	"/^#\?listen_addresses = / s/.*/listen_addresses = ''/"

log "starting database ..."
service postgresql start

log "creating database user ..."
psql -U postgres <<EOF
CREATE USER nextcloud;
ALTER ROLE nextcloud CREATEDB;
EOF

log "creating postgresql command wrappers ..."
cat > /usr/local/bin/postgres <<'EOF'
#!/bin/sh

CMD="/usr/bin/$(basename "$0")"
if [ "$(id -un)" != "${POSTGRES_USER:="postgres"}" ]; then
	exec su -s /bin/sh "$POSTGRES_USER" -c "$CMD" "@"
else
	exec "$CMD" "$@"
fi
EOF
chmod +x /usr/local/bin/postgres
ln -s ./postgres /usr/local/bin/initdb
ln -s ./postgres /usr/local/bin/psql
(cd /usr/bin; find . -name 'pg_*' -exec ln -s ./postgres /usr/local/bin/{} ';')


log "installing nextcloud ..."
apk add nextcloud nextcloud-initscript nextcloud-default-apps
rc-update add nextcloud default

log "installing nginx and php ..."
apk add nginx php8-fpm
rc-update add nginx default

log "configuring nginx ..."
[ -f /etc/nginx/http.d/default.conf ] && rm /etc/nginx/http.d/default.conf
cat > /etc/nginx/http.d/nextcloud.conf <<EOF
server {
	listen [::]:80;
	listen 80;
	# listen unix:/run/nginx/http.sock proxy_protocol;
	server_name $FQDN;
	# return 301 https://\$host\$request_uri;
	location '/.well-known/acme-challenge' {
		default_type "text/plain";
		root /var/lib/nginx/html;
	}
	location / {
		return 301 https://\$host\$request_uri;
	}
}

server {
	listen [::]:443 ssl;
	listen 443 ssl;
	server_name $FQDN;

	root /usr/share/webapps/nextcloud;
	index  index.php index.html index.htm;
	disable_symlinks off;

	ssl_certificate      /etc/ssl/nextcloud/cert.pem;
	ssl_certificate_key  /etc/ssl/nextcloud/key.pem;
	ssl_session_timeout  5m;

	#Enable Perfect Forward Secrecy and ciphers without known vulnerabilities
	#Beware! It breaks compatibility with older OS and browsers (e.g. Windows XP, Android 2.x, etc.)
	ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA;
	ssl_prefer_server_ciphers  on;


	location / {
		try_files \$uri \$uri/ /index.html;
	}

	# pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
	location ~ [^/]\.php(/|$) {
		fastcgi_split_path_info ^(.+?\.php)(/.*)$;
		if (!-f \$document_root\$fastcgi_script_name) {
			return 404;
		}
		#fastcgi_pass 127.0.0.1:9000;
		#fastcgi_pass unix:/run/php-fpm/socket;
		fastcgi_pass unix:/run/nextcloud/fastcgi.sock; # From the nextcloud-initscript package
		fastcgi_index index.php;
		include fastcgi.conf;
	}

	# Help pass nextcloud's configuration checks after install:
	# Per https://docs.nextcloud.com/server/22/admin_manual/issues/general_troubleshooting.html#service-discovery
	location ^~ /.well-known/carddav { return 301 /remote.php/dav/; }
	location ^~ /.well-known/caldav { return 301 /remote.php/dav/; }
	location ^~ /.well-known/webfinger { return 301 /index.php/.well-known/webfinger; }
	location ^~ /.well-known/nodeinfo { return 301 /index.php/.well-known/nodeinfo; }
}
EOF

log 'configuring nginx.conf ...'
update_file '/etc/nginx/nginx.conf' \
	'/^\s*client_max_body_size / s/client_max_body_size.*/client_max_body_size 0;/'

log 'configuring php8 upload file size ...'
# https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/big_file_upload_configuration.html
update_file '/etc/php8/php.ini' \
	'/^;\?memory_limit \?=/ s/.*/memory_limit = 1G/' \
	'/^;\?upload_max_filesize \?=/ s/.*/upload_max_filesize = 4G/' \
	'/^;\?post_max_size \?=/ s/.*/post_max_size = 4G/' \
	# '/^;\?max_input_time \?=/ s/.*/max_input_time = 3200/' \
	# '/^;\?max_execution_time \?=/ s/.*/max_execution_time = 3200/' \

log 'configuring php8 opcache ...'
# https://docs.nextcloud.com/server/latest/admin_manual/installation/server_tuning.html
update_file '/etc/php8/php.ini' \
	'/^;\?opcache.enable \?=/ s/.*/opcache.enable = 1/' \
	'/^;\?opcache.interned_strings_buffer \?=/ s/.*/opcache.interned_strings_buffer = 8/' \
	'/^;\?opcache.max_accelerated_files \?=/ s/.*/opcache.max_accelerated_files = 10000/' \
	'/^;\?opcache.memory_consumption \?=/ s/.*/opcache.memory_consumption = 128/' \
	'/^;\?opcache.save_comments \?=/ s/.*/opcache.save_comments = 1/' \
	'/^;\?opcache.revalidate_freq \?=/ s/.*/opcache.revalidate_freq = 1/'

log 'configuring php8 ...'
cp '/etc/php8/php-fpm.d/www.conf' '/etc/php8/php-fpm.d/www.conf.orig'
update_file '/etc/php8/php-fpm.d/www.conf' \
	'/^user =/ s/.*/user = nginx/' \
	'/^group =/ s/.*/group = www-data/' \
	'/^listen =/ s/.*/listen = \/var\/run\/php-fpm7\/php-fpm.sock/' \
	'/^;listen\.owner =/ s/.*/listen.owner = nginx/' \
	'/^;listen\.group =/ s/.*/listen.group = www-data/' \
	's/^;env/env/'

log "creating ssl certificate utility script \`/usr/local/sbin/certman\` ..."
mkdir -p /usr/local/sbin
cat > '/usr/local/sbin/certman' <<-EOF
	#!/bin/sh -e
	# generate ssl private key and request/renew related certificate
	FQDN="\$(hostname -f)"
	KEYDIR="/etc/ssl/nextcloud"
	install -d "\$KEYDIR"
	if [ "\$1" = "--self-signed" ]; then
		printf "generating self signed certificate\n\n"
		command -v openssl >/dev/null || apk add openssl
		openssl req -x509 \
			-nodes \
			-days 365 \
			-newkey ec \
			-pkeyopt ec_paramgen_curve:secp384r1 \
			-subj "/CN=\$FQDN" \
			-keyout "\$KEYDIR/key.pem" \
			-out "\$KEYDIR/cert.pem"
		ln -s './cert.pem' "\$KEYDIR/ca.pem"
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
		ln -fs "../letsencrypt/live/\$FQDN/privkey.pem" "\$KEYDIR/key.pem"
		ln -fs "../letsencrypt/live/\$FQDN/fullchain.pem" "\$KEYDIR/cert.pem"
		ln -fs './cert.pem' "\$KEYDIR/ca.pem"
		# create link to run this script weekly to take care of renewals
		ln -fs "\$(realpath "\$0")" '/etc/periodic/weekly/certman'
	fi
EOF
chmod +x '/usr/local/sbin/certman'

log 'creating self signed cert ...'
certman --self-signed

log "starting nginx ..."
service nginx start
log "starting nextcloud ..."
service nextcloud start

log 'generating admin password ...'
ADMIN_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13)"
echo "$ADMIN_PASS" > "/root/nextcloud_password"

log 'performing initial nextcloud configuration (this may take some time) ...'
occ maintenance:install \
	--database 'pgsql' \
	--database-host '/run/postgresql' \
	--database-name 'nextcloud' \
	--database-user 'nextcloud' \
	--database-pass '' \
	--admin-user 'admin' \
	--admin-pass "$ADMIN_PASS" \
	--data-dir "/var/lib/nextcloud/data"

psql -U postgres <<EOF
ALTER ROLE nextcloud NOCREATEDB;
EOF

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

log 'installing clamav antivirus ...'
apk add clamav clamav-libunrar
rc-update add clamd default
rc-update add freshclam default
service clamd start
service freshclam start

# log 'downloading clamav database ...'
# freshclam --show-progress --foreground

log 'installing and enabling "files_antivirus" nextcloud app ...'
occ app:install 'files_antivirus' || warn 'error: install failed for files_antivirus'
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

log 'installing APCu and redis ...'
apk add redis php8-pecl-redis redis-openrc php8-pecl-apcu
rc-update add redis default

log 'configuring redis ...'
# do not listen on tcp (only listen on local socket)
update_file '/etc/redis.conf' \
	'/^port / s/.*/port 0/'
adduser nginx redis
adduser nextcloud redis

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
update_file '/etc/php8/php.ini' \
	'/^session\.save_handler =/ s/.*/session.save_handler = redis/' \
	'/^;session\.save_path =/ s/.*/session.save_path = "\/run\/redis\/redis.sock"/'

cat >> '/etc/php8/php.ini' <<-EOF

	[redis session management]
	redis.session.locking_enabled=1
	redis.session.lock_retries=-1
	redis.session.lock_wait_time=10000

	; https://github.com/nextcloud/vm/issues/2039#issuecomment-875849079
	apc.enable_cli=1
EOF

service redis start
service nextcloud restart



		#log 'configuring nginx for nextcloud ...'
		#cat > '/etc/nginx/http.d/https.conf' <<-EOF
		#	# adapted from https://docs.nextcloud.com/server/latest/admin_manual/installation/nginx.html
		#	upstream php-handler {
		#	    server unix:/var/run/php-fpm7/php-fpm.sock;
		#	}

		#	server {
		#	    listen 443      ssl http2;
		#	    listen [::]:443 ssl http2;
		#	    listen unix:/run/nginx/https.sock ssl http2 proxy_protocol;
		#	    server_name $FQDN;

		#	    # generated 2021-06-15, Mozilla Guideline v5.6, nginx 1.18.0, OpenSSL 1.1.1k, modern configuration, no HSTS
		#	    # https://ssl-config.mozilla.org/#server=nginx&version=1.18.0&config=modern&openssl=1.1.1k&hsts=false&guideline=5.6
		#	    ssl_certificate /etc/nginx/cert.pem;
		#	    ssl_certificate_key /etc/nginx/key.pem;
		#	    ssl_session_timeout 1d;
		#	    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
		#	    ssl_session_tickets off;

		#	    # modern configuration
		#	    ssl_protocols TLSv1.2 TLSv1.3;
		#	    ssl_prefer_server_ciphers off;

		#	    # OCSP stapling
		#	    ssl_stapling on;
		#	    ssl_stapling_verify on;

		#	    # verify chain of trust of OCSP response using Root CA and Intermediate certs
		#	    ssl_trusted_certificate /etc/nginx/ca.pem;

		#	    # replace with the IP address of your resolver
		#	    resolver 127.0.0.1;

		#	    # set max upload size
		#	    client_max_body_size 4G;
		#	    fastcgi_buffers 64 4K;

		#	    # Enable gzip but do not remove ETag headers
		#	    gzip on;
		#	    gzip_vary on;
		#	    gzip_comp_level 4;
		#	    gzip_min_length 256;
		#	    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
		#	    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

		#	    # Pagespeed is not supported by Nextcloud, so if your server is built
		#	    # with the \`ngx_pagespeed\` module, uncomment this line to disable it.
		#	    #pagespeed off;

		#	    # HTTP response headers borrowed from Nextcloud \`.htaccess\`
		#	    add_header Referrer-Policy                      "no-referrer"   always;
		#	    add_header X-Content-Type-Options               "nosniff"       always;
		#	    add_header X-Download-Options                   "noopen"        always;
		#	    add_header X-Frame-Options                      "SAMEORIGIN"    always;
		#	    add_header X-Permitted-Cross-Domain-Policies    "none"          always;
		#	    add_header X-Robots-Tag                         "none"          always;
		#	    add_header X-XSS-Protection                     "1; mode=block" always;

		#	    # Remove X-Powered-By, which is an information leak
		#	    fastcgi_hide_header X-Powered-By;

		#	    # Path to the root of your installation
		#	    root $APP_DIR;

		#	    # Specify how to handle directories -- specifying \`/index.php\$request_uri\`
		#	    # here as the fallback means that Nginx always exhibits the desired behaviour
		#	    # when a client requests a path that corresponds to a directory that exists
		#	    # on the server. In particular, if that directory contains an index.php file,
		#	    # that file is correctly served; if it doesn't, then the request is passed to
		#	    # the front-end controller. This consistent behaviour means that we don't need
		#	    # to specify custom rules for certain paths (e.g. images and other assets,
		#	    # \`/updater\`, \`/ocm-provider\`, \`/ocs-provider\`), and thus
		#	    # \`try_files \$uri \$uri/ /index.php\$request_uri\`
		#	    # always provides the desired behaviour.
		#	    index index.php index.html /index.php\$request_uri;

		#	    # Rule borrowed from \`.htaccess\` to handle Microsoft DAV clients
		#	    location = / {
		#	        if ( \$http_user_agent ~ ^DavClnt ) {
		#	            return 302 /remote.php/webdav/\$is_args\$args;
		#	        }
		#	    }

		#	    location = /robots.txt {
		#	        allow all;
		#	        log_not_found off;
		#	        access_log off;
		#	    }

		#	    # Make a regex exception for \`/.well-known\` so that clients can still
		#	    # access it despite the existence of the regex rule
		#	    # \`location ~ /(\\.|autotest|...)\` which would otherwise handle requests
		#	    # for \`/.well-known\`.
		#	    location ^~ /.well-known {
		#	        # The rules in this block are an adaptation of the rules
		#	        # in \`.htaccess\` that concern \`/.well-known\`.

		#	        location = /.well-known/carddav { return 301 /remote.php/dav/; }
		#	        location = /.well-known/caldav  { return 301 /remote.php/dav/; }

		#	        location /.well-known/acme-challenge    { try_files \$uri \$uri/ =404; }
		#	        location /.well-known/pki-validation    { try_files \$uri \$uri/ =404; }

		#	        # Let Nextcloud's API for \`/.well-known\` URIs handle all other
		#	        # requests by passing them to the front-end controller.
		#	        return 301 /index.php\$request_uri;
		#	    }

		#	    # Rules borrowed from \`.htaccess\` to hide certain paths from clients
		#	    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
		#	    location ~ ^/(?:\\.|autotest|occ|issue|indie|db_|console)                { return 404; }

		#	    # Ensure this block, which passes PHP files to the PHP process, is above the blocks
		#	    # which handle static assets (as seen below). If this block is not declared first,
		#	    # then Nginx will encounter an infinite rewriting loop when it prepends \`/index.php\`
		#	    # to the URI, resulting in a HTTP 500 error response.
		#	    location ~ \\.php(?:$|/) {
		#	        fastcgi_split_path_info ^(.+?\\.php)(/.*)\$;
		#	        set \$path_info \$fastcgi_path_info;

		#	        try_files \$fastcgi_script_name =404;

		#	        include fastcgi_params;
		#	        fastcgi_param REMOTE_ADDR \$proxy_protocol_addr;
		#	        fastcgi_param REMOTE_PORT \$proxy_protocol_port;
		#	        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
		#	        fastcgi_param PATH_INFO \$path_info;
		#	        fastcgi_param HTTPS on;

		#	        fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
		#	        fastcgi_param front_controller_active true;     # Enable pretty urls
		#	        fastcgi_pass php-handler;

		#	        fastcgi_intercept_errors on;
		#	        fastcgi_request_buffering off;
		#	    }

		#	    location ~ \\.(?:css|js|svg|gif)$ {
		#	        try_files \$uri /index.php\$request_uri;
		#	        expires 6M;         # Cache-Control policy borrowed from \`.htaccess\`
		#	        access_log off;     # Optional: Don't log access to assets
		#	    }

		#	    location ~ \\.woff2?$ {
		#	        try_files \$uri /index.php\$request_uri;
		#	        expires 7d;         # Cache-Control policy borrowed from \`.htaccess\`
		#	        access_log off;     # Optional: Don't log access to assets
		#	    }

		#	    # Rule borrowed from \`.htaccess\`
		#	    location /remote {
		#	        return 301 /remote.php\$request_uri;
		#	    }

		#	    location / {
		#	        try_files \$uri \$uri/ /index.php\$request_uri;
		#	    }
		#	}
		#EOF



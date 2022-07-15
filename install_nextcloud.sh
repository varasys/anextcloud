#!/bin/sh -eu
# adapted from https://wiki.alpinelinux.org/wiki/Nextcloud

readonly NC='\e[0m'
readonly RED='\e[0;31;1m'
readonly YELLOW='\e[0;33;1m'
readonly BLUE='\e[0;34;1m'
readonly PURPLE='\e[0;35;1m'

log() {
	msg="$1"; shift
	printf "\n%b$msg%b\n" "$BLUE" "$@" "$NC"
}
doc() { # save important information to an installation log file
	log "$@"
	msg="$1"; shift
	# shellcheck disable=SC2059
	printf "$msg\n" "$@" >> "$DOC_FILE"
}
warn() {
	msg="$1"; shift
	printf "\n%b$msg%b\n" "$YELLOW" "$@" "$NC" >&2
}
error() {
	msg="$1"; shift
	printf "\n%b$msg%b\n" "$RED" "$@" "$NC" >&2
}
prompt() { # does not include newline (so user input is on the same line)
	msg="$1"; shift
	printf "\n%b$msg%b" "$PURPLE" "$@" "$NC" >&2
	IFS= read -r var
	printf "%s" "$var"
}

update_file() { # convenience function to run `sed` inplace with multiple expressions
	file="$1"
	shift
	cp "$file" "$file.orig"
	for exp in "$@"; do
		sed -i "$exp" "$file"
	done
}

if [ "$(id -u)" -ne 0 ]; then
	log "restarting as root ..."
	exec doas "$0" "$@"
fi

DOC_FILE="$HOME/nextcloud.txt"
doc 'nextcloud installation on %s\n' "$(date)"
FQDN="${FQDN:-"$(hostname -f)"}"
doc 'FQDN: %s' "$FQDN"
PG_VERSION="14"

apk update
apk upgrade

log "installing postgresql ..."
apk add nextcloud-pgsql postgresql$PG_VERSION postgresql$PG_VERSION-client
rc-update add postgresql default

PGDATA="/var/lib/postgresql/$PG_VERSION/data"
doc 'PGDATA: %s' "$PGDATA"

if [ ! -d "$PGDATA" ]; then
	log "initializing database ..."
	su postgres -c "initdb --encoding=UTF8 --auth=reject --auth-local=peer -D '$PGDATA'"

	log 'disabling postgresql TCP access ...'
	update_file "$PGDATA/postgresql.conf" \
		"/^#\?listen_addresses = / s/.*/listen_addresses = ''/"
fi
doc 'postgresql config: %s' "$PGDATA/postgresql.conf"

log "starting database ..."
service postgresql start

log "creating database user ..."
su postgres -c psql <<EOF
BEGIN;
CREATE USER nextcloud;
END;
ALTER ROLE nextcloud CREATEDB;
EOF
doc 'postgresql user: nextcloud'
doc 'postgresql password: unset since socket authentication is based on "peer"'

# log "installing unbound dns resolver ..." # for nginx resolver
# apk add unbound
# rc-update add unbound default
# service unbound start

log "installing nextcloud ..."
apk add nextcloud nextcloud-initscript nextcloud-default-apps
rc-update add nextcloud default

log "installing nginx and php ..."
apk add nginx php8-fpm php8-opcache php8-pecl-imagick
rc-update add nginx default

log "configuring nginx http ..."
rm -f '/etc/nginx/http.d/default.conf'
cat > '/etc/nginx/http.d/http.conf' <<EOF
server {
	listen 80 http2;
	listen [::]:80 http2;
	listen unix:/var/run/nginx/http.sock http2;
	server_name $FQDN;

	server_tokens off;

	location '/.well-known/acme-challenge' {
		default_type "text/plain";
		root /var/lib/nginx/html;
	}

	location / {
		return 301 https://\$host\$request_uri;
	}
}
EOF
service nginx start

log "creating ssl certificate utility script \`/usr/local/sbin/certman\` ..."
apk add openssl
install -d "/usr/local/sbin"
cat > '/usr/local/sbin/certman' <<EOF
#!/bin/sh -e
# generate ssl private key and request/renew related certificate
FQDN="\$(hostname -f)"
KEYDIR="/etc/ssl/nextcloud"
install -d "\$KEYDIR"
if [ "\$1" = "--self-signed" ] || [ ! -d "/etc/letsencrypt" ]; then
	printf "generating self signed certificate\n\n"
	command -v openssl >/dev/null || apk add openssl
	openssl req -x509 \\
		-nodes \\
		-days 365 \\
		-newkey ec \\
		-pkeyopt ec_paramgen_curve:secp384r1 \\
		-subj "/CN=\$FQDN" \\
		-keyout "\$KEYDIR/key.pem" \\
		-out "\$KEYDIR/cert.pem"
	ln -fs './cert.pem' "\$KEYDIR/ca.pem"
elif [ -d "/etc/letsencrypt/\$FQDN" ]; then
	printf "renewing existing letsencrypt certificate\n\n"
	command -v certbot >/dev/null || apk add certbot
	certbot renew --post-hook "rc-service nginx reload"
else # request a new letsencrypt certificate
	printf "requesting new letsencrypt certificate\n\n"
	command -v certbot >/dev/null || apk add certbot
	certbot certonly --domain "\$FQDN" \\
		--key-type ecdsa \\
		--elliptic-curve secp384r1 \\
		--webroot \\
		--webroot-path="/var/lib/nginx/html" \\
		--email "admin@\$FQDN" \\
		--agree-tos \\
		--non-interactive
	ln -fs "../letsencrypt/live/\$FQDN/privkey.pem" "\$KEYDIR/key.pem"
	ln -fs "../letsencrypt/live/\$FQDN/fullchain.pem" "\$KEYDIR/cert.pem"
	ln -fs './cert.pem' "\$KEYDIR/ca.pem"
	# create link to run this script weekly to take care of renewals
	ln -fs "\$(realpath "\$0")" '/etc/periodic/weekly/certman'
fi
EOF
chmod +x '/usr/local/sbin/certman'

if [ -f '/etc/ssl/nextcloud/cert.pem' ]; then
	log 'using existing x509 certificate at /etc/ssl/nextcloud/cert.pem'
else
	log 'creating x509 certificate ...'
	certman
fi
doc 'ssl cert: %s' "/etc/ssl/nextcloud/cert.pem"
doc 'ssl key: %s' "/etc/ssl/nextcloud/key.pem"

log "configuring nginx https ..."
cat > '/etc/nginx/http.d/https.conf' <<EOF
# adapted from https://docs.nextcloud.com/server/latest/admin_manual/installation/nginx.html
upstream php-handler {
	server unix:/run/nextcloud/fastcgi.sock; # From the nextcloud-initscript package
}

# Set the \`immutable\` cache control options only for assets with a cache busting \`v\` argument
map \$arg_v \$asset_immutable {
	"" "";
	default "immutable";
}

server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	listen unix:/var/run/nginx/https.sock ssl http2;
	server_name $FQDN;

	root /usr/share/webapps/nextcloud;

	# generated 2021-06-15, Mozilla Guideline v5.6, nginx 1.18.0, OpenSSL 1.1.1k, modern configuration, no HSTS
	# https://ssl-config.mozilla.org/#server=nginx&version=1.18.0&config=modern&openssl=1.1.1k&hsts=false&guideline=5.6
	ssl_certificate /etc/ssl/nextcloud/cert.pem;
	ssl_certificate_key /etc/ssl/nextcloud/key.pem;
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
	ssl_trusted_certificate /etc/ssl/nextcloud/ca.pem;

	# # use local dns resolver
	# resolver 127.0.0.1;

	# Prevent nginx HTTP Server Detection
	server_tokens off;

	# set max upload size and increase upload timeout:
	client_max_body_size 512M;
	client_body_timeout 300s;
	fastcgi_buffers 64 4K;
	fastcgi_read_timeout 3600s;

	# Enable gzip but do not remove ETag headers
	gzip on;
	gzip_vary on;
	gzip_comp_level 4;
	gzip_min_length 256;
	gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
	gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/wasm application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

	# Pagespeed is not supported by Nextcloud, so if your server is built
	# with the \`ngx_pagespeed\` module, uncomment this line to disable it.
	#pagespeed off;

	# The settings allows you to optimize the HTTP2 bandwitdth.
	# See https://blog.cloudflare.com/delivering-http-2-upload-speed-improvements/
	# for tunning hints
	client_body_buffer_size 512k;

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
		# Required for legacy support (remove this to allow /phpinfo.php for debugging)
		rewrite ^/(?!index|remote|public|cron|core\\/ajax\\/update|status|ocs\\/v[12]|updater\\/.+|oc[ms]-provider\\/.+|.+\\/richdocumentscode\\/proxy) /index.php\$request_uri;

		fastcgi_split_path_info ^(.+?\\.php)(/.*)\$;
		set \$path_info \$fastcgi_path_info;

		try_files \$fastcgi_script_name =404;

		include fastcgi_params;
		fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
		fastcgi_param PATH_INFO \$path_info;
		fastcgi_param HTTPS on;

		fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
		fastcgi_param front_controller_active true;     # Enable pretty urls
		fastcgi_pass php-handler;

		fastcgi_intercept_errors on;
		fastcgi_request_buffering off;

		fastcgi_max_temp_file_size 0;

		# fastcgi_param REMOTE_ADDR \$proxy_protocol_addr;
		# fastcgi_param REMOTE_PORT \$proxy_protocol_port;
	}

	location ~ \\.(?:css|js|svg|gif|png|jpg|ico|wasm|tflite|map)$ {
		try_files \$uri /index.php\$request_uri;
		add_header Cache-Control "public, max-age=15778463, \$asset_immutable";
		access_log off;     # Optional: Don't log access to assets

		location ~ \\.wasm\$ {
			default_type application/wasm;
		}
	}

	location ~ \\.woff2?\$ {
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
doc 'nginx root: /usr/share/webapps/nextcloud'

log 'deleting default php-fpm.d/www.conf default config ...'
rm -f '/etc/php8/php-fpm.d/www.conf' # the default file

log "starting nginx ..."
service nginx restart

log "configuring php memory limit ..."
update_file '/etc/php8/php.ini' \
	'/^memory_limit = / s/.*/memory_limit = 512M/'

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

su postgres -c psql <<EOF
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

#log 'installing clamav antivirus ...'
#apk add clamav clamav-libunrar
#rc-update add clamd default
#rc-update add freshclam default
#service freshclam start
#service clamd start

#log 'installing and enabling "files_antivirus" nextcloud app ...'
occ app:install 'files_antivirus'
occ config:import <<-EOF
	{
		"apps": {
			"files_antivirus": {
				"av_mode": "daemon",
				"av_host": "clamav.${FQDN#*.}",
				"av_port": "3310"
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
	'/^port / s/.*/port 0/' \
	'/^unixsocketperm / s/.*/unixsocketperm 777/' \
	'/^loglevel / s/.*/loglevel debug/'
adduser nginx redis
adduser nextcloud redis

service redis start

log 'configuring redis caching ...'
occ config:import <<EOF
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

cat >> '/etc/php8/php.ini' <<-EOF

	[redis session management]
	redis.session.locking_enabled=1
	redis.session.lock_retries=-1
	redis.session.lock_wait_time=10000

	apc.enable_cli = 1
EOF

update_file '/etc/php8/php-fpm.d/nextcloud.conf' \
	'/^php_admin_value\[session.save_path\] = / s/.*/php_admin_value[session.save_path] = \/run\/redis\/redis.sock\nphp_admin_value[session.save_handler] = redis/'

service nextcloud restart
service nginx restart

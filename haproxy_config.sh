#!/usr/bin/env sh
set -e

# define colors - change to empty strings if you don't want colors
NC='\e[0m'
RED='\e[0;31;1m'
YELLOW='\e[0;33;1m'
BLUE='\e[0;34;1m'
PURPLE='\e[0;35;1m'

# define logging utility functions
log() {
	msg="$1"; shift
	printf "%b$msg%b\n" "$BLUE" "$@" "$NC" >&2
}
warn() {
	msg="$1"; shift
	printf "%b$msg%b\n" "$YELLOW" "$@" "$NC" >&2
}
error() {
	msg="$1"; shift
	printf "%b$msg%b\n" "$RED" "$@" "$NC" >&2
}
prompt() { # does not include newline (so user input is on the same line)
	msg="$1"; shift
	printf "%b$msg%b" "$PURPLE" "$@" "$NC" >&2
	IFS= read -r var
	printf "%s" "$var"
}

PREFIX="${PREFIX:="/etc/haproxy"}"
log 'using prefix: %s' "$PREFIX"

ROOT="$PREFIX/haproxy.cfg"

if [ -f "$ROOT" ]; then
	warn "backing up '$ROOT' to '$ROOT.orig' ..."
	cp "$ROOT" "$ROOT.orig"
fi

if [ ! -d "$ROOT" ]; then
	warn "creating '$ROOT' directory ..."
	mkdir -p "$ROOT"
else
	log "'$ROOT' directory already exists"
fi

if [ ! -f "$ROOT/10-haproxy.cfg" ]; then
	warn "creating '$ROOT/10-haproxy.cfg' file ..."
	cat > "$ROOT/10-haproxy.cfg" <<-EOF
		global
		    log stdout format raw local0 info
		    chroot /run/haproxy
		    user haproxy
		    group haproxy

		defaults
		    log global
		    timeout connect 30s
		    timeout client  50s
		    timeout server  50s

		frontend fe_http
		    bind :80
		    mode http
		    option httplog
		    http-request redirect scheme https unless { path_beg -i /.well-known/acme-challenge/ }
		    use_backend %[req.hdr(Host),lower]-http

		frontend fe_https
		    bind :443
		    mode tcp
		    option tcplog
		    tcp-request inspect-delay 5s
		    tcp-request content accept if { req_ssl_hello_type 1 }
		    use_backend %[req_ssl_sni,lower]-https

	EOF
else
	log "'$ROOT/10-haproxy.cfg' file already exists"
fi

if [ $# -eq 0 ]; then
	log 'using system FQDN'
	HOSTNAME="$(hostname -s)"
	DOMAIN="$(hostname -d)"
	[ -z "$HOSTNAME" ] && { log 'error: invalid/missing hostname'; exit 1; }
	[ -z "$DOMAIN" ] && { log 'error: invalid/missing domain'; exit 1; }
	set "$HOSTNAME.$DOMAIN"
fi

for site in "$@"; do
	if [ ! -f "$ROOT/50-$site.cfg" ]; then
		warn "creating '$ROOT/50-$site.cfg' file ..."
		cat > "$ROOT/50-$site.cfg" <<-EOF
			backend $site-http
			    mode http
			    option httplog
			    server server1 /$site/http.sock send-proxy-v2

			backend $site-https
			    mode tcp
			    option tcplog
			    option ssl-hello-chk
			    server server1 /$site/https.sock send-proxy-v2 check

		EOF
	else
		error "'$ROOT/50-$site.cfg' file already exists"
	fi
done

cat <<-EOF
	$(printf '%b' "$PURPLE")
	Finished haproxy configuration.

	This configuration is based on using a directory instead of a single
	configuration file. To start haproxy pass the \`-f $ROOT\` command
	line argument so all of the files in the configuration directory
	will be used (in lexical order).

	Run \`systemctl restart haproxy.service\` to restart haproxy or
	\`systemctl enable --now haproxy.service\` to start haproxy, and autostart
	at boot.

	$(printf '%b' "$NC")
EOF

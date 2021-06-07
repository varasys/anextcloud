#!/usr/bin/env sh
set -e # fail fast

FQDN="${1:-"${FQDN:="${HOSTNAME:="$(hostname -s)"}.${DOMAIN:="$(hostname -d)"}"}"}"

printf 'creating self signed certificate for: "%s" ...\n\n' "$FQDN"
openssl req -x509 \
	-nodes \
	-days 365 \
	-newkey ec \
	-pkeyopt ec_paramgen_curve:prime256v1 \
	-out "$FQDN.crt" \
	-keyout "$FQDN.key"
chmod 600 "$FQDN.key"

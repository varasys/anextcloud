#!/bin/sh
set -e # fail fast

FQDN="${1:-"${FQDN:="$(hostname -f)"}"}"

printf 'creating self signed certificate for: "%s" ...\n\n' "$FQDN"
openssl req -x509 \
	-nodes \
	-days "${DAYS:-"365"}" \
	-newkey ec \
	-pkeyopt ec_paramgen_curve:secp384r1 \
	-subj "/CN=$FQDN" \
	-keyout "$FQDN.key" \
	-out "$FQDN.crt"
chmod 600 "$FQDN.key"

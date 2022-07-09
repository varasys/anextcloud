#!/bin/sh
set -e # fail fast

FQDN="${1:-"${FQDN:="$(hostname -f)"}"}"
OUTDIR="/etc/ssl/nextcloud"

command -v openssl >/dev/null || apk add openssl
install -d "$OUTDIR"

printf 'creating self signed certificate for: "%s" ...\n\n' "$FQDN"
openssl req -x509 \
	-nodes \
	-days "${DAYS:-"365"}" \
	-newkey ec \
	-pkeyopt ec_paramgen_curve:secp384r1 \
	-subj "/CN=$FQDN" \
	-keyout "$OUTDIR/key.pem" \
	-out "$OUTDIR/cert.pem"
chmod 600 "$OUTDIR/key.pem"

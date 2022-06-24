# Nextcloud Installer

## NOTE
the `install_nextcloud.sh` script uses the native alpine nextcloud package and is better than the other installer.

This project aims to create a reproducible Nextcloud installation in an Alpine Linux filesystem based container run with `systemd-nspawn` and the following configuration:

* alpine linux container OS
* PostgreSQL database
* Nginx webserver
* clamav antivirus scanner
* redis cache
* cron scheduler run Nextcloud 'cron.php' script

This script should create a reproducible Nextcloud installation on any OS which has available `systemd-nspawn`.

## Quick Start

Edit the 'config.json' file to meet your requirements, and run the 'install.sh' script as root.

## Description

## Security

The Alpine Linux and Nextcloud GPG public keys are embedded in the script to ensure valid versions of Alpine Linux and Nextcloud are downloaded from the Internet, or used from the cache.

## Utility Scripts

The following utility scripts are included for convenience _inside the container_. Soft links to these scripts are created in the '/root' directory mostly for a reference to help remember they exist.

* */usr/local/sbin/pg_dump*
* */usr/local/sbin/psql*
* */usr/local/bin/nclog*
* */usr/local/sbin/occ*

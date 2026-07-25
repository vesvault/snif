#!/bin/bash

#/**************************************************************************
# *     _________
# *    /````````_\                  S N I F ~ e2e TLS trust for IoT
# *   /\     , / O\      ___
# *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
# *  | |     |  ``/`````\___/       e2e TLS CA Proxy
# *  | |     | . | <"""""""~~
# *  |  \___/ ``  \________/        https://snif.host
# *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
# *    \_________/                  Jim Zubov <jz@vesvault.com>
# *
# *
# * Apache License, Version 2.0
# * You may use, copy, modify, merge, publish, distribute and/or sell copies
# * of the Software under the terms of the Apache License, Version 2.0, a copy
# * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
# *
# * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# * CONDITIONS OF ANY KIND, either express or implied.
# *
# **************************************************************************/

# Container entrypoint for the SNIF Relay: brings up the CA proxy (Apache +
# mod_php), the ACME issuance daemon (snif-certd), and the relay daemon (snifd).
# See docker/README-relay.md for configuration and DNS prerequisites.

set -e

# ---- configuration (matches /etc/snif/snif.conf and ca-proxy) ---------------
SNIF_CA_PROXY=/var/lib/snif/ca-proxy
TEMPLATE=/opt/snif/ca-proxy

# Base domain for issued device hostnames AND the HTTPS init origin. Devices are
# named snif-XXXX-YYYY.$SNIF_RELAY_DOMAIN ; the init URL is
# https://$SNIF_RELAY_DOMAIN:$SNIF_INIT_PORT/ . REQUIRED.
: ${SNIF_RELAY_DOMAIN:?set SNIF_RELAY_DOMAIN to the base domain, e.g. snif.example.com}

# Space-separated relay fwd ports where public TLS clients connect (SNI-routed
# to connectors). 443 is the usual one.
: ${SNIF_RELAY_PORTS:=443}

# HTTPS init / authorization origin port (the snifd -a URL).
: ${SNIF_INIT_PORT:=4443}

# DoS abuse-detection sensitivity for the relay (snifd -t).
: ${SNIF_RELAY_ABUSE:=64}

# Optional: static SNI map entries for the relay (snifd -m), space-separated.
: ${SNIF_RELAY_MAP:=}

# Optional TLS cert/key for the init origin. If unset, a self-signed pair is
# generated (fine for a first bring-up, but device connectors will reject it
# over TLS until you supply a publicly trusted cert for $SNIF_RELAY_DOMAIN).
: ${SNIF_INIT_CERT:=}
: ${SNIF_INIT_KEY:=}

# Set to 1 to issue against the Let's Encrypt STAGING environment (untrusted
# certs, high rate limits) while you shake out DNS. Default: production.
: ${SNIF_LE_STAGING:=0}

log() { echo "*** SNIF relay: $*"; }

# ---- seed the persistent volume from the image template on first boot -------
if [ ! -d "${SNIF_CA_PROXY}/public_html" ]; then
    log "seeding ${SNIF_CA_PROXY} from image template"
    mkdir -p "${SNIF_CA_PROXY}"
    cp -a "${TEMPLATE}/." "${SNIF_CA_PROXY}/"
fi

# Runtime state directories (idempotent; mirrors ca-proxy/mkdirs + Makefile).
for d in csr cfg auth crt arc var apns log etc; do
    [ -d "${SNIF_CA_PROXY}/${d}" ] || mkdir -m 02775 "${SNIF_CA_PROXY}/${d}"
done

# The issuance control FIFO: written by the PHP endpoints (as www-data, added
# to the snif group) and read by snif-certd (as snif), so it is group writable.
# The optional snifd-in/snifd-out-apnsd pipes are the APNS integration; we do
# not run snif-apnsd here, and an unread push pipe can stall the relay, so we
# deliberately do not create them (snif-relay skips them when absent).
[ -p "${SNIF_CA_PROXY}/var/snif-certd.ctl" ] || mkfifo -m 0660 "${SNIF_CA_PROXY}/var/snif-certd.ctl"

# The catch-all base domain that issued device names live under. The init
# origin (snif-auth.php) reads this same file keyed by the request Host header,
# so a device dialing https://$SNIF_RELAY_DOMAIN:$SNIF_INIT_PORT/ resolves here.
echo "${SNIF_RELAY_DOMAIN}" > "${SNIF_CA_PROXY}/etc/${SNIF_RELAY_DOMAIN}.domains"

# The authorization URL advertised to connectors (X-SNIF-AuthUrl): this relay's
# own init origin, not the public snif.xyz one. snif-cert.php reads
# etc/<base>.authurl per the standard per-domain config convention.
echo "https://${SNIF_RELAY_DOMAIN}:${SNIF_INIT_PORT}/" > "${SNIF_CA_PROXY}/etc/${SNIF_RELAY_DOMAIN}.authurl"

# Let's Encrypt account key, generated once and reused for all issuance.
if [ ! -s "${SNIF_CA_PROXY}/etc/account.key" ]; then
    log "generating a Let's Encrypt account key"
    openssl genrsa -out "${SNIF_CA_PROXY}/etc/account.key" 4096 2>/dev/null
fi

chown -R snif:snif "${SNIF_CA_PROXY}"
chmod 0660 "${SNIF_CA_PROXY}"/var/*.ctl

# ---- init-origin TLS cert (for https://$SNIF_RELAY_DOMAIN:$SNIF_INIT_PORT/) --
INIT_CRT=/etc/snif/init.crt
INIT_KEY=/etc/snif/init.key
mkdir -p /etc/snif
if [ -n "${SNIF_INIT_CERT}" ] && [ -n "${SNIF_INIT_KEY}" ]; then
    cp "${SNIF_INIT_CERT}" "${INIT_CRT}"
    cp "${SNIF_INIT_KEY}" "${INIT_KEY}"
elif [ ! -s "${INIT_CRT}" ]; then
    log "no SNIF_INIT_CERT supplied — generating a SELF-SIGNED init cert for ${SNIF_RELAY_DOMAIN}"
    log "  device connectors will reject it until you provide a trusted cert (see README-relay.md)"
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 \
        -keyout "${INIT_KEY}" -out "${INIT_CRT}" \
        -subj "/CN=${SNIF_RELAY_DOMAIN}" \
        -addext "subjectAltName=DNS:${SNIF_RELAY_DOMAIN}" 2>/dev/null
fi

# ---- /etc/snif/snif.conf (read by snif-relay; /etc/snif.conf by certd) ------
cat > /etc/snif/snif.conf <<EOF
# Generated by snif-relay-entrypoint from the container environment.
SNIF_CA_PROXY=${SNIF_CA_PROXY}
SNIF_RELAY_PORTS="${SNIF_RELAY_PORTS}"
SNIF_RELAY_ABUSE=${SNIF_RELAY_ABUSE}
SNIF_RELAY_MAP="${SNIF_RELAY_MAP}"
EOF
ln -sf /etc/snif/snif.conf /etc/snif.conf

# Opt-in Let's Encrypt staging: applied to the runtime copy of snif-certd only,
# never to the source in the repo.
if [ "${SNIF_LE_STAGING}" = "1" ]; then
    log "issuing against Let's Encrypt STAGING (certs will NOT be publicly trusted)"
    sed -i 's/^\$Live = 1;/$Live = 0;/' /usr/bin/snif-certd
fi

# ---- Apache (CA proxy web API) ----------------------------------------------
# www-data needs to write the shared CA proxy state (cfg/csr/auth + the certd
# FIFO), so put it in the snif group.
usermod -aG snif www-data >/dev/null 2>&1 || true

a2enmod rewrite headers ssl php8.4 >/dev/null 2>&1 || a2enmod rewrite headers ssl php >/dev/null 2>&1 || true
a2dissite 000-default default-ssl >/dev/null 2>&1 || true

cat > /etc/apache2/ports.conf <<EOF
Listen 80
Listen ${SNIF_INIT_PORT}
EOF

cat > /etc/apache2/sites-available/snif-relay.conf <<EOF
# :80 — catch-all for device hostnames: HTTP-01 ACME challenges, the plaintext
# cert API, and the "nothing to see here" landing page.
<VirtualHost *:80>
    ServerName ${SNIF_RELAY_DOMAIN}
    ServerAlias *.${SNIF_RELAY_DOMAIN}
    DocumentRoot ${SNIF_CA_PROXY}/public_html
    <Directory ${SNIF_CA_PROXY}/public_html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

# :${SNIF_INIT_PORT} — HTTPS init / authorization origin (snifd -a target).
<VirtualHost *:${SNIF_INIT_PORT}>
    ServerName ${SNIF_RELAY_DOMAIN}
    DocumentRoot ${SNIF_CA_PROXY}/secure_html
    SSLEngine on
    SSLCertificateFile ${INIT_CRT}
    SSLCertificateKeyFile ${INIT_KEY}
    <Directory ${SNIF_CA_PROXY}/secure_html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
a2ensite snif-relay >/dev/null 2>&1 || true

# ---- process supervision ----------------------------------------------------
# One container runs three long-lived processes that share the CA proxy dir.
# snifd (the relay) is the foreground process; if it exits, the container stops.
export APACHE_RUN_USER=www-data APACHE_RUN_GROUP=www-data
export APACHE_PID_FILE=/var/run/apache2/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2 APACHE_LOCK_DIR=/var/lock/apache2
export APACHE_LOG_DIR=/var/log/apache2
mkdir -p "${APACHE_RUN_DIR}" "${APACHE_LOCK_DIR}"

CERTD_PID=""
APACHE_PID=""
shutdown() {
    log "shutting down"
    [ -n "${APACHE_PID}" ] && kill "${APACHE_PID}" 2>/dev/null || true
    [ -n "${CERTD_PID}" ]  && kill "${CERTD_PID}"  2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

log "starting snif-certd (ACME issuance)"
gosu snif /usr/bin/snif-certd &
CERTD_PID=$!

log "starting Apache CA proxy on :80 and :${SNIF_INIT_PORT}"
apache2ctl -D FOREGROUND &
APACHE_PID=$!

log "starting relay: snifd on control :7123, fwd ports ${SNIF_RELAY_PORTS}"
# snifd binds the fwd ports (443 etc.) — Docker's default capability set
# includes NET_BIND_SERVICE, so root in the container binds them directly.
/usr/bin/snif-relay &
RELAY_PID=$!

# Wait for any of the three to exit; if one dies, tear the whole container down
# so the orchestrator restarts a clean stack.
wait -n "${CERTD_PID}" "${APACHE_PID}" "${RELAY_PID}"
log "a component exited — stopping"
shutdown

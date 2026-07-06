#!/bin/sh

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

# Container entrypoint for the SNIF Connector.
# The variables match /etc/snif/snif.conf, see docker/README.md

: ${SNIF_CONN_DIR:=/etc/snif}
: ${SNIF_CONN_CRT:=${SNIF_CONN_DIR}/snif.crt}
: ${SNIF_CONN_KEY:=${SNIF_CONN_DIR}/snif.key}
: ${SNIF_CONN_INITURL:=https://snif.snif.xyz:4443/}
: ${SNIF_CONN_PORTS:=7357:^}
: ${SNIF_INIT_RETRY:=30}

# Fix the ownership of a fresh named volume, then drop root
if [ "`id -u`" = "0" ]
then
    mkdir -p ${SNIF_CONN_DIR}
    chown -R snif:snif ${SNIF_CONN_DIR}
    exec su-exec snif "$0" "$@"
fi

umask 0027

SNIF_ARGS="-c ${SNIF_CONN_CRT} -k ${SNIF_CONN_KEY} -a ${SNIF_CONN_INITURL}"

[ -n "${SNIF_CONN_APIURL}" ] && SNIF_ARGS="${SNIF_ARGS} -u ${SNIF_CONN_APIURL}"

if [ -n "${SNIF_CONN_HOSTNAME}" ]
then
    SNIF_ARGS="${SNIF_ARGS} -r ${SNIF_CONN_HOSTNAME}"
else
    SNIF_ARGS="${SNIF_ARGS} -P"
fi

trap 'exit 0' TERM INT

# Single-shot initialization until the cert is issued; each attempt re-prints
# the authorization URL so it stays at the tail of `docker logs`
while :
do
    OUT=`snifd ${SNIF_ARGS}` && break
    echo "${OUT}"
    echo "*** SNIF: waiting for authorization, retrying in ${SNIF_INIT_RETRY}s ***"
    sleep ${SNIF_INIT_RETRY} &
    wait $!
done

SNIF_HOST=`echo "${OUT}" | tail -1`
echo "${SNIF_HOST}" > ${SNIF_CONN_DIR}/hostname
echo "*** SNIF hostname: ${SNIF_HOST} ***"

exec snifd -d ${SNIF_ARGS} ${SNIF_CONN_PORTS}

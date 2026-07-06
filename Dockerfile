#**************************************************************************
#     _________
#    /````````_\                  S N I F ~ e2e TLS trust for IoT
#   /\     , / O\      ___
#  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
#  | |     |  ``/`````\___/       e2e TLS CA Proxy
#  | |     | . | <"""""""~~
#  |  \___/ ``  \________/        https://snif.host
#   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
#    \_________/                  Jim Zubov <jz@vesvault.com>
#
#
# Apache License, Version 2.0
# You may use, copy, modify, merge, publish, distribute and/or sell copies
# of the Software under the terms of the Apache License, Version 2.0, a copy
# of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
#
# This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
#
#**************************************************************************

# SNIF Connector container image
# See docker/README.md for usage

FROM alpine:3.22 AS build
RUN apk add --no-cache build-base openssl-dev curl-dev
COPY . /src
WORKDIR /src
RUN ./configure --disable-shared && make && strip snifd/snifd

FROM alpine:3.22
RUN apk add --no-cache libssl3 libcrypto3 libcurl ca-certificates su-exec \
    && adduser -D -H -u 909 snif
COPY --from=build /src/COPYING /src/NOTICE /usr/share/licenses/snif/
COPY --from=build /src/snifd/snifd /usr/bin/snifd
COPY --chmod=755 docker/snif-entrypoint.sh /usr/bin/snif-entrypoint

LABEL org.opencontainers.image.title="SNIF Connector"
LABEL org.opencontainers.image.description="e2e TLS trust for devices behind NAT: a publicly trusted TLS hostname with the private key never leaving this container"
LABEL org.opencontainers.image.url="https://snif.host"
LABEL org.opencontainers.image.source="https://github.com/vesvault/snif"
LABEL org.opencontainers.image.licenses="Apache-2.0"

VOLUME /etc/snif
ENTRYPOINT ["snif-entrypoint"]

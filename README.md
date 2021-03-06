```
/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 **************************************************************************/
```


SUMMARY:

SNIF enables anonymous end-to-end public trust TLS communications between apps
through a designated SNIF relay. By providing TLS public trust on a full
end-to-end level, SNIF creates a peer-to-peer app-level VPN, eliminating the
middle-man and any corresponding ability to intercept, monitor or read the
private communication.

Any app on any device can utilize a designated SNIF relay to allow any other
app on any device to directly communicate with the SNIF enabled app via a
trusted, certificated and anonymous host name using full end-to-end TLS
encryption.



# HOW IT WORKS:

The private key is generated locally by the SNIF connector and never leaves
the device.

The connector sends a CSR to the CA proxy on the SNIF relay server. The proxy
acquires an X.509 certificate and feeds it back to the device.

Having the certificate and the private key, the connector is now capable of
terminating TLS traffic. Incoming TLS connections to the device's hostname
come to the SNIF relay, which uses SNI record to identify the destination
device and forward the TLS TCP socket traffic through the matching connector.

An IoT device can run snifd connector as a separate process that forwards
incoming TLS connections to local ports, either unsecure TCP with TLS being
terminated by snifd, or TLS being terminated by the listening app using the
certificate and the private key shared with snifd.

In more advanced setups SNIF connector can be integrated directly with the
app that serves incoming connections on the device.

From the client's point of view, a TLS connection to the hostname of the
SNIF enabled device or app works same way as a TLS connection to a trusted
server.

Any potential attempts of malicious actions by any SNIF relay are easily
detectable through the public TLS certificate records.

To avoid public exposure of the unique SNIF hostname through the public CA
records, the CA proxy can issue a wildcard certificate to a unique subdomain.
The actual hostname will be a specific host within the certificate's subdomain
that is not listed on the public records.



# INITIALIZING THE TLS CERTIFICATE:
```
                   DNS: *.snif.xyz
                         |               (no public IP or DNS hostname)
                         v
                    SNIF Relay                     IoT Device
                +----------------+     +--------------------------------+
                |                |     | Generate a Private Key         |
                |                |     | (never leaves the device)      |
Certificate     | snif-cert:     |     |                                |
 Authority      |                <-----< Request a permanent hostname   |
+---------+     |                >-----> host1.snif.xyz                 |
|         |     |                |     |                                |
|     CSR <-----< PKCS#10 CSR    <-----< PKCS#10 CSR for host1.snif.xyz |
|  Verify <-----> host1.snif.xyz |     |                                |
|   Issue >-----> X.509 cert     >-----> X.509 cert for host1.snif.xyz  |
|         |     |                |     |                                |
+---------+     +----------------+     +--------------------------------+
```


# ACCEPTING TLS CONNECTIONS:
```
                   DNS: *.snif.xyz
                         |               (no public IP or DNS hostname)
                         v
                    SNIF Relay                     IoT Device
                +----------------+     +--------------------------------+
                |                |     | Private Key +                  |
                |                |     | X.509 cert for host1.snif.xyz  |
                |                |     |   v v v v v                    |
                | snifd relay:   |     | snifd connector or app:        |
                |                |     |                                |
                |                <-----< open ctl connection            |
                | TLS SNI=       |     |                                |
                | host1.snif.xyz >-----> receive ctl notification       |
        +-------> ============== <-----< launch Server Process          |
        |       | e2e TLS tunnel |     |                                |
        |       |                |     |                                |
        |       +----------------+     +--------------------------------+
        |
+-------^------------------+
| https://host1.snif.xyz   |
| (TLS SNI=host1.snif.xyz) |
|                          |
| A web browser, or        |
| any TLS enabled client,  |
| anywhere on the Internet |
+--------------------------+
```


# EXAMPLE SETUP:
```
# SNIF Relay Server:
#
# Run an http/https server (apache / nginx / ...)
# Serve "https://snif.example.com:4443", respond with a randomly generated
# unique hostname. The DNS record for the hostname must point to the relay
# server.
# Serve HTTP PUT "http://{hostname}/snif-cert/{hostname}.csr" to store a valid
# CSR for a previously generated {hostname}.
# Serve HTTP GET "http://{hostname}/snif-cert/{hostname}.crt" to return a
# certificate generated by snif-certd. If a requested certificate doesn't
# exist and the matching CSR has been uploaded - notify snif-certd and return
# a temporary error 503.
# Preferrably, add an authorization mechanism to throttle certificate issuance
# and mitigate potential DoS attacks. Return 401 in response to a certificate
# http request until the device user performs a specific action to authorize
# the allocated hostname. VES account authorization is included by default.
#
# Run snif-certd daemon
snif-certd
#
# Run snifd daemon in the relay mode:
# Accept control connections from SNIF connectors on the default port 7123
# Listen to incoming TLS connections on TCP 443 and 1443
# Read SNI records of the incoming TLS connections,
# when the SNI hostname matches the certificate CN on one of SNIF control
# connections - send a notification over that control connection and wait
# for a matching incoming data connection to relay to.
snifd 443 1443

# IoT Device:
#
# Run snifd daemon in the connector mode:
# Use the certificate file "snif.crt" and the private key file "snif.key".
# If the private key doesn't exist:
# - generate a new private key and store in "snif.key",
# - allocate a new SNIF hostname using "https://snif.example.com:4443/",
# - generate a provisional self-signed cert and store in "snif.crt",
# - generate a CSR and HTTP PUT it to "http://{hostname}/snif-cert/{hostname}.csr"
# - HTTP GET "http://{hostname}/snif-cert/{hostname}.crt",
# - if a trusted certificate is returned - store it in "snif.crt",
# - otherwise - retry after a delay
# Having the private key and the trusted certificate:
# - establish a SNIF control connection to {hostname} default SNIF port TCP 7123,
# - use the certificate and the private key to initiate TLS over the connection,
# - wait for control messages,
# - when the certificate is about to expire - download a new one from the relay
# When a control message is received notifying of an incoming connection to 443:
# - Connect back to the relay port referenced in the message,
# - pass the connection id referenced in the message,
# - use the certificate and the private key to initiate TLS,
# - relay the decrypted traffic with unsecure local TCP 80
# When a control message is received notifying of an incoming connection to 1443:
# - Connect back to the relay port referenced in the message,
# - pass the connection id referenced in the message,
# - relay the traffic with local TCP 2443, the local app on 2443 is expected to
#   handle TLS using "snif.crt" and "snif.key"
snifd -d -c snif.crt -k snif.key -a https://snif.example.com:4443/ 443:^80 1443:2443
```


# BEWARE OF ROOT CERT EXPIRATION!

DST Root X3 has expired on 09/30/21.
On a Linux/Unix platform - try
```
curl https://letsencrypt.org
```
If getting a certificate error - take care of your CA trust root first.



# CONTENTS:
```
lib/        SNIF Connector libraries source code
snifd/      SNIF Daemon source code, Relay and Connector
ca-proxy/   CA Proxy scripts and web API
```

# REQUIREMENTS:

## snifd:
    OpenSSL >= 1.0.1
    cURL
## ca-proxy:
    http + https server + .htaccess
    PHP
    perl + cpan

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


typedef struct snif_host {
    struct snif_sock *clients;
    struct snif_sock *ctls;
    char hostname[1];
} snif_host;

struct snif_host *snif_host_get(const char *hostname, int len);
int snif_host_notifyl(struct snif_host *host, const char *ntfy, int l);
#define	snif_host_notify(host, ntfy)	snif_host_notifyl(host, ntfy, strlen(ntfy))
void snif_host_chkalive(snif_host *host);

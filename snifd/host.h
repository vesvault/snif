/**************************************************************************
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021-2026 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 **************************************************************************/


/* Max CONNECT lines held from input FIFOs for hosts with no control connection here */
#ifndef SNIF_HOST_MAXHELD
#define	SNIF_HOST_MAXHELD	4096
#endif

typedef struct snif_host {
    struct snif_sock *clients;
    struct snif_sock *ctls;
    char hostname[1];
} snif_host;

struct snif_host *snif_host_get(const char *hostname, int len);
int snif_host_notifyx(struct snif_host *host, const char *ntfy, int l, struct snif_sock *except);
#define	snif_host_notifyl(host, ntfy, l)	snif_host_notifyx(host, ntfy, l, NULL)
#define	snif_host_notify(host, ntfy)	snif_host_notifyl(host, ntfy, strlen(ntfy))
void snif_host_chkalive(snif_host *host);
void snif_host_hold(struct snif_host *host, const char *connid, const char *ntfy, int l, int tmout);
void snif_host_unhold(const char *connid);
void snif_host_sendheld(struct snif_host *host, struct snif_sock *ctl);

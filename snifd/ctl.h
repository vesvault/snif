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


#define	SNIF_CTL_WBUFSIZE	8192
#define	SNIF_CTL_RBUFSIZE	4096
#define	SNIF_CTL_MAXTIME	0xffffffff
#define	SNIF_CTL_ABUSE		90
#define	SNIF_CTL_PUSHGRACE	20

struct snif_sock *snif_ctl(struct snif_sock *sock);
#define	snif_ctl_alive(sock)	((sock)->ctl.alive)
int snif_ctl_out(struct snif_sock *sock, const char *buf, int len);

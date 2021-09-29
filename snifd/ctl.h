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


#define	SNIF_CTL_WBUFSIZE	8192
#define	SNIF_CTL_RBUFSIZE	4096
#define	SNIF_CTL_MAXTIME	0xffffffff
#define	SNIF_CTL_ABUSE		90
#define	SNIF_CTL_PUSHGRACE	20

struct snif_sock *snif_ctl(struct snif_sock *sock);
#define	snif_ctl_alive(sock)	((sock)->ctl.alive)
int snif_ctl_out(struct snif_sock *sock, const char *buf, int len);

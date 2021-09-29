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


typedef struct snif_buf {
    int max;
    int len;
    int low;
    char buf[0];
} snif_buf;

#define	SNIF_BUF_ERR	-1

struct snif_buf *snif_buf_new(int max);
void snif_buf_shift(struct snif_buf *buf, int l);
int snif_buf_recv(struct snif_buf *buf, int fd);
int snif_buf_send(struct snif_buf *buf, int fd);
int snif_buf_recv_ssl(struct snif_buf *buf, void *ssl);
int snif_buf_send_ssl(struct snif_buf *buf, void *ssl);
int snif_buf_append(struct snif_buf *buf, const char *src, int len);
int snif_buf_scanl(struct snif_buf *buf, int *cmdlen, ...);
#define	snif_buf_readl(buf, ...)	snif_buf_scanl(buf, NULL, __VA_ARGS__)
#define	snif_buf_eof(buf)	(!buf || (!buf->max && !buf->len))
#define	snif_buf_free(buf)	free(buf)

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

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "help.h"


const char *snif_banner =

"    \x1b[1m_________\x1b[0m\n"
"   \x1b[1m/\x1b[0m\x1b[1;30m````````\x1b[0m\x1b[1m_\\\x1b[0m                   \x1b[1;36mS N I F\x1b[0m \x1b[1;31m~\x1b[0m e2e TLS trust for IoT\n"
"  \x1b[1m/\x1b[0m\x1b[2;33m\\     ,\x1b[0m \x1b[1m/\x1b[0m \x1b[1;34mO\x1b[0m\x1b[1;30m\\\x1b[0m      \x1b[1;30m___\x1b[0m         e2e TLS SNI Forwarder\n"
" \x1b[1m|\x1b[0m \x1b[2;33m|     |\x1b[0m \x1b[1m\\__\x1b[0m\x1b[1;30m|\x1b[0m\x1b[1m_____\x1b[0m\x1b[1;30m/  o\\\x1b[0m        e2e TLS CA Proxy\n"
" \x1b[1m|\x1b[0m \x1b[2;33m|     |\x1b[0m  \x1b[1;30m``/`````\\___/\x1b[0m\n"
" \x1b[1m|\x1b[0m \x1b[2;33m|     |\x1b[0m \x1b[1;30m. |\x1b[0m <\x1b[1m\"\"\"\"\"\"\"\x1b[0m\x1b[1;31m~~\x1b[0m        https://snif.host\n"
" \x1b[1m|\x1b[0m  \x1b[2;33m\\___/\x1b[0m \x1b[1;30m``  \\\x1b[0m\x1b[1m________/\x1b[0m         (C) 2021 VESvault Corp\n"
"  \x1b[1m\\\x1b[0m  \x1b[2;33m'''\x1b[0m  \x1b[1;30m```\x1b[0m \x1b[1m/\x1b[0m\x1b[1;30m````````\x1b[0m          \x1b[1msnifd\x1b[0m v." SNIF_VERSION_STR "\n"
"   \x1b[1m\\_________/\x1b[0m\n"
"\n";



const char *snif_help =

"  SNIF Relay Daemon Mode:\n"
"  \x1b[1msnifd\x1b[0m \x1b[2;36m[\x1b[0m-l \x1b[2;36m[\x1b[0mbind:\x1b[2;36m]\x1b[0msnif_port\x1b[2;36m]\x1b[0m"
" \x1b[2;36m[\x1b[0m-s \x1b[2;36m[\x1b[0mbind:\x1b[2;36m]\x1b[0mrelay_port\x1b[2;36m]\x1b[0m"
" \x1b[2;36m[\x1b[0m-p push_fifo\x1b[2;36m]\x1b[0m \x1b[2;36m[\x1b[0m-i in_fifo\x1b[2;36m]\x1b[0m\n"
"\t\x1b[2;36m[\x1b[0m-t abuse_sense\x1b[2;36m]\x1b[0m"
" \x1b[2;36m[\x1b[0mbind:\x1b[2;36m]\x1b[0m\x1b[1mfwd_port\x1b[0m"
" \x1b[2;36m[[\x1b[0mbind:\x1b[2;36m]\x1b[0mfwd_port\x1b[2;36m] ...\x1b[0m\n"
 "\n"
"  SNIF Connector Certificate Initialization:\n"
"  \x1b[1msnifd -c cert_filename -k pkey_filename -a https://snif.snif.xyz:4443/\x1b[0m\n"
 "\n"
"  SNIF Connector Daemon Mode (can be combined with Initialization):\n"
"  \x1b[1msnifd\x1b[0m \x1b[2;36m[\x1b[0m-d\x1b[2;36m]\x1b[0m \x1b[1m-c cert_file -k pkey_file\x1b[0m \x1b[2;36m[\x1b[0m-r snif_host\x1b[2;36m[\x1b[0m:relay_port\x1b[2;36m]]\x1b[0m\n"
"\t\x1b[2;36m[\x1b[0m-p push_fifo\x1b[2;36m]\x1b[0m \x1b[2;36m[\x1b[0m-i in_fifo\x1b[2;36m]\x1b[0m \x1b[2;36m[\x1b[0mfwd_test_port:^\x1b[2;36m]\x1b[0m\n"
"\t\x1b[2;36m[\x1b[0mfwd_port:\x1b[2;36m[\x1b[0mdst_host:\x1b[2;36m]]\x1b[0m\x1b[1mdst_tls_port\x1b[0m"
" \x1b[2;36m| [\x1b[0mfwd_port:\x1b[2;36m[\x1b[0mdst_host:\x1b[2;36m]]\x1b[0m\x1b[1m^dst_plain_port\x1b[0m \x1b[2;36m...\x1b[0m\n"
 "\n"
 ;

void snif_out_ansi(int fdi, const char *str) {
    struct winsize wsize;
    if (ioctl(fdi, TIOCGWINSZ, &wsize) >= 0) {
	write(fdi, str, strlen(str));
	return;
    }
    const char *s = str;
    const char *s0 = s;
    char c;
    char esc = 0;
    do {
	c = *s++;
	if (esc) {
	    if (c == 'm') {
		esc = 0;
		s0 = s;
	    }
	} else {
	    if (c == 0x1b || c == 0) {
		esc = 1;
		int l = s - s0 - 1;
		if (l > 0) write(fdi, s0, l);
	    }
	}
    } while (c);
}

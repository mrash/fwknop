/*
 ******************************************************************************
 *
 * File:    cmd_opts.h
 *
 * Purpose: Header file for fwknop command line options.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 ******************************************************************************
*/
#ifndef CMD_OPTS_H
#define CMD_OPTS_H

/* Long options values (for those without a short option).
*/
enum {
    FKO_DIGEST_NAME     = 0x100,
    ENCRYPTION_MODE,
    NAT_LOCAL,
    NAT_PORT,
    NAT_RAND_PORT,
    TIME_OFFSET_MINUS,
    TIME_OFFSET_PLUS,
    SAVE_RC_STANZA,
    FORCE_SAVE_RC_STANZA,
    STANZA_LIST,
    NO_SAVE_ARGS,
    SHOW_LAST_ARGS,
    RC_FILE_PATH,
    RESOLVE_HTTP_ONLY,
    RESOLVE_URL,
    SERVER_RESOLVE_IPV4,
    USE_HMAC,
    USE_WGET_USER_AGENT,
    SPA_ICMP_TYPE,
    SPA_ICMP_CODE,
    KEY_LEN,
    HMAC_DIGEST_TYPE,
    HMAC_KEY_LEN,
    GET_HMAC_KEY,
    KEY_RIJNDAEL,
    KEY_RIJNDAEL_BASE64,
    KEY_HMAC_BASE64,
    KEY_HMAC,
    FD_SET_STDIN,
    FD_SET_ALT,
    FAULT_INJECTION_TAG,

    /* Put GPG-related items below the following line */
    GPG_ENCRYPTION      = 0x200,
    GPG_RECIP_KEY,
    GPG_SIGNER_KEY,
    GPG_HOME_DIR,
    GPG_EXE_PATH,
    GPG_AGENT,
    GPG_ALLOW_NO_SIGNING_PW,
    NOOP /* Just to be a marker for the end */
};


/* Our getopt_long options string.
*/
#define GETOPTS_OPTION_STRING "a:A:bB:C:D:E:f:gG:hH:kK:lm:M:n:N:p:P:Q:rRsS:Tu:U:vVw:"

/* Our program command-line options...
*/
static struct option cmd_opts[] =
{
    {"allow-ip",            1, NULL, 'a'},
    {"access",              1, NULL, 'A'},
    {"save-packet-append",  0, NULL, 'b'},
    {"save-packet",         1, NULL, 'B'},
    {"save-rc-stanza",      0, NULL, SAVE_RC_STANZA},
    {"force-stanza",        0, NULL, FORCE_SAVE_RC_STANZA},
    {"stanza-list",         0, NULL, STANZA_LIST},
    {"no-save-args",        0, NULL, NO_SAVE_ARGS},
    {"server-cmd",          1, NULL, 'C'},
    {"digest-type",         1, NULL, FKO_DIGEST_NAME},
    {"destination",         1, NULL, 'D'},
    {"save-args-file",      1, NULL, 'E'},
    {"encryption-mode",     1, NULL, ENCRYPTION_MODE},
    {"fd",                  1, NULL, FD_SET_ALT},
    {"fw-timeout",          1, NULL, 'f'},
    {"fault-injection-tag", 1, NULL, FAULT_INJECTION_TAG },
    {"gpg-encryption",      0, NULL, 'g'},
    {"gpg-recipient-key",   1, NULL, GPG_RECIP_KEY },
    {"gpg-signer-key",      1, NULL, GPG_SIGNER_KEY },
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"gpg-exe",             1, NULL, GPG_EXE_PATH },
    {"gpg-agent",           0, NULL, GPG_AGENT },
    {"gpg-no-signing-pw",   0, NULL, GPG_ALLOW_NO_SIGNING_PW },
    {"get-key",             1, NULL, 'G'},
    {"get-hmac-key",        1, NULL, GET_HMAC_KEY },
    {"help",                0, NULL, 'h'},
    {"http-proxy",          1, NULL, 'H'},
    {"key-gen",             0, NULL, 'k'},
    {"key-gen-file",        1, NULL, 'K'},
    {"key-rijndael",        1, NULL, KEY_RIJNDAEL },
    {"key-base64-rijndael", 1, NULL, KEY_RIJNDAEL_BASE64 },
    {"key-base64-hmac",     1, NULL, KEY_HMAC_BASE64 },
    {"key-hmac",            1, NULL, KEY_HMAC },
    {"key-len",             1, NULL, KEY_LEN},
    {"hmac-key-len",        1, NULL, HMAC_KEY_LEN},
    {"hmac-digest-type",    1, NULL, HMAC_DIGEST_TYPE},
    {"icmp-type",           1, NULL, SPA_ICMP_TYPE },
    {"icmp-code",           1, NULL, SPA_ICMP_CODE },
    {"last-cmd",            0, NULL, 'l'},
    {"nat-access",          1, NULL, 'N'},
    {"named-config",        1, NULL, 'n'},
    {"nat-local",           0, NULL, NAT_LOCAL},
    {"nat-port",            1, NULL, NAT_PORT},
    {"nat-rand-port",       0, NULL, NAT_RAND_PORT},
    {"server-port",         1, NULL, 'p'},
    {"server-proto",        1, NULL, 'P'},
    {"spoof-source",        1, NULL, 'Q'},
    {"spoof-src",           1, NULL, 'Q'}, /* synonym */
    {"rc-file",             1, NULL, RC_FILE_PATH},
    {"rand-port",           0, NULL, 'r'},
    {"resolve-ip-http",     0, NULL, 'R'},
    {"resolve-ip-https",    0, NULL, 'R'}, /* synonym, default is HTTPS */
    {"resolve-http-only",   0, NULL, RESOLVE_HTTP_ONLY},
    {"resolve-url",         1, NULL, RESOLVE_URL},
    {"server-resolve-ipv4", 0, NULL, SERVER_RESOLVE_IPV4},
    {"show-last",           0, NULL, SHOW_LAST_ARGS},
    {"source-ip",           0, NULL, 's'},
    {"source-port",         1, NULL, 'S'},
    {"stdin",               0, NULL, FD_SET_STDIN},
    {"test",                0, NULL, 'T'},
    {"time-offset-plus",    1, NULL, TIME_OFFSET_PLUS},
    {"time-offset-minus",   1, NULL, TIME_OFFSET_MINUS},
    {"user-agent",          1, NULL, 'u'},
    {"use-hmac",            0, NULL, USE_HMAC},
    {"use-wget-user-agent", 0, NULL, USE_WGET_USER_AGENT},
    {"spoof-user",          1, NULL, 'U'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {"wget-cmd",            1, NULL, 'w'},
    {0, 0, 0, 0}
};

#endif /* CMD_OPTS_H */

/***EOF***/

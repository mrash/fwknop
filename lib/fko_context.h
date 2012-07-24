/*
 *****************************************************************************
 *
 * File:    fko_context.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: fko context definition.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
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
 *****************************************************************************
*/
#ifndef FKO_CONTEXT_H
#define FKO_CONTEXT_H 1

#include "fko_common.h"

#if HAVE_LIBGPGME
/* Stucture to hold a list of the gpg signature information
 * we are interested in.
*/
struct fko_gpg_sig {
    struct fko_gpg_sig *next;
    gpgme_sigsum_t      summary;
    gpgme_error_t       status;
    gpgme_validity_t    validity;
    char               *fpr;
};

typedef struct fko_gpg_sig *fko_gpg_sig_t;
#endif /* HAVE_LIBGPGME */

/* The pieces we need to make an FKO  SPA data packet.
*/
struct fko_context {
    /* FKO SPA user-definable message data */
    char           *rand_val;
    char           *username;
    time_t          timestamp;
    short           message_type;
    char           *message;
    char           *nat_access;
    char           *server_auth;
    unsigned int    client_timeout;

    /* FKO SPA user-settable message encoding types */
    short  digest_type;
    short  encryption_type;
    int    encryption_mode;

    /* Computed or predefined data */
    char           *version;
    char           *digest;

    /* Digest of raw encrypted/base64 data - this is used
     * for replay attack detection
    */
    char           *raw_digest;
    short           raw_digest_type;

    /* Computed processed data (encodings, etc.) */
    char           *encoded_msg;
    char           *encrypted_msg;

    /* State info */
    unsigned short  state;
    unsigned char   initval;

#if HAVE_LIBGPGME
    /* For gpgme support */
    char           *gpg_exe;
    char           *gpg_recipient;
    char           *gpg_signer;
    char           *gpg_home_dir;

    unsigned char   have_gpgme_context;

    gpgme_ctx_t     gpg_ctx;
    gpgme_key_t     recipient_key;
    gpgme_key_t     signer_key;

    unsigned char   verify_gpg_sigs;
    unsigned char   ignore_gpg_sig_error;

    fko_gpg_sig_t   gpg_sigs;

    gpgme_error_t   gpg_err;
#endif /* HAVE_LIBGPGME */
};

#endif /* FKO_CONTEXT_H */

/***EOF***/

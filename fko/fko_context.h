/* $Id$
 *****************************************************************************
 *
 * File:    fko_context.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: fko context definition.
 *
 * Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *     USA
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
    unsigned int    timestamp;
    short           message_type;
    char           *message;
    char           *nat_access;
    char           *server_auth;
    unsigned int    client_timeout;

    /* FKO SPA user-settable message encoding types */
    short  digest_type;
    short  encryption_type;

    /* Computed or predefined data */
    char           *version;
    char           *digest;

    /* Computed processed data (encodings, etc.) */
    char           *encoded_msg;
    char           *encrypted_msg;

    /* State info */
    unsigned short  state;
    unsigned char   initval;

#if HAVE_LIBGPGME
    /* For gpgme support */
    char           *gpg_recipient;
    char           *gpg_signer;
    char           *gpg_home_dir;

    unsigned char   have_gpgme_context;

    gpgme_ctx_t     gpg_ctx;
    gpgme_key_t     recipient_key;
    gpgme_key_t     signer_key;

    unsigned char   verify_gpg_sigs;

    fko_gpg_sig_t   gpg_sigs;

    gpgme_error_t   gpg_err;
#endif /* HAVE_LIBGPGME */
};

#endif /* FKO_CONTEXT_H */

/***EOF***/

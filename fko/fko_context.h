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
#endif /* HAVE_LIBGPGME */
};

#endif /* FKO_CONTEXT_H */

/***EOF***/

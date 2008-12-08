/* $Id$
 *****************************************************************************
 *
 * File:    spa_mesage.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Construct the raw spa message based on the current spa data.
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
#include "fwknop.h"

char* spa_message(spa_message_t *sm)
{
    char    user_b64[1024]  = {0};
    char    msg_text[1024]  = {0};

    b64_encode((uchar*)sm->user, user_b64, strlen(sm->user));

    switch(sm->message_type)
    {
        case SPA_ACCESS_MSG:
            sprintf(msg_text, "%s,%s,%u",
                sm->allow_ip,
                sm->access_str,
                sm->enc_pcap_port
            );
            break;

        case SPA_COMMAND_MSG:
        case SPA_NAT_ACCESS_MSG:
        case SPA_CLIENT_TIMEOUT_ACCESS_MSG:
        case SPA_CLIENT_TIMEOUT_NAT_ACCESS_MSG:
        case SPA_LOCAL_NAT_ACCESS_MSG:
        case SPA_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG:
        default:
            sprintf(msg_text, "## Mode %u not supported ##", sm->message_type);

    }

    sprintf(sm->message, "%s:%s:%u:%s:%u:%s",
        sm->rand_val,
        user_b64,
        sm->timestamp,
        sm->version,
        sm->message_type,
        msg_text
    );

    // NOT DONE YET

    return(sm->message);
} 

/***EOF***/

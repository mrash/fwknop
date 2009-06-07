/* $Id$
 *****************************************************************************
 *
 * File:    fko_limits.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: libfko header that defines non-public parameter/limits, etc..
 *
 * Copyright (C) 2009 Damien Stuart (dstuart@dstuart.org)
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
#ifndef FKO_LIMITS_H
#define FKO_LIMITS_H 1

/* How much space we allow for the fko context error message buffer.
*/
#define MAX_FKO_ERR_MSG_SIZE        128

/* Define some limits (--DSS XXX: These sizes need to be reviewed)
*/
#define MAX_SPA_USERNAME_SIZE        64
#define MAX_SPA_MESSAGE_SIZE        256
#define MAX_SPA_NAT_ACCESS_SIZE     128
#define MAX_SPA_SERVER_AUTH_SIZE     64

#define MIN_SPA_ENCODED_MSG_SIZE     36 /* Somewhat arbitrary */
#define MIN_GNUPG_MSG_SIZE          400

/* Misc.
*/
#define FKO_ENCODE_TMP_BUF_SIZE    1024
#define FKO_RAND_VAL_SIZE            16

#endif /* FKO_LIMITS_H */

/***EOF***/

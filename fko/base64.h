/* $Id$
 *****************************************************************************
 *
 * File:    base64.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop base64.c
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
#ifndef BASE64_H
#define BASE64_H 1

#include "fko_common.h"

/* Prototypes
*/
int b64_encode(uchar *in, char *out, int in_len);
int b64_decode(char *in, uchar *out, int out_len);
void strip_b64_eq(char *data);

#endif /* BASE64_H */

/***EOF***/

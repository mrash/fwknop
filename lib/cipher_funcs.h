/* $Id$
 *****************************************************************************
 *
 * File:    cipher_funcs.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop cipher_funcs.c.
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
#ifndef CIPHER_FUNCS_H
#define CIPHER_FUNCS_H 1

#include "fko_common.h"
#include "rijndael.h"

/* Provide the predicted encrypted data size for given input data based
 * on a 16-byte block size (for Rijndael implementation,this also accounts
 * for the 16-byte salt as well).
*/
#define PREDICT_ENCSIZE(x) (1+(x>>4)+(x&0xf?1:0))<<4

int fko_encrypt(uchar *in, int len, char *key, uchar *out);
int fko_decrypt(uchar *in, int len, char *key, uchar *out);
void hex_dump(uchar *data, int size);

#endif /* CIPHER_FUNCS_H */

/***EOF***/

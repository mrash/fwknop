/* $Id$
 *****************************************************************************
 *
 * File:    digest.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop digest.c.
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
#ifndef _DIGEST_H_
#define _DIGEST_H_

#include <endian.h>
#include "types.h"

/* This should be fine for most linux systems (hopefully).
 * TODO: We should look into the portability of this. --DSS
*/
#define BYTEORDER __BYTE_ORDER


#include "md5.h"
#include "sha.h"

void md5(char* in, char* out, int in_len);
void sha1(char* in, char* out, int in_len);
void sha256(char* in, char* out, int in_len);

#endif /* _DIGEST_H_ */

/***EOF***/

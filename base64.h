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
#ifndef _BASE64_H_
#define _BASE64_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Prototypes
*/
void b64_encode(char *in, char *out, int in_len);
void b64_decode(char *in, char *out, int out_len);

#endif /* _BASE64_H_ */

/***EOF***/

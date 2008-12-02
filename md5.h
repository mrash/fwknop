/* $Id$
 *****************************************************************************
 *
 * File:    md5.h
 *
 * Purpose: Header for the fwknop md5.c.
 *
 * MD5 Message Digest Algorithm (RFC1321).
 *
 * Derived from cryptoapi implementation, originally based on the
 * public domain implementation written by Colin Plumb in 1993.
 *
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
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
#ifndef _MD5_H_
#define _MD5_H_

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define MD5_DIGEST_STR_LENGTH 16

/* The following tests optimise behaviour on little-endian
 * machines, where there is no need to reverse the byte order
 * of 32 bit words in the MD5 computation.  By default,
 * HIGHFIRST is defined, which indicates we're running on a
 * big-endian (most significant byte first) machine, on which
 * the byteReverse function in md5.c must be invoked. However,
 * byteReverse is coded in such a way that it is an identity
 * function when run on a little-endian machine, so calling it
 * on such a platform causes no harm apart from wasting time. 
 * If the platform is known to be little-endian, we speed
 * things up by undefining HIGHFIRST, which defines
 * byteReverse as a null macro.  Doing things in this manner
 * insures we work on new platforms regardless of their byte
 * order.
*/
#define HIGHFIRST

#ifdef __i386__
#undef HIGHFIRST
#endif

/* On machines where "long" is 64 bits, we need to declare
 * uint32 as something guaranteed to be 32 bits.
*/
typedef u_int32_t uint32;

typedef struct _MD5Context {
        uint32 buf[4];
        uint32 bits[2];
        unsigned char in[64];
} MD5Context;

void md5(char* in, char* out, int in_len);
void MD5Init(MD5Context*);
void MD5Update(MD5Context *ctx, unsigned char *buf, unsigned len);
void MD5Final(unsigned char digest[16], MD5Context *ctx);
void MD5Transform(uint32 buf[4], uint32 in[16]);

#endif /* _MD5_H_ */

/***EOF***/

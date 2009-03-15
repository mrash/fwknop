/* $Id$
 *****************************************************************************
 *
 * File:    digest.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Roll-up of teh digests used by fwknop.
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
#include "digest.h"
#include "base64.h"

/* Convert a raw digest into its hex string representation.
*/
void
digest_to_hex(char *out, unsigned char *in, int size)
{
    int i;
    for(i=0; i<size; i++)
    {
        sprintf(out, "%02x", in[i]);
        out += 2;
    }
}

/* Compute MD5 hash on in and store result in out.
*/
void
md5(unsigned char *out, unsigned char *in, int size)
{
    MD5Context ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)in, size);
    MD5Final(out, &ctx);
}

/* Compute MD5 hash on in and store the hex string result in out.
*/
void
md5_hex(char *out, unsigned char *in, int size)
{
    uint8_t      md[MD5_DIGESTSIZE];

    md5(md, in, size);
    digest_to_hex(out, md, MD5_DIGESTSIZE);
}

/* Compute MD5 hash on in and store the base64 string result in out.
*/
void
md5_base64(char *out, unsigned char *in, int size)
{
    uint8_t      md[MD5_DIGESTSIZE];

    md5(md, in, size);
    b64_encode(md, out, MD5_DIGESTSIZE);

    strip_b64_eq(out);
}

/* Compute SHA1 hash on in and store result in out.
*/
void
sha1(unsigned char *out, unsigned char *in, int size)
{
    SHA_INFO    sha_info;

    sha1_init(&sha_info);
    sha1_update(&sha_info, (uint8_t*)in, size);
    sha1_final(out, &sha_info);
}

/* Compute SHA1 hash on in and store the hex string result in out.
*/
void
sha1_hex(char *out, unsigned char *in, int size)
{
    uint8_t       md[SHA1_DIGESTSIZE];

    sha1(md, in, size);
    digest_to_hex(out, md, SHA1_DIGESTSIZE);
}

/* Compute SHA1 hash on in and store the base64 string result in out.
*/
void
sha1_base64(char *out, unsigned char *in, int size)
{
    uint8_t       md[SHA1_DIGESTSIZE];

    sha1(md, in, size);
    b64_encode(md, out, SHA1_DIGESTSIZE);

    strip_b64_eq(out);
}

/* Compute SHA256 hash on in and store the hex string result in out.
*/
void
sha256(unsigned char *out, unsigned char *in, int size)
{
    SHA_INFO    sha_info;

    sha256_init(&sha_info);
    sha256_update(&sha_info, (uint8_t*)in, size);
    sha256_final(&sha_info);
    sha256_unpackdigest(out, &sha_info);
}

/* Compute SHA256 hash on in and store the hex string result in out.
*/
void
sha256_hex(char *out, unsigned char *in, int size)
{
    uint8_t       md[SHA256_DIGESTSIZE];

    sha256(md, in, size);
    digest_to_hex(out, md, SHA256_DIGESTSIZE);
}

/* Compute SHA256 hash on in and store the base64 string result in out.
*/
void
sha256_base64(char *out, unsigned char *in, int size)
{
    uint8_t       md[SHA256_DIGESTSIZE];

    sha256(md, in, size);
    b64_encode(md, out, SHA256_DIGESTSIZE);

    strip_b64_eq(out);
}


/***EOF***/

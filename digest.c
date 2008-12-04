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

/* Convert a raw digest into its hex string representation.
*/
void digest_to_hex(uint8 *in, char *digest, int in_len)
{
    int i;
    for(i=0; i<in_len; i++)
    {
        sprintf(digest, "%02x", in[i]);
        digest += 2;
    }
}

/* Compute MD5 hash on in and store the hex string result in out.
*/
void md5(char *in, char *digest, int in_len)
{
    MD5Context ctx;
    uint8      md[MD5_DIGESTSIZE];


    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)in, in_len);
    MD5Final(md, &ctx);

    digest_to_hex(md, digest, MD5_DIGESTSIZE);
}

/* Compute SHA1 hash on in and store the hex string result in out.
*/
void sha1(char *in, char *digest, int in_len)
{
    SHA_INFO    sha_info;
    uint8       md[SHA1_DIGESTSIZE];

    sha1_init(&sha_info);
    sha1_update(&sha_info, (uint8*)in, in_len);
    sha1_final(md, &sha_info);

    digest_to_hex(md, digest, SHA1_DIGESTSIZE);
}

/* Compute SHA256 hash on in and store the hex string result in out.
*/
void sha256(char *in, char *digest, int in_len)
{
    SHA_INFO    sha_info;
    uint8       md[SHA256_DIGESTSIZE];

    sha256_init(&sha_info);
    sha256_update(&sha_info, (uint8*)in, in_len);
    sha256_final(&sha_info);
    sha256_unpackdigest(md, &sha_info);

    digest_to_hex(md, digest, SHA256_DIGESTSIZE);
}


/***EOF***/

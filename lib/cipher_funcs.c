/* $Id$
 *****************************************************************************
 *
 * File:    cipher_funcs.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Cipher functions used by fwknop
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
#include <stdio.h>
#include <string.h>

#ifdef WIN32
  #include <sys/timeb.h>
  #include <time.h>
  #include <stdlib.h>
#else
  #include <sys/time.h>
#endif

#include "cipher_funcs.h"
#include "digest.h"

#ifndef WIN32
  #ifndef RAND_FILE
    #define RAND_FILE "/dev/urandom"
  #endif
#endif

/* Get random data.
*/
void
get_random_data(unsigned char *data, size_t len)
{
	uint32_t		i;
#ifdef WIN32
	int				rnum;
	struct _timeb	tb;

	_ftime_s(&tb);

	srand((uint32_t)(tb.time*1000)+tb.millitm);

	for(i=0; i<len; i++)
	{
		rnum = rand();
        *(data+i) = rnum % 0xff;
	}
#else
	FILE           *rfd;
    struct timeval  tv;

    /* Attempt to read seed data from /dev/urandom.  If that does not
     * work, then fall back to a time-based method (less secure, but
     * probably more portable).
    */
    if((rfd = fopen(RAND_FILE, "r")) == NULL)
    {
        /* Seed based on time (current usecs).
        */
        gettimeofday(&tv, NULL);
        srand(tv.tv_usec);

        for(i=0; i<len; i++)
            *(data+i) = rand() % 0xff;
    }
    else
    {
        /* Read seed from /dev/urandom
        */
        fread(data, len, 1, rfd);
        fclose(rfd);
    }
#endif

}


/*** These are Rijndael-specific functions ***/

/* Rijndael function to generate initial salt and initialization vector
 * (iv).  This is is done to be compatible with the data produced via
 * the Perl Crypt::CBC module's use of Rijndael.
*/
void
rij_salt_and_iv(RIJNDAEL_context *ctx, char *pass, unsigned char *data)
{
    char            pw_buf[16];
    unsigned char   tmp_buf[64];    /* How big does this need to be? */
    unsigned char   kiv_buf[48];    /* Key and IV buffer */
    unsigned char   md5_buf[16];    /* Buffer for computed md5 hash */

    size_t          kiv_len = 0;
    size_t          plen = strlen(pass);

    /* First make pw 16 bytes (pad with "0" (ascii 0x30)) or truncate.
     * Note: pw_buf was initialized with '0' chars (again, not the value
     *       0, but the digit '0' character).
    */
    if(plen < 16)
    {
        memcpy(pw_buf, pass, plen);
        memset(pw_buf+plen, '0', 16 - plen);
    }
    else
        strncpy(pw_buf, pass, 16);
          
    /* If we are decrypting, data will contain the salt. Otherwise,
     * for encryption, we generate a random salt.
    */
    if(data != NULL)
    {
        /* Pull the salt from the data
        */
        memcpy(ctx->salt, (data+8), 8);
    }
    else
    {
        /* Generate a random 8-byte salt.
        */
        get_random_data(ctx->salt, 8);
    }

    /* Now generate the key and initialization vector.
     * (again it is the perl Crypt::CBC way, with a touch of
     * fwknop).
    */ 
    memcpy(tmp_buf+16, pw_buf, 16);
    memcpy(tmp_buf+32, ctx->salt, 8);

    while(kiv_len < sizeof(kiv_buf))
    {
        if(kiv_len == 0)
            md5(md5_buf, tmp_buf+16, 24);
        else
            md5(md5_buf, tmp_buf, 40);

        memcpy(tmp_buf, md5_buf, 16);

        memcpy(kiv_buf + kiv_len, md5_buf, 16);

        kiv_len += 16;
    }

    memcpy(ctx->key, kiv_buf,    32);
    memcpy(ctx->iv,  kiv_buf+32, 16);
}

/* Initialization entry point.
*/
void
rijndael_init(RIJNDAEL_context *ctx, char *pass, unsigned char *data)
{

    /* Use ECB mode to be compatible with the Crypt::CBC perl module.
    */
    ctx->mode = MODE_ECB;

    /* Generate the salt and initialization vector.
    */
    rij_salt_and_iv(ctx, pass, data);

    /* Intialize our rinjdael context.
    */
    rijndael_setup(ctx, 32, ctx->key);
}

/* Take a chunk of data, encrypt it in the same way the perl Crypt::CBC
 * module would.
*/
size_t
rij_encrypt(unsigned char *in, size_t in_len, char *pass, unsigned char *out)
{
    RIJNDAEL_context    ctx;
    unsigned char       plaintext[16];
    unsigned char       mixtext[16];
    unsigned char       ciphertext[16];
    int                 i, pad_val;

    unsigned char      *ondx = out;

    rijndael_init(&ctx, pass, NULL);

    /* Prepend the salt...
    */
    memcpy(ondx, "Salted__", 8);
    ondx+=8;
    memcpy(ondx, ctx.salt, 8);
    ondx+=8;

    /* Now iterate of the input data and encrypt in 16-byte chunks.
    */
    while(in_len)
    {
        for(i=0; i<sizeof(plaintext); i++)
        {
            if(in_len < 1)
                break;

            plaintext[i] = *in++;
            in_len--;
        }

        pad_val = sizeof(plaintext) - i;

        for(; i < sizeof(plaintext); i++)
            plaintext[i] = pad_val;

        for(i=0; i< 16; i++)
            mixtext[i] = plaintext[i] ^ ctx.iv[i];

        block_encrypt(&ctx, mixtext, 16, ciphertext, ctx.iv);

        memcpy(ctx.iv, ciphertext, 16);

        for(i=0; i<sizeof(ciphertext); i++)
            *ondx++ = ciphertext[i];
    }

    return(ondx - out);
}

/* Decrypt the given data.
*/
size_t
rij_decrypt(unsigned char *in, size_t in_len, char *pass, unsigned char *out)
{
    RIJNDAEL_context    ctx;
    unsigned char       plaintext[16];
    unsigned char       mixtext[16];
    unsigned char       ciphertext[16];
    int                 i, pad_val, pad_err = 0;
    unsigned char      *pad_s;
    unsigned char      *ondx = out;

    rijndael_init(&ctx, pass, in);

    /* Remove the salt from the input.
    */
    in_len -= 16;
    memmove(in, in+16, in_len);

    while(in_len)
    {
        for(i=0; i<sizeof(ciphertext); i++)
        {
            if(in_len < 1)
                break;

            ciphertext[i] = *in++;
            in_len--;
        }

        block_decrypt(&ctx, ciphertext, 16, mixtext, ctx.iv);

        for(i=0; i<sizeof(ciphertext); i++)
            plaintext[i] = mixtext[i] ^ ctx.iv[i];

        memcpy(ctx.iv, ciphertext, 16);

        for(i=0; i<sizeof(plaintext); i++)
            *ondx++ = plaintext[i];
    }

    /* Find and remove padding.
    */
    pad_val = *(ondx-1);

    if(pad_val >= 0 && pad_val <= 16)
    {
        pad_s = ondx - pad_val;

        for(i=0; i < (ondx-pad_s); i++)
        {
            if(*(pad_s+i) != pad_val)
                pad_err++;
        }
            
        if(pad_err == 0)
            ondx -= pad_val;
    }

    *ondx = '\0';

    return(ondx - out);
}

/***EOF***/

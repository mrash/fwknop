/**
 * @file    digest.c
 *
 * @author  Damien S. Stuart
 *
 * @brief   Roll-up of the digests used by fwknop.
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 */

#include "fko_common.h"
#include "digest.h"
#include "base64.h"


/* Convert a raw digest into its hex string representation.
*/
static void
digest_to_hex(char *out, size_t size_out, const unsigned char *in, const size_t size_in)
{
    size_t i;

    /* Assume the output buffer must be a NULL terminated string */
    memset(out, 0, size_out);
    size_out -= 1;

    /* The hex string representation must be long enough */
    if (size_out >= (size_in * 2))
    {
        /* For each byte... */
        for(i=0; i<size_in; i++)
        {
            /* Append the hex string to the output buffer */
            snprintf(out, 2, "%02x", in[i]);

            /* Moved the pointer on the output buffer to the next place  */
            out += 2;
        }
    }

    /* Not enough space in the output buffer - Should not occur */
    else;
}

/* Compute MD5 hash on in and store result in out.
*/
void
md5(unsigned char *out, unsigned char *in, size_t size)
{
    MD5Context ctx;

    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)in, size);
    MD5Final(out, &ctx);
}

/* Compute MD5 hash on in and store the hex string result in out.
*/
void
md5_hex(char *out, size_t size_out, unsigned char *in, size_t size_in)
{
    uint8_t      md[MD5_DIGEST_LEN];

    md5(md, in, size_in);
    digest_to_hex(out, size_out, md, MD5_DIGEST_LEN);
}

/* Compute MD5 hash on in and store the base64 string result in out.
*/
void
md5_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t      md[MD5_DIGEST_LEN];

    md5(md, in, size);
    b64_encode(md, out, MD5_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA1 hash on in and store result in out.
*/
void
sha1(unsigned char *out, unsigned char *in, size_t size)
{
    SHA1_INFO    sha1_info;

    sha1_init(&sha1_info);
    sha1_update(&sha1_info, (uint8_t*)in, size);
    sha1_final(out, &sha1_info);
}

/* Compute SHA1 hash on in and store the hex string result in out.
*/
void
sha1_hex(char *out, size_t size_out, unsigned char *in, size_t size_in)
{
    uint8_t       md[SHA1_DIGEST_LEN];

    sha1(md, in, size_in);
    digest_to_hex(out, size_out, md, SHA1_DIGEST_LEN);
}

/* Compute SHA1 hash on in and store the base64 string result in out.
*/
void
sha1_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA1_DIGEST_LEN];

    sha1(md, in, size);
    b64_encode(md, out, SHA1_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA256 hash on in and store the hex string result in out.
*/
void
sha256(unsigned char *out, unsigned char *in, size_t size)
{
    SHA256_CTX    sha256_ctx;

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, (const uint8_t*)in, size);
    SHA256_Final(out, &sha256_ctx);
}

/* Compute SHA256 hash on in and store the hex string result in out.
*/
void
sha256_hex(char *out, size_t size_out, unsigned char *in, size_t size_in)
{
    uint8_t       md[SHA256_DIGEST_LEN];

    sha256(md, in, size_in);
    digest_to_hex(out, size_out, md, SHA256_DIGEST_LEN);
}

/* Compute SHA256 hash on in and store the base64 string result in out.
*/
void
sha256_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA256_DIGEST_LEN];

    sha256(md, in, size);
    b64_encode(md, out, SHA256_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA384 hash on in and store the hex string result in out.
*/
void
sha384(unsigned char *out, unsigned char *in, size_t size)
{
    SHA384_CTX    sha384_ctx;

    SHA384_Init(&sha384_ctx);
    SHA384_Update(&sha384_ctx, (const uint8_t*)in, size);
    SHA384_Final(out, &sha384_ctx);
}

/* Compute SHA384 hash on in and store the hex string result in out.
*/
void
sha384_hex(char *out, size_t size_out, unsigned char *in, size_t size_in)
{
    uint8_t       md[SHA384_DIGEST_LEN];

    sha384(md, in, size_in);
    digest_to_hex(out, size_out, md, SHA384_DIGEST_LEN);
}

/* Compute SHA384 hash on in and store the base64 string result in out.
*/
void
sha384_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA384_DIGEST_LEN];

    sha384(md, in, size);
    b64_encode(md, out, SHA384_DIGEST_LEN);

    strip_b64_eq(out);
}

/* Compute SHA512 hash on in and store the hex string result in out.
*/
void
sha512(unsigned char *out, unsigned char *in, size_t size)
{
    SHA512_CTX    sha512_ctx;

    SHA512_Init(&sha512_ctx);
    SHA512_Update(&sha512_ctx, (const uint8_t*)in, size);
    SHA512_Final(out, &sha512_ctx);
}

/* Compute SHA512 hash on in and store the hex string result in out.
*/
void
sha512_hex(char *out, size_t size_out, unsigned char *in, size_t size_in)
{
    uint8_t       md[SHA512_DIGEST_LEN];

    sha512(md, in, size_in);
    digest_to_hex(out, size_out, md, SHA512_DIGEST_LEN);
}

/* Compute SHA512 hash on in and store the base64 string result in out.
*/
void
sha512_base64(char *out, unsigned char *in, size_t size)
{
    uint8_t       md[SHA512_DIGEST_LEN];

    sha512(md, in, size);
    b64_encode(md, out, SHA512_DIGEST_LEN);

    strip_b64_eq(out);
}

/***EOF***/

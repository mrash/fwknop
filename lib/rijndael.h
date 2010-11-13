/* $Id$
 *****************************************************************************
 *
 * File:    rigndael.c
 *
 * Purpose: rijndael - An implementation of the Rijndael cipher.
 *
 * Copyright (C) 2000, 2001 Rafael R. Sevilla <sevillar@team.ph.inter.net>
 *
 * Currently maintained by brian d foy, <bdfoy@cpan.org>
 *
 *  License (GNU Public License):
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
 *
 *****************************************************************************
*/
/*
 * Rijndael is a 128/192/256-bit block cipher that accepts key sizes of
 * 128, 192, or 256 bits, designed by Joan Daemen and Vincent Rijmen.  See
 * http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ for details.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H 1

#include "fko_common.h"

/* Other block sizes and key lengths are possible, but in the context of
 * the ssh protocols, 256 bits is the default. 
 */
#define RIJNDAEL_BLOCKSIZE 16
#define RIJNDAEL_KEYSIZE   32

#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB        3    /*  Are we ciphering in 128-bit CFB mode? */
#define     MODE_PCBC       4    /*  Are we ciphering in PCBC mode? */
#define     MODE_OFB        5    /*  Are we ciphering in 128-bit OFB mode? */
#define     MODE_CTR        6    /*  Are we ciphering in counter mode? */

/* Allow keys of size 128 <= bits <= 256 */

#define RIJNDAEL_MIN_KEYSIZE 16
#define RIJNDAEL_MAX_KEYSIZE 32

typedef struct {
  uint32_t keys[60];		/* maximum size of key schedule */
  uint32_t ikeys[60];		/* inverse key schedule */
  int nrounds;			/* number of rounds to use for our key size */
  int mode;			    /* encryption mode */
  /* Added by DSS */
  uint8_t key[32];
  uint8_t iv[16];
  uint8_t salt[8];
} RIJNDAEL_context;

/* This basically performs Rijndael's key scheduling algorithm, as it's the
 * only initialization required anyhow.   The key size is specified in bytes,
 * but the only valid values are 16 (128 bits), 24 (192 bits), and 32 (256
 * bits).  If a value other than these three is specified, the key will be
 * truncated to the closest value less than the key size specified, e.g.
 * specifying 7 will use only the first 6 bytes of the key given.  DO NOT
 * PASS A VALUE LESS THAN 16 TO KEYSIZE! 
 */
void
rijndael_setup(RIJNDAEL_context *ctx, size_t keysize, const uint8_t *key);

/*
 * rijndael_encrypt()
 *
 * Encrypt 16 bytes of data with the Rijndael algorithm.  Before this
 * function can be used, rijndael_setup must be used in order to initialize
 * Rijndael's key schedule.
 *
 * This function always encrypts 16 bytes of plaintext to 16 bytes of
 * ciphertext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
rijndael_encrypt(RIJNDAEL_context *context,
		 const uint8_t *plaintext,
		 uint8_t *ciphertext);

/*
 * rijndael_decrypt()
 *
 * Decrypt 16 bytes of data with the Rijndael algorithm.
 *
 * Before this function can be used, rijndael_setup() must be used in order
 * to set up the key schedule required for the decryption algorithm.
 * 
 * This function always decrypts 16 bytes of ciphertext to 16 bytes of
 * plaintext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
rijndael_decrypt(RIJNDAEL_context *context,
		 const uint8_t *ciphertext,
		 uint8_t *plaintext);

/* Encrypt a block of plaintext in a mode specified in the context */
void
block_encrypt(RIJNDAEL_context *ctx, uint8_t *input, int inputlen,
	      uint8_t *output, uint8_t *iv);

/* Decrypt a block of plaintext in a mode specified in the context */
void
block_decrypt(RIJNDAEL_context *ctx, uint8_t *input, int inputlen,
	      uint8_t *output, uint8_t *iv);

#endif /* RIJNDAEL_H */

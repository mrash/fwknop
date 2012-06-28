/*
 *****************************************************************************
 *
 * File:    cipher_funcs.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop cipher_funcs.c.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *  This library is free software; you can redistribute it and/or
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
#ifndef CIPHER_FUNCS_H
#define CIPHER_FUNCS_H 1

#include "fko_common.h"
#include "rijndael.h"
#include "gpgme_funcs.h"

/* Define the consistent prefixes or salt on some ecryption schemes.
 * We identify them here so we can remove and reinsert when needed.
*/
#define B64_RIJNDAEL_SALT "U2FsdGVkX1"
#define B64_GPG_PREFIX "hQ"

/* Provide the predicted encrypted data size for given input data based
 * on a 16-byte block size (for Rijndael implementation,this also accounts
 * for the 16-byte salt as well).
*/
#define PREDICT_ENCSIZE(x) (1+(x>>4)+(x&0xf?1:0))<<4

void get_random_data(unsigned char *data, const size_t len);
size_t rij_encrypt(unsigned char *in, size_t len,
    const char *key, unsigned char *out, int encryption_mode);
size_t rij_decrypt(unsigned char *in, size_t len,
    const char *key, unsigned char *out, int encryption_mode);

#endif /* CIPHER_FUNCS_H */

/***EOF***/

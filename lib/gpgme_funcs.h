/*
 *****************************************************************************
 *
 * File:    gpgme_funcs.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop gpgme_funcs.c.
 *
 * Copyright 2009-2010 Damien Stuart (dstuart@dstuart.org)
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
#ifndef GPGME_FUNCS_H
#define GPGME_FUNCS_H 1

#include "fko_common.h"
#include "fko.h"

int gpgme_encrypt(fko_ctx_t ctx, unsigned char *in, size_t len, const char *pw, unsigned char **out, size_t *out_len);
int gpgme_decrypt(fko_ctx_t ctx, unsigned char *in, size_t len, const char *pw, unsigned char **out, size_t *out_len);
#if HAVE_LIBGPGME
  int get_gpg_key(fko_ctx_t fko_ctx, gpgme_key_t *mykey, int signer);
#endif

#endif /* GPGME_FUNCS_H */

/***EOF***/

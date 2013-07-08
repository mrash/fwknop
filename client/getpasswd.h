/*
 *****************************************************************************
 *
 * File:    getpasswd.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for getpasswd.c.
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
 *
 *****************************************************************************
*/
#ifndef GETPASSWD_H
#define GETPASSWD_H

/* Prototypes
*/
char* getpasswd(const char *prompt, int fd);

/* This can be used to acquire an encryption key or HMAC key
*/
int get_key_file(char *key, int *key_len, const char *key_file,
    fko_ctx_t ctx, const fko_cli_options_t *options);

#endif  /* GETPASSWD_H */

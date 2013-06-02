/*
 *****************************************************************************
 *
 * File:    base64.h
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: Header for the fwknop base64.c
 *
 * Copyright 2009-2013 Damien Stuart (dstuart@dstuart.org)
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
#ifndef BASE64_H
#define BASE64_H 1

/* Prototypes
*/
int b64_encode(unsigned char *in, char *out, int in_len);
int b64_decode(const char *in, unsigned char *out);
void strip_b64_eq(char *data);

#endif /* BASE64_H */

/***EOF***/

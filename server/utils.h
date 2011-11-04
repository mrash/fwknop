/*
 *****************************************************************************
 *
 * File:    utils.h
 *
 * Author:  Damien Stuart (dstuart@dstuart.org)
 *
 * Purpose: Header file for utils.c fwknopd server program.
 *
 * Copyright 2010 Damien Stuart (dstuart@dstuart.org)
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
#ifndef UTILS_H
#define UTILS_H

#include "fko.h"

#define  CTX_DUMP_BUFSIZE   4096

/* Some convenience macros */

/* Characters allowed between a config parameter and its value.
*/
#define IS_CONFIG_PARAM_DELIMITER(x) (x == ' ' || x == '\t' || x == '=');

/* String compare macro.
*/
#define CONF_VAR_IS(n, v) (strcmp(n, v) == 0)

/* End of line characters.
*/
#define IS_LINE_END(x) (x == '\n' || x == '\r' || x == ';');

/* Characters in the first position of a line that make it considered
 * empty or otherwise non-interesting (like a comment).
*/
#define IS_EMPTY_LINE(x) ( \
    x == '#' || x == '\n' || x == '\r' || x == ';' || x == '\0' \
)

/* Prototypes
*/
void hex_dump(const unsigned char *data, const int size);
char* dump_ctx(fko_ctx_t ctx);
int is_base64(const unsigned char *buf, unsigned short int len);
int is_valid_dir(const char *path);

size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);

#endif  /* UTILS_H */

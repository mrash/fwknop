/*
 *****************************************************************************
 *
 * File:    fko_util.c
 *
 * Author:  Michael Rash
 *
 * Purpose: Set/Get the current username.
 *
 * Copyright 2012 Michael Rash (mbr@cipherdyne.org)
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
#include "fko_common.h"
#include "fko.h"

/* Validate encoded message length
*/
int
is_valid_encoded_msg_len(const int len)
{
    if(len < MIN_SPA_ENCODED_MSG_SIZE || len >= MAX_SPA_ENCODED_MSG_SIZE)
        return(0);

    return(1);
}

/* Validate plaintext input size
*/
int
is_valid_pt_msg_len(const int len)
{
    if(len < MIN_SPA_PLAINTEXT_MSG_SIZE || len >= MAX_SPA_PLAINTEXT_MSG_SIZE)
        return(0);

    return(1);
}

/* Validate digest length
*/
int
is_valid_digest_len(const int len)
{
    switch(len)
    {
        case MD5_B64_LENGTH:
            break;
        case SHA1_B64_LENGTH:
            break;
        case SHA256_B64_LENGTH:
            break;
        case SHA384_B64_LENGTH:
            break;
        case SHA512_B64_LENGTH:
            break;
        default:
            return(0);
    }

    return(1);
}

/***EOF***/

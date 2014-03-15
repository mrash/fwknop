/*
 *****************************************************************************
 *
 * File:    fko_timestamp.c
 *
 * Purpose: Get the current timestamp with optional offset applied.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
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
#include "fko_common.h"
#include "fko.h"


/* Set the timestamp.
*/
int
fko_set_timestamp(fko_ctx_t ctx, const int offset)
{
    time_t ts;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    ts = time(NULL) + offset;

    if(ts < 0)
        return(FKO_ERROR_INVALID_DATA_TIMESTAMP_VALIDFAIL);

    ctx->timestamp = ts;

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the current timestamp.
*/
int
fko_get_timestamp(fko_ctx_t ctx, time_t *timestamp)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(timestamp == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *timestamp = ctx->timestamp;

    return(FKO_SUCCESS);
}

/***EOF***/

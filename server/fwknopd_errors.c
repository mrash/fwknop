/*
 *****************************************************************************
 *
 * File:    errors.c
 *
 * Purpose: Error message functions for fwknopd
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
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
#include "fwknopd_common.h"
#include "fwknopd_errors.h"

/* Return a string describing the meaning of the given error code.
*/
static const char*
fwknopd_errstr(const int err_code)
{
    switch (err_code)
    {
        case 0:
            return("Success");

        case SPA_MSG_BAD_DATA:
            return("Data is not a valid SPA message format");

        case SPA_MSG_LEN_TOO_SMALL:
            return("Not enough data to be a valid SPA message");

        case SPA_MSG_NOT_SPA_DATA:
            return("Data is not an SPA message");

        case SPA_MSG_HTTP_NOT_ENABLED:
            return("SPA via HTTP request, but ENABLE_SPA_OVER_HTTP is not set");

        case SPA_MSG_FKO_CTX_ERROR:
            return("Error creating FKO context for incoming data.");

        case SPA_MSG_DIGEST_ERROR:
            return("Unable to retrieve digest from the SPA data.");

        case SPA_MSG_DIGEST_CACHE_ERROR:
            return("Error trying to access the digest.cache file");

        case SPA_MSG_REPLAY:
            return("Detected SPA message replay");

        case SPA_MSG_TOO_OLD:
            return("SPA message timestamp is outside the allowable window");

        case SPA_MSG_ACCESS_DENIED:
            return("SPA message did not pass access checks");

        case SPA_MSG_COMMAND_ERROR:
            return("An error occurred while executing an SPA command message");

        case SPA_MSG_NOT_SUPPORTED:
            return("Unsupported SPA message operation");

        case SPA_MSG_ERROR:
            return("General SPA message processing error");

        case FW_RULE_ADD_ERROR:
            return("An error occurred while tring to add a firewall rule");

        case FW_RULE_DELETE_ERROR:
            return("An error occurred while tring to delete a firewall rule");

        case FW_RULE_UNKNOWN_ERROR:
            return("Unknown/unclassified firewall rule processing error");
    }

    return("Undefined/unknown fwknopd Error");
}

/* Attempt to determine the error code type and send the appropriate
 * response. Basically assume it is a libfko error if it is not an fwknopd
 * error code.
*/
const char*
get_errstr(const int err_code)
{
    if(! IS_FWKNOPD_ERROR(err_code))
        return(fko_errstr(err_code));

    return(fwknopd_errstr(err_code));
}

/* print all server errors (from server/fwknopd_errors.c) to stdout
*/
void
dump_server_errors(void)
{
    int i;
    for (i=SPA_MSG_BAD_DATA; i<=SPA_MSG_ERROR; i++)
    {
        fprintf(stdout, "err code: %d, err string: '%s'\n",
                i, fwknopd_errstr(i));
    }
    for (i=FW_RULE_ADD_ERROR; i<=FW_RULE_UNKNOWN_ERROR; i++)
    {
        fprintf(stdout, "err code: %d, err string: '%s'\n",
                i, fwknopd_errstr(i));
    }
    fflush(stdout);
    return;
}

/***EOF***/

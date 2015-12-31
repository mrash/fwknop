/**
 * \file lib/fko_rand_value.c
 *
 * \ Generate a 16-byte random numeric value.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
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
#include "fko_common.h"
#include "fko.h"

#ifdef WIN32
  #include <sys/timeb.h>
  #include <time.h>
#else
  #ifdef HAVE_SYS_TIME_H
    #include <sys/time.h>
    #ifdef TIME_WITH_SYS_TIME
      #include <time.h>
    #endif
  #endif

  #define RAND_FILE "/dev/urandom"
#endif

/* Set/Generate the SPA data random value string.
*/
int
fko_set_rand_value(fko_ctx_t ctx, const char * const new_val)
{
#ifdef WIN32
	struct _timeb	tb;
#else
    FILE           *rfd;
    struct timeval  tv;
    size_t          amt_read;
#endif
    unsigned long   seed;
    char           *tmp_buf;

#if HAVE_LIBFIU
    fiu_return_on("fko_set_rand_value_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* If a valid value was given, use it and return happy.
    */
    if(new_val != NULL)
    {

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_lenval", FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
#endif
        if(strnlen(new_val, FKO_RAND_VAL_SIZE+1) != FKO_RAND_VAL_SIZE)
            return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);

        if(ctx->rand_val != NULL)
            free(ctx->rand_val);

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_strdup", FKO_ERROR_MEMORY_ALLOCATION);
#endif
        ctx->rand_val = strdup(new_val);
        if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        ctx->state |= FKO_DATA_MODIFIED;

        return(FKO_SUCCESS);
    }

#ifdef WIN32
	_ftime_s(&tb);
	seed = ((tb.time * 1000) + tb.millitm) & 0xFFFFFFFF;
#else
    /* Attempt to read seed data from /dev/urandom.  If that does not
     * work, then fall back to a time-based method (less secure, but
     * probably more portable).
    */
    if((rfd = fopen(RAND_FILE, "r")) != NULL)
    {
        /* Read seed from /dev/urandom
        */
        amt_read = fread(&seed, 4, 1, rfd);
        fclose(rfd);

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_read", FKO_ERROR_FILESYSTEM_OPERATION);
#endif
        if (amt_read != 1)
            return(FKO_ERROR_FILESYSTEM_OPERATION);
    }
    else
    {
        /* Seed based on time (current usecs).
        */
        gettimeofday(&tv, NULL);

        seed = tv.tv_usec;
    }
#endif

    srand(seed);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_calloc1", FKO_ERROR_MEMORY_ALLOCATION);
#endif
    ctx->rand_val = calloc(1, FKO_RAND_VAL_SIZE+1);
    if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

#if HAVE_LIBFIU
        fiu_return_on("fko_set_rand_value_calloc2", FKO_ERROR_MEMORY_ALLOCATION);
#endif
    tmp_buf = calloc(1, FKO_RAND_VAL_SIZE+1);
    if(tmp_buf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

    snprintf(ctx->rand_val, FKO_RAND_VAL_SIZE, "%u", rand());

    while(strnlen(ctx->rand_val, FKO_RAND_VAL_SIZE+1) < FKO_RAND_VAL_SIZE)
    {
        snprintf(tmp_buf, FKO_RAND_VAL_SIZE, "%u", rand());
        strlcat(ctx->rand_val, tmp_buf, FKO_RAND_VAL_SIZE+1);
    }

    free(tmp_buf);

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the current rand value.
*/
int
fko_get_rand_value(fko_ctx_t ctx, char **rand_value)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_value == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *rand_value = ctx->rand_val;

    return(FKO_SUCCESS);
}

/***EOF***/

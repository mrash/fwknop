/*
 *****************************************************************************
 *
 * File:    fko_rand_value.c
 *
 * Purpose: Generate a 16-byte random numeric value.
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
#include "base64.h"

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


/* Get random data and place it into a buffer.
*/
void
get_random_data(unsigned char *buf, const size_t len, const int mode)
{
    uint32_t            i;
    int                 rlen = len;

#ifdef WIN32
	int				rnum;
	struct _timeb	tb;

	_ftime_s(&tb);

	srand((uint32_t)(tb.time*1000)+tb.millitm);

	for(i=0; i<rlen; i++)
	{
		rnum = rand();
		*(buf+i) = rnum % 0xff;
	}
#else

    FILE           *rfd;
    struct timeval  tv;
    int             do_time = 0;
    size_t          amt_read;
    char            tmp_buf[FKO_MAX_RAND_SIZE+1] = {0};
    unsigned long   seed;  /* only used in legacy mode since
                              we prioritize on /dev/urandom
                           */

    /* We should never need more the 128 bytes for our purposes
    */
    if(rlen > FKO_MAX_RAND_SIZE)
        rlen = FKO_MAX_RAND_SIZE;

    /* Attempt to read random data from /dev/urandom directly.  If that does
     * not work, then fall back to seeding rand() from /dev/urandom, data
     * and finally fall back to time-based seeding method (less secure, but
     * probably more portable).
    */
    if((rfd = fopen(RAND_FILE, "r")) == NULL)
    {
        do_time = 1;
    }
    else
    {
        /* Read data from /dev/urandom
        */
        if(mode == FKO_RAND_MODE_LEGACY)
            amt_read = fread(&seed, 4, 1, rfd);
        else
            amt_read = fread(buf, rlen, 1, rfd);

        fclose(rfd);

        if (amt_read != 1)
            do_time = 1;
    }

    if (do_time)
    {
        /* Seed based on time (current usecs).
        */
        gettimeofday(&tv, NULL);

        /* Always seed random number generation
        */
        srand(tv.tv_usec);
    }
    else if(mode == FKO_RAND_MODE_LEGACY)
        srand(seed);

    if(mode == FKO_RAND_MODE_LEGACY)
    {
        snprintf((char *)buf, rlen+1, "%u", rand());
        while(strnlen((char *)buf, rlen+1) < rlen)
        {
            snprintf(tmp_buf, rlen+1, "%u", rand());
            strlcat((char *)buf, tmp_buf, FKO_RAND_VAL_SIZE+1);
        }
    }
    else if(do_time)
    {
        for(i=0; i<rlen; i++)
            *(buf+i) = rand() % 0xff;
    }
#endif
}

/* Set the SPA randomization mode (use random length and style)
*/
int
fko_set_rand_mode(fko_ctx_t ctx, const int rand_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_mode < 0 || rand_mode >= FKO_LAST_RAND_MODE)
        return(FKO_ERROR_INVALID_DATA_RAND_MODE_VALIDFAIL);

    ctx->rand_mode = rand_mode;

    ctx->state |= FKO_RAND_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the SPA randomization mode.
*/
int
fko_get_rand_mode(fko_ctx_t ctx, int *rand_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(rand_mode == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *rand_mode = ctx->rand_mode;

    return(FKO_SUCCESS);
}

/* Set/Generate the SPA data random value string.
*/
int
fko_set_rand_value(fko_ctx_t ctx, const char * const new_val)
{
    unsigned char           *tmp_buf;
    int                      b64_len = 0;

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* If a valid value was given, use it and return happy.
    */
    if(new_val != NULL)
    {
        if(ctx->rand_mode == FKO_RAND_MODE_LEGACY)
        {
            if (strnlen(new_val, FKO_RAND_VAL_SIZE+1) != FKO_RAND_VAL_SIZE)
            {
                return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
            }
        }
        else
        {
            /* This looks for a 22-byte string (16 bytes of base64
             * encoded data without the trailing '=' chars)
            */
            if(strnlen(new_val, FKO_RAND_VAL_B64_SIZE+1) != FKO_RAND_VAL_B64_SIZE-3)
                return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
        }

        if(ctx->rand_val != NULL)
            free(ctx->rand_val);

        ctx->rand_val = strdup(new_val);
        if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        ctx->state |= FKO_DATA_MODIFIED;

        return(FKO_SUCCESS);
    }

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    ctx->rand_val = malloc(FKO_RAND_VAL_B64_SIZE+1);
    if(ctx->rand_val == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);
    memset(ctx->rand_val, 0, FKO_RAND_VAL_B64_SIZE+1);

    tmp_buf = malloc(FKO_RAND_VAL_SIZE+1);
    if(tmp_buf == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    memset(tmp_buf, 0, FKO_RAND_VAL_SIZE+1);

    get_random_data(tmp_buf, FKO_RAND_VAL_SIZE, ctx->rand_mode);

    if(ctx->rand_mode == FKO_RAND_MODE_LEGACY)
    {
        strlcpy(ctx->rand_val, (char *)tmp_buf, FKO_RAND_VAL_SIZE);
    }
    else
    {
        b64_len = b64_encode(tmp_buf, ctx->rand_val, FKO_RAND_VAL_SIZE);

        if(b64_len < FKO_RAND_VAL_SIZE)
        {
            free(tmp_buf);
            return(FKO_ERROR_INVALID_DATA_RAND_LEN_VALIDFAIL);
        }

        strip_b64_eq(ctx->rand_val);
    }

    free(tmp_buf);

    ctx->state |= FKO_DATA_MODIFIED;

    return(FKO_SUCCESS);
}

/* Wrapper for get_random_data(). This does not modify or require an FKO
 * context - it merely provides a consistent interface for getting random
 * data from the OS (used in port randomization for example by the fwknop
 * client).
*/
int
fko_rand_data(unsigned char *buf, const size_t len, const int mode)
{
    get_random_data(buf, len, mode);
    return FKO_SUCCESS;
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
